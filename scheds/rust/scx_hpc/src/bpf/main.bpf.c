/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_hpc - HPC-dedicated scheduler for MPI/OpenMP scientific computing.
 *
 * Two-class CPU partitioning:
 *   - Compute cores: HPC tasks run with SCX_SLICE_INF, zero preemption
 *   - Service core(s): OS housekeeping, daemons, non-HPC tasks with fair scheduling
 *
 * HPC task detection: by tgid (process group) or comm prefix.
 * NUMA-aware placement: keep thread groups on same NUMA node.
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

extern unsigned CONFIG_HZ __kconfig;

/*
 * Volatile configuration set from userspace rodata.
 */
const volatile u32 nr_cpu_ids;
const volatile u32 nr_numa_nodes;
const volatile bool smt_enabled;
const volatile u64 service_slice_ns;
const volatile u64 tick_freq;
const volatile bool detect_by_comm;
const volatile u32 nr_comm_prefixes;

/*
 * Scheduling statistics.
 */
volatile u64 nr_hpc_dispatches;
volatile u64 nr_service_dispatches;
volatile u64 nr_hpc_preemptions;
volatile u64 nr_service_preemptions;
volatile u64 nr_migrations_to_service;
volatile u64 nr_ticks;
volatile u64 nr_numa_local;
volatile u64 nr_numa_remote;

/*
 * CPU masks for compute and service partitions.
 */
private(HPC_A) struct bpf_cpumask __kptr *compute_cpumask;
private(HPC_B) struct bpf_cpumask __kptr *service_cpumask;

/*
 * Per-NUMA node compute CPU masks for NUMA-local placement.
 */
private(HPC_N0) struct bpf_cpumask __kptr *numa_cpumask_0;
private(HPC_N1) struct bpf_cpumask __kptr *numa_cpumask_1;
private(HPC_N2) struct bpf_cpumask __kptr *numa_cpumask_2;
private(HPC_N3) struct bpf_cpumask __kptr *numa_cpumask_3;

/*
 * Hash map of tgids classified as HPC workloads.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_HPC_TGIDS);
} hpc_tgids SEC(".maps");

/*
 * Array of comm name prefixes for HPC task detection.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, char[COMM_PREFIX_LEN]);
	__uint(max_entries, MAX_COMM_PREFIXES);
} comm_prefixes SEC(".maps");

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	struct bpf_timer timer;
	bool is_compute;
	s32 numa_node;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, MAX_CPUS);
} cpu_ctx_stor SEC(".maps");

/*
 * Per-task context.
 */
struct task_ctx {
	enum task_class class;
	u32 tgid;
	s32 preferred_numa;
	u64 last_run_at;
	u64 exec_runtime;
	u64 deadline;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Global vruntime for SERVICE task fairness.
 */
static u64 vtime_now;

static struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	return bpf_map_lookup_elem(&cpu_ctx_stor, &cpu);
}

static struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
				    (struct task_struct *)p, 0, 0);
}

/*
 * Check if a CPU is a compute core (fast path, uses cached value).
 */
static bool is_compute_cpu(s32 cpu)
{
	struct cpu_ctx *cctx = try_lookup_cpu_ctx(cpu);

	return cctx ? cctx->is_compute : false;
}

/*
 * Get the per-NUMA compute cpumask. We support up to 4 NUMA nodes
 * with separate private() storage to satisfy the BPF verifier.
 */
static struct bpf_cpumask **get_numa_cpumask_ptr(s32 node)
{
	switch (node) {
	case 0: return &numa_cpumask_0;
	case 1: return &numa_cpumask_1;
	case 2: return &numa_cpumask_2;
	case 3: return &numa_cpumask_3;
	default: return NULL;
	}
}

/*
 * Check if a tgid is registered as an HPC workload.
 */
static bool is_hpc_tgid(u32 tgid)
{
	return bpf_map_lookup_elem(&hpc_tgids, &tgid) != NULL;
}

/*
 * Check if task comm matches any registered HPC prefix.
 * Only called during init_task (cold path).
 */
static bool matches_hpc_comm(const struct task_struct *p)
{
	char task_comm[COMM_PREFIX_LEN] = {};
	u32 i, j;

	if (!detect_by_comm || !nr_comm_prefixes)
		return false;

	bpf_probe_read_kernel_str(task_comm, sizeof(task_comm), p->comm);

	bpf_for(i, 0, MAX_COMM_PREFIXES) {
		char *prefix;
		bool match = true;

		if (i >= nr_comm_prefixes)
			break;

		prefix = bpf_map_lookup_elem(&comm_prefixes, &i);
		if (!prefix)
			continue;

		bpf_for(j, 0, COMM_PREFIX_LEN) {
			if (prefix[j] == 0)
				break;
			if (task_comm[j] != prefix[j]) {
				match = false;
				break;
			}
		}
		if (match)
			return true;
	}
	return false;
}

/*
 * Classify a task as HPC or SERVICE.
 *
 * Priority:
 *   1. Kernel threads (PF_KTHREAD) -> always SERVICE
 *   2. tgid in hpc_tgids map -> HPC
 *   3. comm prefix match -> HPC
 *   4. Default -> SERVICE
 */
static enum task_class classify_task(const struct task_struct *p)
{
	if (p->flags & PF_KTHREAD)
		return TASK_CLASS_SERVICE;

	if (is_hpc_tgid((u32)p->tgid))
		return TASK_CLASS_HPC;

	if (matches_hpc_comm(p))
		return TASK_CLASS_HPC;

	return TASK_CLASS_SERVICE;
}

/*
 * Compute vruntime-based deadline for SERVICE tasks.
 */
static u64 task_deadline(const struct task_struct *p, struct task_ctx *tctx)
{
	u64 vtime_min;

	vtime_min = vtime_now - service_slice_ns;
	if (time_before(tctx->deadline, vtime_min))
		tctx->deadline = vtime_min;

	return tctx->deadline + scale_by_task_weight_inverse(p, tctx->exec_runtime);
}

/*
 * Return the tick interval in nanoseconds.
 */
static inline u64 tick_interval_ns(void)
{
	u64 freq = tick_freq ? : CONFIG_HZ;

	return NSEC_PER_SEC / freq;
}

/*
 * select_cpu: CPU selection on wakeup.
 *
 * HPC tasks: prefer prev_cpu if compute, then NUMA-local idle compute core,
 *            then any idle compute core.
 * SERVICE tasks: route to service cores.
 */
s32 BPF_STRUCT_OPS(hpc_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	struct task_ctx *tctx;
	const struct cpumask *mask;
	s32 cpu;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return prev_cpu;

	if (tctx->class == TASK_CLASS_HPC) {
		/*
		 * HPC: prefer prev_cpu for cache locality.
		 */
		if (is_compute_cpu(prev_cpu)) {
			scx_bpf_test_and_clear_cpu_idle(prev_cpu);
			return prev_cpu;
		}

		/*
		 * Try NUMA-local idle compute core (prefer full idle core).
		 */
		if (tctx->preferred_numa >= 0 &&
		    tctx->preferred_numa < MAX_NUMA_NODES) {
			struct bpf_cpumask **ptr;

			ptr = get_numa_cpumask_ptr(tctx->preferred_numa);
			if (ptr) {
				bpf_rcu_read_lock();
				mask = cast_mask(*ptr);
				if (mask) {
					cpu = scx_bpf_pick_idle_cpu(mask,
						SCX_PICK_IDLE_CORE);
					if (cpu >= 0) {
						bpf_rcu_read_unlock();
						__sync_fetch_and_add(&nr_numa_local, 1);
						return cpu;
					}
					cpu = scx_bpf_pick_idle_cpu(mask, 0);
					if (cpu >= 0) {
						bpf_rcu_read_unlock();
						__sync_fetch_and_add(&nr_numa_local, 1);
						return cpu;
					}
				}
				bpf_rcu_read_unlock();
			}
		}

		/*
		 * Fallback: any idle compute core globally.
		 */
		bpf_rcu_read_lock();
		mask = cast_mask(compute_cpumask);
		if (mask) {
			cpu = scx_bpf_pick_idle_cpu(mask, SCX_PICK_IDLE_CORE);
			if (cpu >= 0) {
				bpf_rcu_read_unlock();
				__sync_fetch_and_add(&nr_numa_remote, 1);
				return cpu;
			}
			cpu = scx_bpf_pick_idle_cpu(mask, 0);
			if (cpu >= 0) {
				bpf_rcu_read_unlock();
				__sync_fetch_and_add(&nr_numa_remote, 1);
				return cpu;
			}
		}
		bpf_rcu_read_unlock();

		return prev_cpu;
	}

	/*
	 * SERVICE task: route to a service core.
	 */
	bpf_rcu_read_lock();
	mask = cast_mask(service_cpumask);
	if (mask) {
		cpu = scx_bpf_pick_idle_cpu(mask, 0);
		if (cpu >= 0) {
			bpf_rcu_read_unlock();
			return cpu;
		}
		cpu = bpf_cpumask_any_distribute(mask);
		bpf_rcu_read_unlock();
		if (cpu < nr_cpu_ids) {
			scx_bpf_test_and_clear_cpu_idle(cpu);
			return cpu;
		}
	} else {
		bpf_rcu_read_unlock();
	}

	return prev_cpu;
}

/*
 * enqueue: task enqueue.
 *
 * HPC tasks: direct local dispatch with infinite slice.
 * SERVICE tasks: vruntime-based fair scheduling on SERVICE_DSQ.
 *
 * Special case: migration-disabled SERVICE tasks (e.g., per-CPU kworkers)
 * pinned to a compute core are dispatched locally so they don't starve
 * in SERVICE_DSQ which compute cores never consume.
 */
void BPF_STRUCT_OPS(hpc_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	if (tctx->class == TASK_CLASS_HPC) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_INF,
				    enq_flags);
		__sync_fetch_and_add(&nr_hpc_dispatches, 1);
		return;
	}

	/*
	 * SERVICE task pinned to a compute core (migration disabled):
	 * dispatch locally with a bounded slice so it can run on that
	 * compute CPU without starving in SERVICE_DSQ.
	 */
	if ((enq_flags & SCX_ENQ_MIGRATION_DISABLED) &&
	    is_compute_cpu(scx_bpf_task_cpu(p))) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, service_slice_ns,
				    enq_flags);
		__sync_fetch_and_add(&nr_service_dispatches, 1);
		return;
	}

	/*
	 * SERVICE task: fair scheduling with vruntime deadline.
	 */
	scx_bpf_dsq_insert_vtime(p, SERVICE_DSQ, service_slice_ns,
				  task_deadline(p, tctx), enq_flags);
	__sync_fetch_and_add(&nr_service_dispatches, 1);
}

/*
 * dispatch: CPU dispatch.
 *
 * Compute cores: never consume SERVICE_DSQ. Keep HPC task running.
 * Service cores: consume from SERVICE_DSQ.
 */
void BPF_STRUCT_OPS(hpc_dispatch, s32 cpu, struct task_struct *prev)
{
	struct cpu_ctx *cctx;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	if (cctx->is_compute) {
		/*
		 * Compute core: if prev is HPC and still runnable,
		 * keep running it with infinite slice.
		 */
		if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
			struct task_ctx *tctx = try_lookup_task_ctx(prev);

			if (tctx && tctx->class == TASK_CLASS_HPC) {
				prev->scx.slice = SCX_SLICE_INF;
				return;
			}
		}
		/*
		 * Compute core idle or prev is not HPC.
		 * Do NOT consume from SERVICE_DSQ - let it stay idle.
		 */
		return;
	}

	/*
	 * Service core: consume from SERVICE_DSQ.
	 */
	if (scx_bpf_dsq_move_to_local(SERVICE_DSQ))
		return;

	/*
	 * Nothing in SERVICE_DSQ. Keep prev running if still runnable.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		prev->scx.slice = service_slice_ns;
}

/*
 * runnable: task becomes ready to run.
 */
void BPF_STRUCT_OPS(hpc_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->exec_runtime = 0;
}

/*
 * running: task starts executing on a CPU.
 */
void BPF_STRUCT_OPS(hpc_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->last_run_at = scx_bpf_now();

	if (tctx->class == TASK_CLASS_SERVICE) {
		if (time_before(vtime_now, tctx->deadline))
			vtime_now = tctx->deadline;
	}

	/*
	 * Request maximum CPU frequency for HPC tasks.
	 */
	if (tctx->class == TASK_CLASS_HPC)
		scx_bpf_cpuperf_set(bpf_get_smp_processor_id(),
				     SCX_CPUPERF_ONE);
}

/*
 * stopping: task is about to release the CPU.
 */
void BPF_STRUCT_OPS(hpc_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 slice;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	slice = scx_bpf_now() - tctx->last_run_at;

	if (tctx->class == TASK_CLASS_SERVICE) {
		if (tctx->exec_runtime < NSEC_PER_SEC)
			tctx->exec_runtime += slice;
		tctx->deadline += scale_by_task_weight_inverse(p, slice);
	}
}

/*
 * tick: periodic tick on a CPU.
 */
void BPF_STRUCT_OPS(hpc_tick, struct task_struct *p)
{
	__sync_fetch_and_add(&nr_ticks, 1);
}

/*
 * enable: task enters the BPF scheduler.
 */
void BPF_STRUCT_OPS(hpc_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->deadline = vtime_now;
}

/*
 * init_task: task is created or enters sched_ext.
 */
s32 BPF_STRUCT_OPS(hpc_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	tctx->class = classify_task(p);
	tctx->tgid = (u32)p->tgid;
	tctx->preferred_numa = __COMPAT_scx_bpf_cpu_node(scx_bpf_task_cpu(p));
	tctx->exec_runtime = 0;
	tctx->deadline = vtime_now;

	return 0;
}

/*
 * BPF timer callback for service core preemption checking.
 * Only checks service cores - never touches compute cores.
 */
static int sched_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	s32 cpu;

	bpf_rcu_read_lock();
	bpf_for(cpu, 0, nr_cpu_ids) {
		struct cpu_ctx *cctx;
		struct task_struct *p;

		if (cpu >= MAX_CPUS)
			break;

		cctx = try_lookup_cpu_ctx(cpu);
		if (!cctx || cctx->is_compute)
			continue;

		p = __COMPAT_scx_bpf_cpu_curr(cpu);
		if (!p || p->flags & PF_IDLE)
			continue;

		if (!scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) &&
		    !scx_bpf_dsq_nr_queued(SERVICE_DSQ))
			continue;

		if (p->scx.slice == SCX_SLICE_INF) {
			p->scx.slice = service_slice_ns;
			__sync_fetch_and_add(&nr_service_preemptions, 1);
		}
	}
	bpf_rcu_read_unlock();

	bpf_timer_start(timer, tick_interval_ns(), 0);

	return 0;
}

/*
 * Start the BPF timer on a service CPU.
 */
static void init_timer(s32 cpu)
{
	struct cpu_ctx *cctx;
	int ret;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	bpf_timer_init(&cctx->timer, &cpu_ctx_stor, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&cctx->timer, sched_timerfn);

	ret = bpf_timer_start(&cctx->timer, tick_interval_ns(), 0);
	if (ret)
		scx_bpf_error("failed to start timer on cpu%d: %d", cpu, ret);
}

/*
 * Allocate/re-allocate a cpumask.
 */
static int calloc_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	return 0;
}

/*
 * Initialize a cpumask if not already initialized.
 */
static int init_cpumask(struct bpf_cpumask **cpumask)
{
	struct bpf_cpumask *mask;
	int err = 0;

	mask = *cpumask;
	if (mask)
		return 0;

	err = calloc_cpumask(cpumask);
	if (!err)
		mask = *cpumask;
	if (!mask)
		err = -ENOMEM;

	return err;
}

/*
 * Syscall: configure a CPU as compute or clear the compute mask.
 * cpu_id < 0 clears the mask.
 */
SEC("syscall")
int enable_compute_cpu(struct cpu_arg *input)
{
	struct bpf_cpumask *mask;
	struct cpu_ctx *cctx;
	s32 cpu = input->cpu_id;
	int ret;

	ret = init_cpumask(&compute_cpumask);
	if (ret)
		return ret;

	bpf_rcu_read_lock();
	mask = compute_cpumask;
	if (mask) {
		if (cpu < 0) {
			bpf_cpumask_clear(mask);
		} else {
			bpf_cpumask_set_cpu(cpu, mask);
			cctx = try_lookup_cpu_ctx(cpu);
			if (cctx) {
				cctx->is_compute = true;
				cctx->numa_node = __COMPAT_scx_bpf_cpu_node(cpu);
			}
		}
	}
	bpf_rcu_read_unlock();

	return 0;
}

/*
 * Syscall: configure a CPU as service or clear the service mask.
 * cpu_id < 0 clears the mask.
 */
SEC("syscall")
int enable_service_cpu(struct cpu_arg *input)
{
	struct bpf_cpumask *mask;
	struct cpu_ctx *cctx;
	s32 cpu = input->cpu_id;
	int ret;

	ret = init_cpumask(&service_cpumask);
	if (ret)
		return ret;

	bpf_rcu_read_lock();
	mask = service_cpumask;
	if (mask) {
		if (cpu < 0) {
			bpf_cpumask_clear(mask);
		} else {
			bpf_cpumask_set_cpu(cpu, mask);
			cctx = try_lookup_cpu_ctx(cpu);
			if (cctx) {
				cctx->is_compute = false;
				cctx->numa_node = __COMPAT_scx_bpf_cpu_node(cpu);
			}
		}
	}
	bpf_rcu_read_unlock();

	return 0;
}

/*
 * Syscall: set a CPU in a per-NUMA compute cpumask.
 * Encodes NUMA node in upper 16 bits, CPU in lower 16 bits.
 * cpu_id < 0 means initialize/clear the mask for node (-cpu_id - 1).
 */
SEC("syscall")
int set_numa_compute_cpu(struct cpu_arg *input)
{
	struct bpf_cpumask **ptr;
	struct bpf_cpumask *mask;
	s32 val = input->cpu_id;
	s32 node, cpu;
	int ret;

	if (val < 0) {
		/* Clear mode: node = (-val - 1) */
		node = -val - 1;
		ptr = get_numa_cpumask_ptr(node);
		if (!ptr)
			return -EINVAL;
		ret = init_cpumask(ptr);
		if (ret)
			return ret;
		bpf_rcu_read_lock();
		mask = *ptr;
		if (mask)
			bpf_cpumask_clear(mask);
		bpf_rcu_read_unlock();
		return 0;
	}

	/* Set mode: node in upper 16 bits, cpu in lower 16 bits */
	node = (val >> 16) & 0xffff;
	cpu = val & 0xffff;

	ptr = get_numa_cpumask_ptr(node);
	if (!ptr)
		return -EINVAL;

	ret = init_cpumask(ptr);
	if (ret)
		return ret;

	bpf_rcu_read_lock();
	mask = *ptr;
	if (mask)
		bpf_cpumask_set_cpu(cpu, mask);
	bpf_rcu_read_unlock();

	return 0;
}

/*
 * Syscall: register a tgid as HPC workload.
 */
SEC("syscall")
int register_hpc_tgid(struct tgid_arg *input)
{
	u32 tgid = (u32)input->tgid;
	u8 val = 1;

	return bpf_map_update_elem(&hpc_tgids, &tgid, &val, BPF_ANY);
}

/*
 * Syscall: unregister a tgid from HPC set.
 */
SEC("syscall")
int unregister_hpc_tgid(struct tgid_arg *input)
{
	u32 tgid = (u32)input->tgid;

	return bpf_map_delete_elem(&hpc_tgids, &tgid);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(hpc_init)
{
	int ret;

	ret = scx_bpf_create_dsq(SERVICE_DSQ, -1);
	if (ret < 0)
		return ret;

	init_timer(bpf_get_smp_processor_id());

	return 0;
}

void BPF_STRUCT_OPS(hpc_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(hpc_ops,
	       .select_cpu		= (void *)hpc_select_cpu,
	       .enqueue			= (void *)hpc_enqueue,
	       .dispatch		= (void *)hpc_dispatch,
	       .runnable		= (void *)hpc_runnable,
	       .running			= (void *)hpc_running,
	       .stopping		= (void *)hpc_stopping,
	       .tick			= (void *)hpc_tick,
	       .enable			= (void *)hpc_enable,
	       .init_task		= (void *)hpc_init_task,
	       .init			= (void *)hpc_init,
	       .exit			= (void *)hpc_exit,
	       .timeout_ms		= 10000,
	       .name			= "hpc");
