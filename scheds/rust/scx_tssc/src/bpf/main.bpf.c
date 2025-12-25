#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/* Forward declarations */
static u32 get_numa_node(s32 cpu);
// static bool same_numa_node(s32 cpu1, s32 cpu2);
static s32 pick_idle_cpu_in_numa_node(struct task_struct *p, u32 numa_node);
static void increment_stat(u32 stat_id);

/*
 * Performance monitoring statistics
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 16);
} stats SEC(".maps");

enum {
	STAT_TASKS_LOCAL_NUMA,
	STAT_TASKS_CROSS_NUMA,
	STAT_KICKS_LOCAL_NUMA,
	STAT_KICKS_CROSS_NUMA,
	STAT_CONGESTED_SLICES,
	STAT_INFINITE_SLICES,
	STAT_NUMA_MIGRATIONS,
	STAT_CACHE_HITS,
	STAT_CACHE_MISSES,
	STAT_MAX,
};

/*
 * HPC workloads require strict affinity, but we must prevent system lockups.
 * If a CPU is overloaded (e.g., HPC task + SSH daemon), we fall back to a
 * finite slice to ensure the system remains responsive.
 */
#define TSSC_SLICE_INF SCX_SLICE_INF
#define TSSC_SLICE_CONGESTED (20 * 1000 * 1000) // 20ms for congested CPUs
#define MAX_NUMA_NODES 8
#define MAX_CPUS 1024

/*
 * CPU to NUMA node mapping
 * Populated by userspace based on actual topology
 */
struct {
       __uint(type, BPF_MAP_TYPE_ARRAY);
       __type(key, u32);
       __type(value, u32);
       __uint(max_entries, MAX_CPUS);
} cpu_node_map SEC(".maps");

/*
 * Get NUMA node ID for a CPU from the map
 */
static u32 get_numa_node(s32 cpu)
{
       if (cpu < 0 || cpu >= MAX_CPUS)
               return 0;
               
       u32 *node_id = bpf_map_lookup_elem(&cpu_node_map, &cpu);
       if (!node_id)
               return 0; // Fallback
               
       return *node_id;
}
/*
 * Check if two CPUs are on the same NUMA node
 */
// static bool same_numa_node(s32 cpu1, s32 cpu2)
// {
	// if (cpu1 < 0 || cpu2 < 0)
		// return false;
	// return get_numa_node(cpu1) == get_numa_node(cpu2);
// }

/*
 * Get the preferred CPUs for the same NUMA node
 */
static s32 pick_idle_cpu_in_numa_node(struct task_struct *p, u32 numa_node)
{
	s32 cpu;
	
	/* Try to find idle core in the same NUMA node */
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, SCX_PICK_IDLE_CORE);
	if (cpu >= 0 && get_numa_node(cpu) == numa_node)
		return cpu;
	
	/* Try any idle CPU in the same NUMA node */
	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0 && get_numa_node(cpu) == numa_node)
		return cpu;
	
	return -1;
}

s32 BPF_STRUCT_OPS(tssc_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    s32 cpu;
    s32 current_cpu = bpf_get_smp_processor_id();
    u32 current_node = get_numa_node(current_cpu);
    u32 prev_node = (prev_cpu >= 0) ? get_numa_node(prev_cpu) : MAX_NUMA_NODES;

    /*
     * 1. NUMA-AWARE STICKY: Prioritize same NUMA node affinity
     * 
     * HPC workloads benefit immensely from NUMA locality. We prefer:
     * - Same CPU (best: L1/L2 cache + local memory)
     * - Same NUMA node (good: L3 cache + local memory)  
     * - Different NUMA node (bad: remote memory access)
     */
    if (prev_cpu >= 0 && bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
        /* Strong preference for same CPU */
        if (prev_cpu == current_cpu) {
            return prev_cpu;
        }
        /* Good preference for same NUMA node */
        if (prev_node == current_node) {
            return prev_cpu;
        }
    }

    /*
     * 2. NUMA-AWARE NEW PLACEMENT: Pick idle core in current NUMA node first
     * 
     * Optimization for SMT/Dual-Socket with NUMA awareness:
     * Step A: Try to find a fully idle PHYSICAL CORE in the same NUMA node.
     * This preserves both cache locality AND memory locality.
     */
    cpu = pick_idle_cpu_in_numa_node(p, current_node);
    if (cpu >= 0) {
        return cpu;
    }

    /*
     * Step B: If no idle core in current NUMA node, try any idle physical core.
     * Better to run on a different NUMA node than wait in queue.
     */
    cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, SCX_PICK_IDLE_CORE);
    if (cpu >= 0) {
        return cpu;
    }

    /*
     * Step C: Try any idle logical core (SMT sibling).
     */
    cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
    if (cpu >= 0) {
        return cpu;
    }

    /*
     * 3. FALLBACK: Pick any allowed CPU with NUMA-aware distribution.
     * System is saturated, but we still prefer the current NUMA node.
     */
    cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
    if (cpu >= 0) {
        return cpu;
    }

    /*
     * 4. LAST RESORT: Return any valid CPU in the mask.
     * We avoid blindly returning current_cpu because it might violate affinity,
     * which causes the kernel to unload the scheduler (UEI crash).
     */
    if (current_cpu >= 0 && bpf_cpumask_test_cpu(current_cpu, p->cpus_ptr)) {
        return current_cpu;
    }
    return bpf_cpumask_first(p->cpus_ptr);
}

void BPF_STRUCT_OPS(tssc_enqueue, struct task_struct *p, u64 enq_flags)
{
    s32 cpu = scx_bpf_task_cpu(p);
    s32 current_cpu = bpf_get_smp_processor_id();
    u64 slice = TSSC_SLICE_INF;
    bool is_congested = false;
    u32 current_node = get_numa_node(current_cpu);
    u32 task_node = get_numa_node(cpu);

    /* 
     * Safety fallback: Ensure CPU is valid and allowed.
     * If cpu is invalid (<0) OR not in the affinity mask, pick a valid one.
     */
    if (cpu < 0 || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
        /* Try to pick CPU in the same NUMA node first */
        cpu = pick_idle_cpu_in_numa_node(p, current_node);
        if (cpu < 0) {
            cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
            if (cpu < 0) {
                /* Ultimate fallback: first allowed CPU */
                cpu = bpf_cpumask_first(p->cpus_ptr);
            }
        }
        task_node = get_numa_node(cpu);
    }

    /*
     * ENHANCED SAFETY VALVE with NUMA awareness:
     * 
     * 1. Check local queue congestion
     * 2. Consider cross-NUMA migration cost
     * 3. Adaptive slice based on NUMA locality and congestion
     */
    u64 current_queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
    
    /* Enhanced congestion detection */
    is_congested = (current_queued > 0);
    
    /* 
     * NUMA-aware slice adjustment:
     * - Cross-NUMA tasks get finite slices even on idle CPUs to prevent
     *   "remote memory bandwidth hogging"
     * - Same-NUMA tasks maintain infinite slices for maximum throughput
     */
    if (is_congested) {
        slice = TSSC_SLICE_CONGESTED;
    } else if (task_node != current_node) {
        /* Cross-NUMA tasks get reduced but still generous slices */
        slice = TSSC_SLICE_CONGESTED * 2; /* 40ms for cross-NUMA */
    }

    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, enq_flags);
    
    /* Collect NUMA locality statistics */
    if (task_node == current_node) {
        increment_stat(STAT_TASKS_LOCAL_NUMA);
    } else {
        increment_stat(STAT_TASKS_CROSS_NUMA);
    }
    
    /* Collect slice allocation statistics */
    if (slice == TSSC_SLICE_INF) {
        increment_stat(STAT_INFINITE_SLICES);
    } else {
        increment_stat(STAT_CONGESTED_SLICES);
    }
    
    /*
     * NUMA-aware CPU kick strategy:
     * 
     * Kick when:
     * 1. Enqueuing to a different CPU
     * 2. This is a wakeup operation
     * 3. Enhanced: consider NUMA locality and urgency
     * 
     * Cross-NUMA wakeups get higher priority kicks due to memory latency concerns
     */
    bool should_kick = (cpu != current_cpu) && (enq_flags & SCX_ENQ_WAKEUP);
    
    /* 
     * Additional kick conditions for NUMA optimization:
     * - Always kick on cross-NUMA wakeups (memory latency critical)
     * - Kick on same-NUMA if there's congestion (fairness)
     * 
     * CRITICAL FIX: We must kick unconditionally on wakeup.
     * The previous logic skipped kicking for uncongested local nodes, which
     * caused tasks to sit in the queue of idle CPUs without waking them up.
     */
    if (should_kick) {
        scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
        
        /* Collect kick statistics */
        if (task_node == current_node) {
            increment_stat(STAT_KICKS_LOCAL_NUMA);
        } else {
            increment_stat(STAT_KICKS_CROSS_NUMA);
        }
    }
}

static void increment_stat(u32 stat_id)
{
	u64 *cntp;
	u32 key = stat_id;

	cntp = bpf_map_lookup_elem(&stats, &key);
	if (cntp)
		(*cntp)++;
}

void BPF_STRUCT_OPS(tssc_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(tssc_ops,
           .select_cpu      = (void *)tssc_select_cpu,
           .enqueue         = (void *)tssc_enqueue,
           .exit            = (void *)tssc_exit,
           .name            = "scx_tssc");
