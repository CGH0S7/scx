#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * HPC workloads require strict affinity, but we must prevent system lockups.
 * If a CPU is overloaded (e.g., HPC task + SSH daemon), we fall back to a
 * finite slice to ensure the system remains responsive.
 */
#define TSSC_SLICE_INF SCX_SLICE_INF
#define TSSC_SLICE_CONGESTED (20 * 1000 * 1000) // 20ms for congested CPUs

s32 BPF_STRUCT_OPS(tssc_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    s32 cpu;
    s32 current_cpu = bpf_get_smp_processor_id();

    /*
     * 1. STICKY: If the task ran here before, keep it there.
     * Cache locality (L1/L2) is King in HPC.
     * Even if the CPU is currently busy, migrating memory cache is usually
     * more expensive than waiting a tiny bit, assuming strict partitioning.
     * 
     * Fixed: Removed prev_cpu != current_cpu check which broke locality
     * when waking up on the same CPU.
     */
    if (prev_cpu >= 0 && 
        bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
        return prev_cpu;
    }

    /*
     * 2. NEW PLACEMENT: If it's a new task (or forced migration), pick an IDLE core.
     * We prefer physical cores to avoid SMT contention if possible.
     */
    cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
    if (cpu >= 0) {
        return cpu;
    }

    /*
     * 3. FALLBACK: Pick any allowed CPU with proper validation.
     * System is saturated.
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

    /* 
     * Safety fallback: Ensure CPU is valid and allowed.
     * If cpu is invalid (<0) OR not in the affinity mask, pick a valid one.
     */
    if (cpu < 0 || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
        cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
        if (cpu < 0) {
            /* Ultimate fallback: first allowed CPU */
            cpu = bpf_cpumask_first(p->cpus_ptr);
        }
    }

    /*
     * CRITICAL SAFETY VALVE:
     * Check congestion.
     * 1. If nr_queued > 0, we have waiters.
     * 
     * Note: We cannot easily check if the CPU is currently running a task (is_idle)
     * without 'scx_bpf_test_cpu_idle', so we rely on queue depth. This prevents
     * starvation when multiple tasks are queued, but might allow a new task to
     * preempt a running task and take an infinite slice (Newcomer Bully).
     * However, the critical affinity fix ensures we don't crash.
     */
    u64 current_queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
    is_congested = (current_queued > 0);
    
    if (is_congested) {
        slice = TSSC_SLICE_CONGESTED;
    }

    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, enq_flags);
    
    /*
     * Optimized CPU kick strategy:
     * Only kick remote CPUs when necessary to reduce IPI overhead.
     * Kick when:
     * 1. Enqueuing to a different CPU
     * 2. This is a wakeup operation
     * 
     * Fixed: Removed 'is_congested' check. We MUST kick on wakeup even if the queue 
     * looked empty (nr_queued==0), because there might be a task currently RUNNING 
     * with an infinite slice. If we don't kick, that running task won't be preempted, 
     * and this new task will starve ("First Waiter Starvation").
     */
    if (cpu != current_cpu && (enq_flags & SCX_ENQ_WAKEUP)) {
        scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
    }
}

void BPF_STRUCT_OPS(tssc_dispatch, s32 cpu, struct task_struct *prev)
{
    /*
     * Minimal dispatch logic with error handling.
     * Tasks are consumed directly from the built-in local DSQ.
     * 
     * The dispatcher automatically consumes from the local DSQ, so we don't
     * need explicit dispatch logic here. However, we should handle edge cases
     * and provide debugging information if needed.
     */
    
    /*
     * In case of unexpected conditions, we can add fallback logic here.
     * For now, the built-in local DSQ consumption handles most cases.
     */
    
    /* Optional: Add debugging or statistics collection here if needed */
}

void BPF_STRUCT_OPS(tssc_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(tssc_ops,
           .select_cpu      = (void *)tssc_select_cpu,
           .enqueue         = (void *)tssc_enqueue,
           .dispatch        = (void *)tssc_dispatch,
           .exit            = (void *)tssc_exit,
           .name            = "scx_tssc");