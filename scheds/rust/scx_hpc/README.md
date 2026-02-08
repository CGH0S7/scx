# scx_hpc

An HPC-dedicated [sched_ext](https://github.com/sched-ext/scx) scheduler designed to minimize OS noise for MPI/OpenMP scientific computing workloads.

## Overview

`scx_hpc` partitions CPUs into two classes:

- **Compute cores** — Dedicated to HPC tasks. These run with an infinite time slice (`SCX_SLICE_INF`), experience zero scheduler-driven preemption, and never execute non-HPC work. The goal is to let MPI ranks and OpenMP threads run completely undisturbed until they voluntarily yield (e.g., at an `MPI_Barrier`, `pthread_barrier_wait`, or I/O call).

- **Service core(s)** — Handle everything else: OS housekeeping, system daemons, kernel threads, and any non-HPC user processes. These use vruntime-based fair scheduling with configurable time slices.

This two-class model directly addresses the primary performance bottleneck in tightly-coupled parallel applications: **OS jitter**. When one MPI rank is delayed by even a few milliseconds of scheduler interference, all other ranks stall at the next synchronization barrier, amplifying the noise into a global slowdown.

## Why Not scx_tickless?

`scx_tickless` takes a different approach: it routes *all* wakeups through a set of primary CPUs, then redistributes tasks to tickless CPUs via a BPF timer. This design has two problems for HPC workloads:

1. **OpenMP penalty** — When an OpenMP thread team wakes up (e.g., entering a parallel region), every thread is first routed to a primary CPU and then redistributed. This adds latency to every fork-join cycle and can significantly degrade OpenMP performance.

2. **No task differentiation** — `scx_tickless` treats all tasks identically. There is no mechanism to ensure that HPC tasks get priority on compute cores while system daemons stay out of the way.

`scx_hpc` solves both problems:
- HPC tasks select their CPU directly in `select_cpu()` with no primary CPU detour.
- Non-HPC tasks are confined to service cores and can never land on compute cores.
- No `nohz_full` kernel boot parameter or `isolcpus` setup is required.

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │              scx_hpc Scheduler              │
                    ├──────────────────────┬──────────────────────┤
                    │   Compute Cores      │   Service Core(s)    │
                    │                      │                      │
                    │  - HPC tasks only    │  - All other tasks   │
                    │  - SCX_SLICE_INF     │  - vruntime fairness │
                    │  - Zero preemption   │  - Configurable tick │
                    │  - Max CPU frequency │  - BPF timer driven  │
                    │  - NUMA-local place  │                      │
                    │  - SMT-aware idle    │                      │
                    └──────────────────────┴──────────────────────┘
```

### Task Classification

Tasks are classified at creation time (`init_task`) using the following priority:

| Priority | Condition | Class |
|----------|-----------|-------|
| 1 | Kernel thread (`PF_KTHREAD`) | SERVICE |
| 2 | tgid in `hpc_tgids` BPF map | HPC |
| 3 | comm prefix matches `--hpc-comm` | HPC |
| 4 | Default | SERVICE |

### Scheduling Callbacks

**`select_cpu`** — CPU selection on wakeup:
- HPC tasks: prefer `prev_cpu` if it is a compute core (cache locality), then try a NUMA-local idle compute core (`SCX_PICK_IDLE_CORE` for full physical cores), then fall back to any idle compute core globally.
- SERVICE tasks: always routed to a service core.

**`enqueue`** — Task insertion:
- HPC tasks: `scx_bpf_dsq_insert(SCX_DSQ_LOCAL, SCX_SLICE_INF)` — direct local dispatch, no queuing overhead.
- SERVICE tasks: `scx_bpf_dsq_insert_vtime(SERVICE_DSQ, deadline)` — fair vruntime-based ordering.

**`dispatch`** — CPU dispatch:
- Compute cores: **never** consume from `SERVICE_DSQ`. If the previous task is HPC and still runnable, extend it with `SCX_SLICE_INF`. Otherwise, go idle.
- Service cores: consume from `SERVICE_DSQ` via `scx_bpf_dsq_move_to_local`.

**`running`** — Task starts executing:
- HPC tasks: call `scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE)` to request maximum CPU frequency.

### BPF Timer

A BPF timer runs **only on service cores**. It periodically checks for contention among SERVICE tasks and sets finite time slices when preemption is needed. It never touches compute cores.

## Usage

### Basic (Auto Mode)

By default, `scx_hpc` uses the lowest-capacity CPU as the service core and all remaining CPUs as compute cores:

```bash
sudo scx_hpc --hpc-comm "mpirun,lammps,vasp,gromacs"
```

### Specify Compute/Service Cores Manually

Use hex bitmasks to control CPU partitioning:

```bash
# CPUs 0-3 as service, CPUs 4-31 as compute
sudo scx_hpc --service-cpus f --compute-cpus fffffff0 --hpc-pids "12345,12346"
```

### Register HPC Tasks by PID

```bash
sudo scx_hpc --hpc-pids "$(pgrep -d, mpirun)"
```

### Register HPC Tasks by Process Name Prefix

```bash
sudo scx_hpc --hpc-comm "mpirun,orted,lammps,vasp,gromacs,openfoam,nekrs,wrf"
```

### Monitor Statistics

```bash
sudo scx_hpc --hpc-comm "mpirun" --stats 1
```

### Typical Workflow for a Competition Run

```bash
# 1. Start the scheduler (auto-detect cores, match MPI processes by name)
sudo scx_hpc --hpc-comm "mpirun,lammps" --stats 2 &

# 2. Run the MPI job
mpirun -np 16 ./lammps -in input.lammps

# 3. Stop the scheduler (Ctrl-C or kill)
sudo kill %1
```

## Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--compute-cpus <HEX>` | `0` (auto) | Hex bitmask of compute cores. `0` = all except lowest-capacity CPU. |
| `--service-cpus <HEX>` | `0` (auto) | Hex bitmask of service cores. `0` = lowest-capacity CPU. |
| `--hpc-pids <LIST>` | none | Comma-separated PIDs/tgids to classify as HPC. |
| `--hpc-comm <LIST>` | none | Comma-separated comm name prefixes for HPC detection. |
| `-s, --slice-us <US>` | `20000` | Time slice for service tasks (microseconds). |
| `-f, --frequency <HZ>` | `0` | Timer tick frequency on service cores. `0` = kernel `CONFIG_HZ`. |
| `-n, --nosmt` | off | Disable SMT topology awareness. |
| `--stats <SEC>` | none | Enable stats monitoring at the given interval. |
| `--monitor <SEC>` | none | Stats-only mode (scheduler not launched). |
| `-v, --verbose` | off | Verbose output including libbpf details. |
| `-V, --version` | — | Print version and exit. |
| `--help-stats` | — | Show statistics field descriptions. |

## Statistics

When `--stats` is enabled, `scx_hpc` reports per-interval deltas:

```
[scx_hpc] hpc: 4821   svc: 312    hpc_preempt: 0    svc_preempt: 28   ticks: 100   numa_local: 4800  numa_remote: 21
```

| Metric | Description | Ideal Value |
|--------|-------------|-------------|
| `nr_hpc_dispatches` | HPC task dispatch events | High |
| `nr_service_dispatches` | Service task dispatch events | Low relative to HPC |
| `nr_hpc_preemptions` | Times an HPC task was preempted | **0** |
| `nr_service_preemptions` | Times a service task was preempted for fairness | Normal |
| `nr_ticks` | BPF timer ticks (service cores only) | Proportional to frequency |
| `nr_numa_local` | HPC tasks placed on their preferred NUMA node | High |
| `nr_numa_remote` | HPC tasks placed on a non-preferred NUMA node | Low |

If `nr_hpc_preemptions` is consistently 0, the scheduler is working as intended — HPC tasks are running without any OS interference.

## Safety Mechanisms

- **Minimum one service core**: If the user specifies all CPUs as compute, CPU 0 is forced to be a service core.
- **Kernel threads always SERVICE**: `PF_KTHREAD` tasks are never classified as HPC, preventing kernel thread starvation.
- **BPF timeout**: `timeout_ms = 10000` — if the scheduler stalls for 10 seconds, the kernel automatically falls back to the default scheduler.
- **Clean shutdown**: Ctrl-C cleanly detaches the BPF scheduler, returning the system to EEVDF.
- **Per-CPU task safety**: Tasks pinned to a single CPU (`nr_cpus_allowed == 1`) are dispatched to their required CPU regardless of compute/service classification.

## Limitations

- **NUMA nodes**: Up to 4 NUMA nodes are supported for per-NUMA compute cpumask tracking (BPF verifier constraint). Systems with more NUMA nodes will still work but without per-node placement optimization for nodes 4+.
- **Dynamic reclassification**: Tasks are classified at creation time. If a process is launched before `scx_hpc` and its tgid is not in `--hpc-pids`, it will be classified as SERVICE. Restarting the process or using `--hpc-comm` for name-based matching works around this.
- **Hot-load only**: This scheduler is designed for temporary use during HPC runs. It intentionally sacrifices fairness for throughput and should not be used as a general-purpose scheduler.

## Building

From the scx workspace root:

```bash
cargo build -p scx_hpc --release
```

The binary is at `target/release/scx_hpc`.

## License

GPL-2.0-only
