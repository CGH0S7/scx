# scx_hpc 中文文档

面向 MPI/OpenMP 科学计算负载的 HPC 专用 [sched_ext](https://github.com/sched-ext/scx) 调度器。

## 概述

`scx_hpc` 将 CPU 划分为两类：

- **计算核心 (Compute cores)** — 专供 HPC 任务使用。以无限时间片 (`SCX_SLICE_INF`) 运行，不受调度器抢占，且永远不会执行非 HPC 工作。目标是让 MPI rank 和 OpenMP 线程完全不受干扰地运行，直到它们主动让出 CPU（如 `MPI_Barrier`、`pthread_barrier_wait` 或 I/O 调用）。

- **服务核心 (Service cores)** — 处理其他所有任务：OS 管家工作、系统守护进程、内核线程以及任何非 HPC 用户进程。使用基于 vruntime 的公平调度，时间片可配置。

这种双类模型直接解决了紧耦合并行应用的首要性能瓶颈：**操作系统抖动 (OS jitter)**。当某个 MPI rank 因调度器干扰而延迟哪怕几毫秒，所有其他 rank 都会在下一个同步屏障处停滞，将噪声放大为全局性能下降。

## 为什么不用 scx_tickless？

`scx_tickless` 采用了不同的方案：它将*所有*唤醒路由到一组主 CPU (primary CPU)，然后通过 BPF 定时器将任务重新分配到 tickless CPU。这种设计对 HPC 负载有两个问题：

1. **OpenMP 惩罚** — 当 OpenMP 线程组唤醒时（例如进入并行区域），每个线程首先被路由到主 CPU，然后再重新分配。这为每次 fork-join 循环增加了延迟，可能显著降低 OpenMP 性能。

2. **无任务区分** — `scx_tickless` 对所有任务一视同仁。没有机制确保 HPC 任务在计算核心上获得优先权，同时让系统守护进程远离计算核心。

`scx_hpc` 解决了这两个问题：
- HPC 任务在 `select_cpu()` 中直接选择 CPU，无需经过主 CPU 中转。
- 非 HPC 任务被限制在服务核心上，永远不会落在计算核心上。
- 不需要 `nohz_full` 内核启动参数或 `isolcpus` 设置。

## 架构

```
                    ┌─────────────────────────────────────────────┐
                    │              scx_hpc 调度器                  │
                    ├──────────────────────┬──────────────────────┤
                    │   计算核心            │   服务核心            │
                    │                      │                      │
                    │  - 仅 HPC 任务       │  - 所有其他任务       │
                    │  - SCX_SLICE_INF     │  - vruntime 公平调度  │
                    │  - 零抢占            │  - 可配置时间片       │
                    │  - 最大 CPU 频率     │  - BPF 定时器驱动     │
                    │  - NUMA 本地放置     │                      │
                    │  - SMT 感知空闲选择  │                      │
                    └──────────────────────┴──────────────────────┘
```

### 任务分类

任务在创建时 (`init_task`) 按以下优先级分类：

| 优先级 | 条件 | 分类 |
|--------|------|------|
| 1 | 内核线程 (`PF_KTHREAD`) | SERVICE |
| 2 | tgid 在 `hpc_tgids` BPF 映射中 | HPC |
| 3 | 进程名前缀匹配 `--hpc-comm` | HPC |
| 4 | 默认 | SERVICE |

### 调度回调

**`select_cpu`** — 唤醒时的 CPU 选择：
- HPC 任务：优先选择 `prev_cpu`（如果它是计算核心，利用缓存局部性），然后尝试 NUMA 本地的空闲计算核心（`SCX_PICK_IDLE_CORE` 选择完整物理核心），最后回退到全局任意空闲计算核心。
- SERVICE 任务：始终路由到服务核心。

**`enqueue`** — 任务入队：
- HPC 任务：`scx_bpf_dsq_insert(SCX_DSQ_LOCAL, SCX_SLICE_INF)` — 直接本地派发，无排队开销。
- SERVICE 任务：`scx_bpf_dsq_insert_vtime(SERVICE_DSQ, deadline)` — 基于 vruntime 的公平排序。

**`dispatch`** — CPU 派发：
- 计算核心：**永远不会**从 `SERVICE_DSQ` 消费任务。如果前一个任务是 HPC 且仍可运行，则以 `SCX_SLICE_INF` 延续。否则进入空闲。
- 服务核心：通过 `scx_bpf_dsq_move_to_local` 从 `SERVICE_DSQ` 消费任务。

**`running`** — 任务开始执行：
- HPC 任务：调用 `scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE)` 请求最大 CPU 频率。

### BPF 定时器

BPF 定时器**仅在服务核心上运行**。它定期检查 SERVICE 任务之间的竞争情况，在需要抢占时设置有限时间片。它永远不会触及计算核心。

## 使用方法

### 基本用法（自动模式）

默认情况下，`scx_hpc` 使用容量最低的 CPU 作为服务核心，其余所有 CPU 作为计算核心：

```bash
sudo scx_hpc --hpc-comm "mpirun,lammps,vasp,gromacs"
```

### 手动指定计算/服务核心

使用十六进制位掩码控制 CPU 分区：

```bash
# CPU 0-3 作为服务核心，CPU 4-31 作为计算核心
sudo scx_hpc --service-cpus f --compute-cpus fffffff0 --hpc-pids "12345,12346"
```

### 通过 PID 注册 HPC 任务

```bash
sudo scx_hpc --hpc-pids "$(pgrep -d, mpirun)"
```

### 通过进程名前缀注册 HPC 任务

```bash
sudo scx_hpc --hpc-comm "mpirun,orted,lammps,vasp,gromacs,openfoam,nekrs,wrf"
```

### 监控统计信息

```bash
sudo scx_hpc --hpc-comm "mpirun" --stats 1
```

### 竞赛典型工作流

```bash
# 1. 启动调度器（自动检测核心，按进程名匹配 MPI 进程）
sudo scx_hpc --hpc-comm "mpirun,lammps" --stats 2 &

# 2. 运行 MPI 作业
mpirun -np 16 ./lammps -in input.lammps

# 3. 停止调度器（Ctrl-C 或 kill）
sudo kill %1
```

## 命令行选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--compute-cpus <HEX>` | `0`（自动） | 计算核心的十六进制位掩码。`0` = 除最低容量 CPU 外的所有 CPU。 |
| `--service-cpus <HEX>` | `0`（自动） | 服务核心的十六进制位掩码。`0` = 最低容量 CPU。 |
| `--hpc-pids <LIST>` | 无 | 逗号分隔的 PID/tgid 列表，标记为 HPC 任务。 |
| `--hpc-comm <LIST>` | 无 | 逗号分隔的进程名前缀，用于 HPC 任务检测。 |
| `-s, --slice-us <US>` | `20000` | 服务任务的时间片（微秒）。 |
| `-f, --frequency <HZ>` | `0` | 服务核心上的定时器频率。`0` = 内核 `CONFIG_HZ`。 |
| `-n, --nosmt` | 关闭 | 禁用 SMT 拓扑感知。 |
| `--stats <SEC>` | 无 | 以指定间隔启用统计监控。 |
| `--monitor <SEC>` | 无 | 仅统计监控模式（不启动调度器）。 |
| `-v, --verbose` | 关闭 | 详细输出，包括 libbpf 细节。 |
| `-V, --version` | — | 打印版本并退出。 |
| `--help-stats` | — | 显示统计字段说明。 |

## 统计指标

启用 `--stats` 后，`scx_hpc` 报告每个间隔的增量：

```
[scx_hpc] hpc: 4821   svc: 312    hpc_preempt: 0    svc_preempt: 28   ticks: 100   numa_local: 4800  numa_remote: 21
```

| 指标 | 说明 | 理想值 |
|------|------|--------|
| `nr_hpc_dispatches` | HPC 任务派发事件 | 高 |
| `nr_service_dispatches` | 服务任务派发事件 | 相对 HPC 较低 |
| `nr_hpc_preemptions` | HPC 任务被抢占次数 | **0** |
| `nr_service_preemptions` | 服务任务因公平性被抢占次数 | 正常 |
| `nr_ticks` | BPF 定时器滴答（仅服务核心） | 与频率成正比 |
| `nr_numa_local` | HPC 任务放置在首选 NUMA 节点 | 高 |
| `nr_numa_remote` | HPC 任务放置在非首选 NUMA 节点 | 低 |

如果 `nr_hpc_preemptions` 持续为 0，说明调度器工作正常 — HPC 任务在没有任何 OS 干扰的情况下运行。

## 安全机制

- **至少一个服务核心**：如果用户将所有 CPU 指定为计算核心，CPU 0 会被强制设为服务核心。
- **内核线程始终为 SERVICE**：`PF_KTHREAD` 任务永远不会被分类为 HPC，防止内核线程饥饿。
- **BPF 超时**：`timeout_ms = 10000` — 如果调度器停滞 10 秒，内核自动回退到默认调度器。
- **干净关闭**：Ctrl-C 会干净地卸载 BPF 调度器，系统恢复到 EEVDF。
- **单 CPU 任务安全**：绑定到单个 CPU 的任务（`nr_cpus_allowed == 1`）无论计算/服务分类如何，都会被派发到其所需的 CPU。

## 限制

- **NUMA 节点**：最多支持 4 个 NUMA 节点用于每节点计算 cpumask 跟踪（BPF 验证器约束）。超过 4 个 NUMA 节点的系统仍可工作，但第 4 个以上的节点不会有每节点放置优化。
- **动态重分类**：任务在创建时分类。如果进程在 `scx_hpc` 启动前已运行且其 tgid 不在 `--hpc-pids` 中，它将被分类为 SERVICE。重启进程或使用 `--hpc-comm` 进行名称匹配可以解决此问题。
- **仅热加载使用**：此调度器设计为在 HPC 运行期间临时使用。它有意牺牲公平性换取吞吐量，不应作为通用调度器使用。

## 构建

从 scx 工作区根目录：

```bash
cargo build -p scx_hpc --release
```

二进制文件位于 `target/release/scx_hpc`。

## 许可证

GPL-2.0-only
