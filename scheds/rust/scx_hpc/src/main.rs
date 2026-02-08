// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 CGH0S7 <jasoncheng@hifuu.ink>
//
// scx_hpc - HPC-dedicated scheduler for MPI/OpenMP scientific computing.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;

use std::ffi::c_int;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use affinity::set_thread_affinity;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::{debug, info, warn};
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Cpumask;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_hpc";

#[derive(Debug, Parser)]
#[command(about = "HPC-dedicated scheduler for MPI/OpenMP scientific computing")]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Hex bitmask of CPUs to use as compute cores.
    /// "auto" = all CPUs except the lowest-capacity one.
    /// "0" or empty = auto mode.
    #[clap(long, default_value = "0")]
    compute_cpus: String,

    /// Hex bitmask of CPUs to use as service cores.
    /// "auto" or "0" = auto-detect (lowest-capacity CPU).
    #[clap(long, default_value = "0")]
    service_cpus: String,

    /// Comma-separated list of PIDs (tgids) to classify as HPC workloads.
    #[clap(long)]
    hpc_pids: Option<String>,

    /// Comma-separated list of comm name prefixes for HPC task detection.
    /// e.g., "mpirun,lammps,vasp,gromacs,openfoam"
    #[clap(long)]
    hpc_comm: Option<String>,

    /// Maximum scheduling slice for service tasks in microseconds.
    #[clap(short = 's', long, default_value = "20000")]
    slice_us: u64,

    /// Tick frequency on service cores (0 = CONFIG_HZ).
    #[clap(short = 'f', long, default_value = "0")]
    frequency: u64,

    /// Disable SMT topology awareness.
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    nosmt: bool,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval.
    /// Scheduler is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        let topo = Topology::new().unwrap();
        let smt_enabled = !opts.nosmt && topo.smt_enabled;

        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if smt_enabled { "SMT on" } else { "SMT off" }
        );

        // Determine compute and service CPU sets.
        let (compute_mask, service_mask) =
            Self::determine_cpu_partitions(opts, &topo)?;

        info!("compute CPUs: 0x{:x}", compute_mask);
        info!("service CPUs: 0x{:x}", service_mask);
        info!(
            "compute cores: {}, service cores: {}",
            compute_mask.weight(),
            service_mask.weight()
        );

        // Count NUMA nodes.
        let nr_numa_nodes = topo.nodes.len() as u32;
        info!("NUMA nodes: {}", nr_numa_nodes);

        // Open BPF skeleton.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, hpc_ops, open_opts)?;
        skel.struct_ops.hpc_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Set rodata.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.nr_cpu_ids = *NR_CPU_IDS as u32;
        rodata.nr_numa_nodes = nr_numa_nodes;
        rodata.smt_enabled = smt_enabled;
        rodata.service_slice_ns = opts.slice_us * 1000;
        rodata.tick_freq = opts.frequency;

        // Configure comm-based detection.
        if let Some(ref comm_list) = opts.hpc_comm {
            let prefixes: Vec<&str> = comm_list.split(',').collect();
            rodata.detect_by_comm = true;
            rodata.nr_comm_prefixes = prefixes.len().min(
                bpf_intf::hpc_consts_MAX_COMM_PREFIXES as usize,
            ) as u32;
        }

        // Set scheduler flags.
        skel.struct_ops.hpc_ops_mut().flags = *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_KEEP_BUILTIN_IDLE
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED;
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.hpc_ops_mut().flags
        );

        // Load BPF program.
        let mut skel = scx_ops_load!(skel, hpc_ops, uei)?;

        // Pin to a service core for timer initialization.
        let timer_cpu = service_mask.iter().next();
        if timer_cpu.is_none() {
            bail!("service cpumask is empty");
        }
        if let Err(e) = set_thread_affinity([timer_cpu.unwrap()]) {
            bail!("cannot set service CPU affinity: {}", e);
        }

        // Configure compute CPU mask.
        Self::init_cpu_mask(&mut skel, &compute_mask, true)?;

        // Configure service CPU mask.
        Self::init_cpu_mask(&mut skel, &service_mask, false)?;

        // Configure per-NUMA compute cpumasks.
        Self::init_numa_masks(&mut skel, &topo, &compute_mask)?;

        // Register HPC tgids if provided.
        if let Some(ref pid_list) = opts.hpc_pids {
            Self::register_hpc_pids(&mut skel, pid_list)?;
        }

        // Populate comm prefixes if provided.
        if let Some(ref comm_list) = opts.hpc_comm {
            Self::populate_comm_prefixes(&mut skel, comm_list)?;
        }

        // Attach scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, hpc_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        // Reset thread affinity.
        if let Err(e) = set_thread_affinity((0..*NR_CPU_IDS).collect::<Vec<usize>>()) {
            bail!("cannot reset CPU affinity: {}", e);
        }

        info!("{} scheduler attached", SCHEDULER_NAME);

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
        })
    }

    fn determine_cpu_partitions(
        opts: &Opts,
        topo: &Topology,
    ) -> Result<(Cpumask, Cpumask)> {
        let nr_cpus = *NR_CPU_IDS;

        // Sort CPUs by capacity (descending).
        let mut cpus: Vec<_> = topo.all_cpus.values().collect();
        cpus.sort_by_key(|cpu| std::cmp::Reverse(cpu.cpu_capacity));

        let compute_input = opts.compute_cpus.trim();
        let service_input = opts.service_cpus.trim();

        let mut compute_mask;
        let mut service_mask;

        if compute_input == "0" && service_input == "0" {
            // Auto mode: service = lowest-capacity CPU, compute = rest.
            service_mask = Cpumask::new();
            compute_mask = Cpumask::new();

            if let Some(slowest) = cpus.last() {
                service_mask.set_cpu(slowest.id)?;
            }

            for cpu_info in &cpus {
                if !service_mask.test_cpu(cpu_info.id) {
                    compute_mask.set_cpu(cpu_info.id)?;
                }
            }
        } else {
            // Manual mode.
            if compute_input != "0" {
                compute_mask = Cpumask::from_str(compute_input)?;
            } else {
                compute_mask = Cpumask::new();
            }

            if service_input != "0" {
                service_mask = Cpumask::from_str(service_input)?;
            } else {
                service_mask = Cpumask::new();
            }

            // If only compute specified, service = everything else.
            if compute_input != "0" && service_input == "0" {
                for cpu in 0..nr_cpus {
                    if !compute_mask.test_cpu(cpu) {
                        service_mask.set_cpu(cpu)?;
                    }
                }
            }

            // If only service specified, compute = everything else.
            if service_input != "0" && compute_input == "0" {
                for cpu in 0..nr_cpus {
                    if !service_mask.test_cpu(cpu) {
                        compute_mask.set_cpu(cpu)?;
                    }
                }
            }
        }

        // Safety: ensure at least one service core.
        if service_mask.is_empty() {
            warn!("no service cores specified, forcing CPU 0 as service");
            service_mask.set_cpu(0)?;
            compute_mask.clear_cpu(0)?;
        }

        // Safety: ensure at least one compute core.
        if compute_mask.is_empty() {
            warn!("no compute cores available, using all non-service CPUs");
            for cpu in 0..nr_cpus {
                if !service_mask.test_cpu(cpu) {
                    compute_mask.set_cpu(cpu)?;
                }
            }
        }

        Ok((compute_mask, service_mask))
    }

    fn call_cpu_syscall(
        skel: &mut BpfSkel<'_>,
        prog_name: &str,
        cpu_id: i32,
    ) -> Result<(), u32> {
        let prog = match prog_name {
            "enable_compute_cpu" => &mut skel.progs.enable_compute_cpu,
            "enable_service_cpu" => &mut skel.progs.enable_service_cpu,
            "set_numa_compute_cpu" => &mut skel.progs.set_numa_compute_cpu,
            _ => return Err(u32::MAX),
        };

        let mut args = cpu_arg {
            cpu_id: cpu_id as c_int,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }
        Ok(())
    }

    fn call_tgid_syscall(
        skel: &mut BpfSkel<'_>,
        prog_name: &str,
        tgid: i32,
    ) -> Result<(), u32> {
        let prog = match prog_name {
            "register_hpc_tgid" => &mut skel.progs.register_hpc_tgid,
            "unregister_hpc_tgid" => &mut skel.progs.unregister_hpc_tgid,
            _ => return Err(u32::MAX),
        };

        let mut args = tgid_arg { tgid };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }
        Ok(())
    }

    fn init_cpu_mask(
        skel: &mut BpfSkel<'_>,
        mask: &Cpumask,
        is_compute: bool,
    ) -> Result<()> {
        let prog_name = if is_compute {
            "enable_compute_cpu"
        } else {
            "enable_service_cpu"
        };

        // Clear the mask first.
        if let Err(err) = Self::call_cpu_syscall(skel, prog_name, -1) {
            warn!("failed to clear {} mask: error {}", prog_name, err);
        }

        // Set each CPU.
        for cpu in 0..*NR_CPU_IDS {
            if mask.test_cpu(cpu) {
                if let Err(err) = Self::call_cpu_syscall(skel, prog_name, cpu as i32) {
                    warn!(
                        "failed to add CPU {} to {} mask: error {}",
                        cpu, prog_name, err
                    );
                }
            }
        }

        Ok(())
    }

    fn init_numa_masks(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
        compute_mask: &Cpumask,
    ) -> Result<()> {
        for (node_id, node) in &topo.nodes {
            let node_idx = *node_id as i32;

            // Only support up to 4 NUMA nodes in BPF.
            if node_idx >= 4 {
                warn!(
                    "NUMA node {} exceeds BPF limit of 4, skipping",
                    node_idx
                );
                continue;
            }

            // Clear the NUMA mask first.
            if let Err(err) = Self::call_cpu_syscall(
                skel,
                "set_numa_compute_cpu",
                -(node_idx + 1),
            ) {
                warn!(
                    "failed to clear NUMA {} mask: error {}",
                    node_idx, err
                );
            }

            // Set compute CPUs in this NUMA node.
            for cpu_id in node.span.iter() {
                if compute_mask.test_cpu(cpu_id) {
                    // Encode: node in upper 16 bits, cpu in lower 16 bits.
                    let encoded = (node_idx << 16) | (cpu_id as i32);
                    if let Err(err) = Self::call_cpu_syscall(
                        skel,
                        "set_numa_compute_cpu",
                        encoded,
                    ) {
                        warn!(
                            "failed to add CPU {} to NUMA {} mask: error {}",
                            cpu_id, node_idx, err
                        );
                    }
                }
            }

            let count = node
                .span
                .iter()
                .filter(|&cpu| compute_mask.test_cpu(cpu))
                .count();
            info!(
                "NUMA node {}: {} compute CPUs",
                node_idx, count
            );
        }

        Ok(())
    }

    fn register_hpc_pids(skel: &mut BpfSkel<'_>, pid_list: &str) -> Result<()> {
        for pid_str in pid_list.split(',') {
            let pid_str = pid_str.trim();
            if pid_str.is_empty() {
                continue;
            }
            match pid_str.parse::<i32>() {
                Ok(pid) => {
                    if let Err(err) =
                        Self::call_tgid_syscall(skel, "register_hpc_tgid", pid)
                    {
                        warn!("failed to register HPC tgid {}: error {}", pid, err);
                    } else {
                        info!("registered HPC tgid: {}", pid);
                    }
                }
                Err(e) => {
                    warn!("invalid PID '{}': {}", pid_str, e);
                }
            }
        }
        Ok(())
    }

    fn populate_comm_prefixes(skel: &mut BpfSkel<'_>, comm_list: &str) -> Result<()> {
        let max_prefixes = bpf_intf::hpc_consts_MAX_COMM_PREFIXES as usize;

        for (i, prefix) in comm_list.split(',').enumerate() {
            if i >= max_prefixes {
                warn!(
                    "too many comm prefixes (max {}), ignoring rest",
                    max_prefixes
                );
                break;
            }

            let prefix = prefix.trim();
            if prefix.is_empty() {
                continue;
            }

            let max_len = bpf_intf::hpc_consts_COMM_PREFIX_LEN as usize;
            let mut buf = vec![0u8; max_len];
            let bytes = prefix.as_bytes();
            let copy_len = bytes.len().min(max_len - 1);
            buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

            let key = (i as u32).to_ne_bytes();
            skel.maps
                .comm_prefixes
                .update(&key, &buf, libbpf_rs::MapFlags::ANY)
                .context(format!("failed to set comm prefix '{}'", prefix))?;

            info!("registered HPC comm prefix: '{}'", prefix);
        }

        Ok(())
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_hpc_dispatches: bss_data.nr_hpc_dispatches,
            nr_service_dispatches: bss_data.nr_service_dispatches,
            nr_hpc_preemptions: bss_data.nr_hpc_preemptions,
            nr_service_preemptions: bss_data.nr_service_preemptions,
            nr_migrations_to_service: bss_data.nr_migrations_to_service,
            nr_ticks: bss_data.nr_ticks,
            nr_numa_local: bss_data.nr_numa_local,
            nr_numa_remote: bss_data.nr_numa_remote,
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {} scheduler", SCHEDULER_NAME);
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    let loglevel = simplelog::LevelFilter::Info;

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            match stats::monitor(Duration::from_secs_f64(intv), shutdown_copy) {
                Ok(_) => {
                    debug!("stats monitor thread finished successfully")
                }
                Err(error_object) => {
                    warn!(
                        "stats monitor thread finished because of an error {}",
                        error_object
                    )
                }
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
