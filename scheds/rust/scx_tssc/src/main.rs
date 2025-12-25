use anyhow::{Result, Context};
use clap::Parser;
use log::{info, warn};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::fs;
use std::path::Path;
use libbpf_rs::{MapFlags, MapCore};
use scx_utils::{
    scx_ops_attach, scx_ops_load, scx_ops_open, uei_exited, uei_report,
    libbpf_clap_opts::LibbpfOpts, compat,
};

mod bpf_skel;
use bpf_skel::*;

#[derive(Parser, Debug)]
struct Opts {
    #[clap(short, long)]
    verbose: bool,

    #[clap(flatten)]
    libbpf: LibbpfOpts,
}

fn parse_cpulist(cpulist: &str) -> Vec<u32> {
    let mut cpus = Vec::new();
    for part in cpulist.trim().split(',') {
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<u32>(), end.parse::<u32>()) {
                for i in s..=e {
                    cpus.push(i);
                }
            }
        } else if let Ok(single) = part.parse::<u32>() {
            cpus.push(single);
        }
    }
    cpus
}

fn populate_numa_topology(skel: &mut BpfSkel) -> Result<()> {
    let sys_node = Path::new("/sys/devices/system/node");
    if !sys_node.exists() {
        warn!("NUMA topology not found at /sys/devices/system/node. Assuming single node.");
        return Ok(());
    }

    info!("Detecting NUMA topology...");
    let map = &skel.maps.cpu_node_map;

    for entry in fs::read_dir(sys_node)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with("node") && name["node".len()..].chars().all(char::is_numeric) {
                let node_id: u32 = name["node".len()..].parse().unwrap_or(0);
                let cpulist_path = path.join("cpulist");
                
                if cpulist_path.exists() {
                    let cpulist = fs::read_to_string(cpulist_path)?;
                    let cpus = parse_cpulist(&cpulist);
                    
                    for cpu in &cpus {
                        let key = cpu.to_ne_bytes();
                        let val = node_id.to_ne_bytes();
                        if let Err(e) = map.update(&key, &val, MapFlags::ANY) {
                            warn!("Failed to update NUMA map for CPU {}: {}", cpu, e);
                        }
                    }
                    info!("Node {}: detected {} CPUs", node_id, cpus.len());
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    let opts = Opts::parse();

    info!("Starting scx_tssc scheduler...");

    let mut open_object = MaybeUninit::uninit();
    let mut skel_builder = BpfSkelBuilder::default();
    skel_builder.obj_builder.debug(opts.verbose);

    let open_opts = opts.libbpf.into_bpf_open_opts();
    
    // Open the scheduler
    let mut skel = scx_ops_open!(skel_builder, &mut open_object, tssc_ops, open_opts)?;

    // Set flags for pinning and performance
    // SCX_OPS_ENQ_MIGRATION_DISABLED: Important for strict pinning
    skel.struct_ops.tssc_ops_mut().flags = 
        *compat::SCX_OPS_ENQ_LAST | 
        *compat::SCX_OPS_ENQ_MIGRATION_DISABLED |
        *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;

    // Load
    let mut skel = scx_ops_load!(skel, tssc_ops, uei)?;

    // Populate NUMA map
    populate_numa_topology(&mut skel).context("Failed to populate NUMA topology")?;

    // Attach
    let _link = scx_ops_attach!(skel, tssc_ops)?;
    
    info!("scx_tssc attached. Press Ctrl-C to exit.");

    // Wait for shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    let stats_map = &skel.maps.stats;
    let mut last_print = std::time::Instant::now();

    // Stats indices matching BPF enum
    const STAT_TASKS_LOCAL_NUMA: u32 = 0;
    const STAT_TASKS_CROSS_NUMA: u32 = 1;
    const STAT_KICKS_LOCAL_NUMA: u32 = 2;
    const STAT_KICKS_CROSS_NUMA: u32 = 3;
    const STAT_CONGESTED_SLICES: u32 = 4;
    const STAT_INFINITE_SLICES: u32 = 5;

    let stats_to_print = [
        (STAT_TASKS_LOCAL_NUMA, "Local NUMA Tasks"),
        (STAT_TASKS_CROSS_NUMA, "Cross NUMA Tasks"),
        (STAT_KICKS_LOCAL_NUMA, "Local NUMA Kicks"),
        (STAT_KICKS_CROSS_NUMA, "Cross NUMA Kicks"),
        (STAT_CONGESTED_SLICES, "Congested Slices"),
        (STAT_INFINITE_SLICES, "Infinite Slices "),
    ];

    while running.load(Ordering::SeqCst) && !uei_exited!(&skel, uei) {
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        if last_print.elapsed() >= std::time::Duration::from_secs(1) {
            println!("\n--- scx_tssc statistics ---");
            for (idx, name) in stats_to_print {
                let key = idx.to_ne_bytes();
                // Read per-cpu values
                if let Ok(Some(values)) = stats_map.lookup_percpu(&key, MapFlags::ANY) {
                    let mut total: u64 = 0;
                    for val_bytes in values {
                        if val_bytes.len() == 8 {
                            total += u64::from_ne_bytes(val_bytes.try_into().unwrap());
                        }
                    }
                    println!("{}: {}", name, total);
                }
            }
            last_print = std::time::Instant::now();
        }
    }

    uei_report!(&skel, uei)?;

    Ok(())
}