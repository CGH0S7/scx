use anyhow::Result;
use clap::Parser;
use log::info;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

    // Attach
    let _link = scx_ops_attach!(skel, tssc_ops)?;
    
    info!("scx_tssc attached. Press Ctrl-C to exit.");

    // Wait for shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    while running.load(Ordering::SeqCst) && !uei_exited!(&skel, uei) {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }

    uei_report!(&skel, uei)?;

    Ok(())
}
