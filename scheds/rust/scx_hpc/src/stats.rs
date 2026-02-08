// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 CGH0S7 <jasoncheng@hifuu.ink>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of HPC task dispatches")]
    pub nr_hpc_dispatches: u64,
    #[stat(desc = "Number of service task dispatches")]
    pub nr_service_dispatches: u64,
    #[stat(desc = "Number of HPC task preemptions (should be ~0)")]
    pub nr_hpc_preemptions: u64,
    #[stat(desc = "Number of service task preemptions")]
    pub nr_service_preemptions: u64,
    #[stat(desc = "Number of tasks migrated to service cores")]
    pub nr_migrations_to_service: u64,
    #[stat(desc = "Number of scheduler ticks (service cores only)")]
    pub nr_ticks: u64,
    #[stat(desc = "Number of NUMA-local HPC placements")]
    pub nr_numa_local: u64,
    #[stat(desc = "Number of NUMA-remote HPC placements")]
    pub nr_numa_remote: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[scx_hpc] hpc: {:<6} svc: {:<6} hpc_preempt: {:<4} \
             svc_preempt: {:<4} ticks: {:<5} numa_local: {:<5} numa_remote: {:<5}",
            self.nr_hpc_dispatches,
            self.nr_service_dispatches,
            self.nr_hpc_preemptions,
            self.nr_service_preemptions,
            self.nr_ticks,
            self.nr_numa_local,
            self.nr_numa_remote,
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_hpc_dispatches: self.nr_hpc_dispatches - rhs.nr_hpc_dispatches,
            nr_service_dispatches: self.nr_service_dispatches - rhs.nr_service_dispatches,
            nr_hpc_preemptions: self.nr_hpc_preemptions - rhs.nr_hpc_preemptions,
            nr_service_preemptions: self.nr_service_preemptions - rhs.nr_service_preemptions,
            nr_migrations_to_service: self.nr_migrations_to_service
                - rhs.nr_migrations_to_service,
            nr_ticks: self.nr_ticks - rhs.nr_ticks,
            nr_numa_local: self.nr_numa_local - rhs.nr_numa_local,
            nr_numa_remote: self.nr_numa_remote - rhs.nr_numa_remote,
        }
    }
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> =
            Box::new(move |_args, (req_ch, res_ch)| {
                req_ch.send(())?;
                let cur = res_ch.recv()?;
                let delta = cur.delta(&prev);
                prev = cur;
                delta.to_json()
            });

        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
