use std::time::{Duration, Instant};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct StageMetric {
    pub stage: String,
    pub actor: Option<String>,
    pub operation: Option<String>,
    pub includes_process_cold_start: bool,
    pub includes_actor_cold_start: bool,
    pub wall_time_ms: f64,
    pub cpu_user_ms: Option<f64>,
    pub cpu_system_ms: Option<f64>,
    pub rss_start_kb: Option<u64>,
    pub rss_end_kb: Option<u64>,
    pub rss_stage_delta_kb: Option<i64>,
    pub process_rss_peak_kb: Option<u64>,
    pub artifact_bytes: u64,
}

#[derive(Debug)]
pub struct StageTimer {
    stage: &'static str,
    actor: Option<&'static str>,
    operation: Option<&'static str>,
    includes_process_cold_start: bool,
    includes_actor_cold_start: bool,
    start: Instant,
    usage_start: ResourceUsage,
}

#[derive(Debug, Clone, Copy, Default)]
struct ResourceUsage {
    cpu_user_ms: Option<f64>,
    cpu_system_ms: Option<f64>,
    rss_kb: Option<u64>,
    rss_peak_kb: Option<u64>,
}

impl StageTimer {
    pub fn start_for(
        stage: &'static str,
        actor: &'static str,
        operation: &'static str,
        includes_process_cold_start: bool,
        includes_actor_cold_start: bool,
    ) -> Self {
        Self {
            stage,
            actor: Some(actor),
            operation: Some(operation),
            includes_process_cold_start,
            includes_actor_cold_start,
            start: Instant::now(),
            usage_start: ResourceUsage::capture(),
        }
    }

    pub fn finish(self, artifact_bytes: u64) -> StageMetric {
        let usage_end = ResourceUsage::capture();
        let rss_stage_delta_kb = match (usage_end.rss_kb, self.usage_start.rss_kb) {
            (Some(end), Some(start)) => Some(end as i64 - start as i64),
            _ => None,
        };
        StageMetric {
            stage: self.stage.to_string(),
            actor: self.actor.map(str::to_string),
            operation: self.operation.map(str::to_string),
            includes_process_cold_start: self.includes_process_cold_start,
            includes_actor_cold_start: self.includes_actor_cold_start,
            wall_time_ms: duration_ms(self.start.elapsed()),
            cpu_user_ms: diff_option(usage_end.cpu_user_ms, self.usage_start.cpu_user_ms),
            cpu_system_ms: diff_option(usage_end.cpu_system_ms, self.usage_start.cpu_system_ms),
            rss_start_kb: self.usage_start.rss_kb,
            rss_end_kb: usage_end.rss_kb,
            rss_stage_delta_kb,
            process_rss_peak_kb: usage_end.rss_peak_kb,
            artifact_bytes,
        }
    }
}

impl ResourceUsage {
    fn capture() -> Self {
        platform_usage()
    }
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn diff_option(end: Option<f64>, start: Option<f64>) -> Option<f64> {
    Some(end? - start?)
}

#[cfg(target_os = "linux")]
fn platform_usage() -> ResourceUsage {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let (cpu_user_ms, cpu_system_ms, rss_peak_kb) =
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } == 0 {
            let usage = unsafe { usage.assume_init() };
            (
                Some(timeval_ms(usage.ru_utime)),
                Some(timeval_ms(usage.ru_stime)),
                Some(usage.ru_maxrss as u64),
            )
        } else {
            (None, None, None)
        };

    ResourceUsage {
        cpu_user_ms,
        cpu_system_ms,
        rss_kb: current_rss_kb(),
        rss_peak_kb,
    }
}

#[cfg(target_os = "linux")]
fn timeval_ms(value: libc::timeval) -> f64 {
    value.tv_sec as f64 * 1000.0 + value.tv_usec as f64 / 1000.0
}

#[cfg(target_os = "linux")]
fn current_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok());
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn platform_usage() -> ResourceUsage {
    ResourceUsage::default()
}
