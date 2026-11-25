//! Raw OS syscall, socket, event poller, hardware clock, and process telemetry layer.
//! Zero external dependencies: links directly against system libc / libSystem.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};

pub mod signal;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

pub type Fd = i32;

/// Global syscall counter for transparent telemetry / mode-switch measurement.
/// Disabled in zero-overhead paths unless counted via per-worker local counters.
#[derive(Default, Debug, Clone, Copy)]
pub struct SyscallCounters {
    pub poll_calls: u64,
    pub poll_events: u64,
    pub accept_calls: u64,
    pub io_calls: u64,
    pub wakeups_sent: u64,
    pub wakeups_suppressed: u64,
}

/// Compact 4-byte IPv4 + 2-byte port endpoint in host byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct EndpointV4 {
    pub ip: u32,
    pub port: u16,
}

impl EndpointV4 {
    #[inline(always)]
    pub const fn new(ip: u32, port: u16) -> Self {
        Self { ip, port }
    }

    #[inline(always)]
    pub fn from_std(addr: SocketAddrV4) -> Self {
        Self {
            ip: u32::from(*addr.ip()),
            port: addr.port(),
        }
    }

    #[inline(always)]
    pub fn to_std(self) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(self.ip), self.port)
    }

    #[inline(always)]
    pub fn from_octets(a: u8, b: u8, c: u8, d: u8, port: u16) -> Self {
        Self {
            ip: u32::from_be_bytes([a, b, c, d]),
            port,
        }
    }
}

impl std::fmt::Display for EndpointV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_std())
    }
}

/// Platform-independent event returned by `Poller::poll`.
#[derive(Clone, Copy, Debug)]
pub struct PollEvent {
    pub token: u64,
    pub readable: bool,
    pub writable: bool,
    pub eof: bool,
    pub error: bool,
    pub is_user: bool,
    /// Hint on readable bytes or pending accepts (available from kqueue `data`).
    pub data_hint: i64,
}

/// Snapshot of OS-reported CPU, context-switch, and RSS telemetry.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessMetrics {
    pub user_time_us: u64,
    pub sys_time_us: u64,
    pub voluntary_ctx_switches: u64,
    pub involuntary_ctx_switches: u64,
    pub peak_rss_bytes: u64,
    pub current_rss_bytes: u64,
}

impl ProcessMetrics {
    #[inline]
    pub fn delta(start: &Self, end: &Self) -> ProcessMetricsDelta {
        ProcessMetricsDelta {
            user_time_us: end.user_time_us.saturating_sub(start.user_time_us),
            sys_time_us: end.sys_time_us.saturating_sub(start.sys_time_us),
            voluntary_ctx_switches: end
                .voluntary_ctx_switches
                .saturating_sub(start.voluntary_ctx_switches),
            involuntary_ctx_switches: end
                .involuntary_ctx_switches
                .saturating_sub(start.involuntary_ctx_switches),
            peak_rss_bytes: end.peak_rss_bytes,
            current_rss_bytes: end.current_rss_bytes,
            rss_delta_bytes: end.current_rss_bytes as i64 - start.current_rss_bytes as i64,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessMetricsDelta {
    pub user_time_us: u64,
    pub sys_time_us: u64,
    pub voluntary_ctx_switches: u64,
    pub involuntary_ctx_switches: u64,
    pub peak_rss_bytes: u64,
    pub current_rss_bytes: u64,
    pub rss_delta_bytes: i64,
}

/// CPU spin-loop relaxation hint to reduce pipeline flushes & power during busy-poll.
#[inline(always)]
pub fn cpu_relax() {
    core::hint::spin_loop();
}

/// Ultra-fast monotonic nanosecond clock using userspace hardware counters when available
/// (zero syscalls on ARM64 `cntvct_el0` and x86_64 TSC/clock fallback).
static CLOCK_FREQ_HZ: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
pub fn fast_now_ns() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let freq = match CLOCK_FREQ_HZ.load(Ordering::Relaxed) {
            0 => {
                let f: u64;
                unsafe {
                    core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack, preserves_flags));
                }
                let f = if f == 0 { 1_000_000_000 } else { f };
                CLOCK_FREQ_HZ.store(f, Ordering::Relaxed);
                f
            }
            f => f,
        };
        let cnt: u64;
        unsafe {
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) cnt, options(nomem, nostack, preserves_flags));
        }
        if freq == 1_000_000_000 {
            cnt
        } else {
            ((cnt as u128 * 1_000_000_000u128) / (freq as u128)) as u64
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        monotonic_clock_ns()
    }
}

/// Convert raw OS errno into `io::Error`.
#[inline]
pub fn last_os_error() -> io::Error {
    io::Error::last_os_error()
}

/// Helper to read available CPU cores.
pub fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_clock_is_monotonic() {
        let t1 = fast_now_ns();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let t2 = fast_now_ns();
        assert!(t2 > t1, "t2={t2} should be > t1={t1}");
        let diff_ms = (t2 - t1) / 1_000_000;
        assert!(diff_ms >= 1 && diff_ms < 200, "diff_ms={diff_ms}");
    }

    #[test]
    fn process_metrics_sample_nonzero_rss() {
        let m = sample_process_metrics();
        assert!(m.current_rss_bytes > 0);
        assert!(m.peak_rss_bytes > 0);
    }
}
