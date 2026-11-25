//! Lock-free POSIX Signal Handling (`SIGTERM`, `SIGINT`, `SIGHUP`, `SIGPIPE` ignore)
//! enabling zero-drop graceful process drain and live config reload.

use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN_SIGNALED: AtomicBool = AtomicBool::new(false);
static RELOAD_SIGNALED: AtomicBool = AtomicBool::new(false);

const SIGINT: i32 = 2;
const SIGPIPE: i32 = 13;
const SIGTERM: i32 = 15;
const SIGHUP: i32 = 1;
const SIG_IGN: usize = 1;

extern "C" {
    fn signal(sig: i32, handler: usize) -> usize;
}

extern "C" fn handle_shutdown(_sig: i32) {
    SHUTDOWN_SIGNALED.store(true, Ordering::Release);
}

extern "C" fn handle_reload(_sig: i32) {
    RELOAD_SIGNALED.store(true, Ordering::Release);
}

/// Install Tier-0 POSIX signal handlers:
/// - `SIGPIPE` ignored (prevents broken client sockets from killing the NLB)
/// - `SIGTERM` / `SIGINT` trigger graceful connection drain
/// - `SIGHUP` triggers state-file reload
pub fn install_signal_handlers() {
    unsafe {
        signal(SIGPIPE, SIG_IGN);
        signal(SIGTERM, handle_shutdown as *const () as usize);
        signal(SIGINT, handle_shutdown as *const () as usize);
        signal(SIGHUP, handle_reload as *const () as usize);
    }
}

#[inline(always)]
pub fn shutdown_requested() -> bool {
    SHUTDOWN_SIGNALED.load(Ordering::Acquire)
}

#[inline(always)]
pub fn take_reload_request() -> bool {
    RELOAD_SIGNALED.swap(false, Ordering::AcqRel)
}

pub fn reset_signals_for_test() {
    SHUTDOWN_SIGNALED.store(false, Ordering::Release);
    RELOAD_SIGNALED.store(false, Ordering::Release);
}
