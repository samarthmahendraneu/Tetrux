//! Cache-line alignment (128B for Apple Silicon & 2x x86_64) and CPU prefetch hints.

use std::ops::{Deref, DerefMut};

/// 128-byte aligned wrapper to eliminate cross-core false sharing on both
/// ARM64 Apple Silicon (128B L1 cache lines) and x86_64 (64B lines with adjacent prefetcher).
#[repr(align(128))]
#[derive(Debug, Default)]
pub struct CachePadded<T>(pub T);

impl<T> CachePadded<T> {
    #[inline(always)]
    pub const fn new(val: T) -> Self {
        Self(val)
    }

    #[inline(always)]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for CachePadded<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for CachePadded<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Hint CPU to prefetch address into L1 data cache for upcoming read.
#[inline(always)]
pub fn prefetch_read<T>(ptr: *const T) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("prfm pldl1keep, [{ptr}]", ptr = in(reg) ptr, options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_prefetch(ptr as *const i8, core::arch::x86_64::_MM_HINT_T0);
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = ptr;
    }
}

/// Hint CPU to prefetch address into L1 data cache for upcoming write (in-place header rewrite).
#[inline(always)]
pub fn prefetch_write<T>(ptr: *mut T) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("prfm pstl1keep, [{ptr}]", ptr = in(reg) ptr, options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_prefetch(ptr as *const i8, core::arch::x86_64::_MM_HINT_T0);
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = ptr;
    }
}
