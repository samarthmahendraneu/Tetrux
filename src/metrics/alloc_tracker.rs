//! Zero-overhead opt-in global counting allocator to mathematically prove
//! ZERO heap allocations on the L4 data path.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

pub static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
pub static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
pub static DEALLOC_COUNT: AtomicU64 = AtomicU64::new(0);

pub struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    #[inline(always)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc(layout)
    }

    #[inline(always)]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }

    #[inline(always)]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }

    #[inline(always)]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AllocSnapshot {
    pub allocs: u64,
    pub bytes: u64,
    pub deallocs: u64,
}

impl AllocSnapshot {
    #[inline]
    pub fn now() -> Self {
        Self {
            allocs: ALLOC_COUNT.load(Ordering::Relaxed),
            bytes: ALLOC_BYTES.load(Ordering::Relaxed),
            deallocs: DEALLOC_COUNT.load(Ordering::Relaxed),
        }
    }

    #[inline]
    pub fn delta(start: Self, end: Self) -> Self {
        Self {
            allocs: end.allocs.saturating_sub(start.allocs),
            bytes: end.bytes.saturating_sub(start.bytes),
            deallocs: end.deallocs.saturating_sub(start.deallocs),
        }
    }
}
