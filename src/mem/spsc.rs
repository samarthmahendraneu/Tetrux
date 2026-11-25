//! Cache-line-padded, lock-free bounded SPSC ring buffer with cached remote indices
//! and vectorized batch push/pop (1 atomic Acquire + 1 Release per batch).

use super::cache::CachePadded;
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct SpscInner<T: Copy> {
    mask: usize,
    capacity: usize,
    /// Producer-owned write cursor (published with Release).
    tail: CachePadded<AtomicUsize>,
    /// Consumer-owned read cursor (published with Release).
    head: CachePadded<AtomicUsize>,
    buf: Box<[UnsafeCell<MaybeUninit<T>>]>,
}

unsafe impl<T: Copy + Send> Send for SpscInner<T> {}
unsafe impl<T: Copy + Send> Sync for SpscInner<T> {}

pub struct SpscProducer<T: Copy> {
    inner: Arc<SpscInner<T>>,
    /// Producer-local cached snapshot of consumer's `head` to avoid remote cache-line reads.
    cached_head: usize,
    /// Producer-local copy of `tail` (avoids atomic load on every push).
    local_tail: usize,
}

pub struct SpscConsumer<T: Copy> {
    inner: Arc<SpscInner<T>>,
    /// Consumer-local cached snapshot of producer's `tail`.
    cached_tail: usize,
    /// Consumer-local copy of `head`.
    local_head: usize,
}

unsafe impl<T: Copy + Send> Send for SpscProducer<T> {}
unsafe impl<T: Copy + Send> Send for SpscConsumer<T> {}

/// Create a bounded lock-free SPSC ring channel. Capacity is rounded up to a power of 2.
pub fn spsc_channel<T: Copy>(min_capacity: usize) -> (SpscProducer<T>, SpscConsumer<T>) {
    let capacity = min_capacity.max(8).next_power_of_two();
    let mut vec = Vec::with_capacity(capacity);
    for _ in 0..capacity {
        vec.push(UnsafeCell::new(MaybeUninit::uninit()));
    }
    let inner = Arc::new(SpscInner {
        mask: capacity - 1,
        capacity,
        tail: CachePadded::new(AtomicUsize::new(0)),
        head: CachePadded::new(AtomicUsize::new(0)),
        buf: vec.into_boxed_slice(),
    });
    (
        SpscProducer {
            inner: Arc::clone(&inner),
            cached_head: 0,
            local_tail: 0,
        },
        SpscConsumer {
            inner,
            cached_tail: 0,
            local_head: 0,
        },
    )
}

impl<T: Copy> SpscProducer<T> {
    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    #[inline(always)]
    pub fn free_slots(&mut self) -> usize {
        let used = self.local_tail.wrapping_sub(self.cached_head);
        if used < self.inner.capacity {
            return self.inner.capacity - used;
        }
        self.cached_head = self.inner.head.load(Ordering::Acquire);
        self.inner
            .capacity
            .saturating_sub(self.local_tail.wrapping_sub(self.cached_head))
    }

    #[inline(always)]
    pub fn try_push(&mut self, item: T) -> Result<(), T> {
        let mut used = self.local_tail.wrapping_sub(self.cached_head);
        if used >= self.inner.capacity {
            self.cached_head = self.inner.head.load(Ordering::Acquire);
            used = self.local_tail.wrapping_sub(self.cached_head);
            if used >= self.inner.capacity {
                return Err(item);
            }
        }
        let idx = self.local_tail & self.inner.mask;
        unsafe {
            (*self.inner.buf[idx].get()).write(item);
        }
        self.local_tail = self.local_tail.wrapping_add(1);
        self.inner.tail.store(self.local_tail, Ordering::Release);
        Ok(())
    }

    /// Push up to `items.len()` elements with a SINGLE atomic Release store.
    #[inline(always)]
    pub fn push_batch(&mut self, items: &[T]) -> usize {
        if items.is_empty() {
            return 0;
        }
        let mut avail = self
            .inner
            .capacity
            .wrapping_sub(self.local_tail.wrapping_sub(self.cached_head));
        if avail < items.len() {
            self.cached_head = self.inner.head.load(Ordering::Acquire);
            avail = self
                .inner
                .capacity
                .wrapping_sub(self.local_tail.wrapping_sub(self.cached_head));
        }
        let n = avail.min(items.len());
        if n == 0 {
            return 0;
        }
        let mask = self.inner.mask;
        let mut tail = self.local_tail;
        for &item in &items[..n] {
            unsafe {
                (*self.inner.buf[tail & mask].get()).write(item);
            }
            tail = tail.wrapping_add(1);
        }
        self.local_tail = tail;
        self.inner.tail.store(tail, Ordering::Release);
        n
    }
}

impl<T: Copy> SpscConsumer<T> {
    #[inline(always)]
    pub fn is_empty(&mut self) -> bool {
        if self.local_head != self.cached_tail {
            return false;
        }
        self.cached_tail = self.inner.tail.load(Ordering::Acquire);
        self.local_head == self.cached_tail
    }

    #[inline(always)]
    pub fn try_pop(&mut self) -> Option<T> {
        if self.local_head == self.cached_tail {
            self.cached_tail = self.inner.tail.load(Ordering::Acquire);
            if self.local_head == self.cached_tail {
                return None;
            }
        }
        let idx = self.local_head & self.inner.mask;
        let item = unsafe { (*self.inner.buf[idx].get()).assume_init() };
        self.local_head = self.local_head.wrapping_add(1);
        self.inner.head.store(self.local_head, Ordering::Release);
        Some(item)
    }

    /// Pop up to `out.len()` elements with a SINGLE atomic Release store.
    #[inline(always)]
    pub fn pop_batch(&mut self, out: &mut [T]) -> usize {
        if out.is_empty() {
            return 0;
        }
        let mut avail = self.cached_tail.wrapping_sub(self.local_head);
        if avail == 0 {
            self.cached_tail = self.inner.tail.load(Ordering::Acquire);
            avail = self.cached_tail.wrapping_sub(self.local_head);
            if avail == 0 {
                return 0;
            }
        }
        let n = avail.min(out.len());
        let mask = self.inner.mask;
        let mut head = self.local_head;
        for slot in &mut out[..n] {
            *slot = unsafe { (*self.inner.buf[head & mask].get()).assume_init() };
            head = head.wrapping_add(1);
        }
        self.local_head = head;
        self.inner.head.store(head, Ordering::Release);
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spsc_single_and_batch_roundtrip() {
        let (mut tx, mut rx) = spsc_channel::<u64>(64);
        for i in 0..64 {
            assert!(tx.try_push(i).is_ok());
        }
        assert!(tx.try_push(999).is_err());

        let mut buf = [0u64; 32];
        assert_eq!(rx.pop_batch(&mut buf), 32);
        assert_eq!(buf[0], 0);
        assert_eq!(buf[31], 31);

        let extra: Vec<u64> = (100..132).collect();
        assert_eq!(tx.push_batch(&extra), 32);

        assert_eq!(rx.pop_batch(&mut buf), 32);
        assert_eq!(buf[0], 32);
        assert_eq!(buf[31], 63);

        assert_eq!(rx.pop_batch(&mut buf), 32);
        assert_eq!(buf[0], 100);
        assert_eq!(buf[31], 131);
        assert!(rx.is_empty());
    }

    #[test]
    fn spsc_multithreaded_stress() {
        let (mut tx, mut rx) = spsc_channel::<u64>(1024);
        let n = 200_000u64;
        let producer = std::thread::spawn(move || {
            let mut cur = 0u64;
            let mut batch = [0u64; 32];
            while cur < n {
                let len = ((n - cur) as usize).min(32);
                for i in 0..len {
                    batch[i] = cur + i as u64;
                }
                let pushed = tx.push_batch(&batch[..len]);
                cur += pushed as u64;
                if pushed == 0 {
                    core::hint::spin_loop();
                }
            }
        });
        let mut expected = 0u64;
        let mut out = [0u64; 32];
        while expected < n {
            let popped = rx.pop_batch(&mut out);
            for &v in &out[..popped] {
                assert_eq!(v, expected);
                expected += 1;
            }
            if popped == 0 {
                core::hint::spin_loop();
            }
        }
        producer.join().unwrap();
    }
}
