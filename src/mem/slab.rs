//! Fixed-capacity intrusive Slab allocator and Page-Aligned Lazy-Lease Ring Buffer Pool.
//! Guarantees ZERO heap allocations on the data path and bounded constant RSS memory.

use crate::sys;
use std::io;

const FREE_NONE: u32 = u32::MAX;

enum Slot<T> {
    Occupied(T),
    Vacant { next_free: u32 },
}

/// Fixed-capacity O(1) slab allocator with intrusive freelist (zero allocations after init).
pub struct Slab<T> {
    slots: Vec<Slot<T>>,
    free_head: u32,
    len: usize,
}

impl<T> Slab<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.max(1);
        let mut slots = Vec::with_capacity(cap);
        for i in 0..cap {
            let next_free = if i + 1 < cap {
                (i + 1) as u32
            } else {
                FREE_NONE
            };
            slots.push(Slot::Vacant { next_free });
        }
        Self {
            slots,
            free_head: 0,
            len: 0,
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.free_head == FREE_NONE
    }

    #[inline(always)]
    pub fn insert(&mut self, value: T) -> Option<u32> {
        if self.free_head == FREE_NONE {
            return None;
        }
        let idx = self.free_head;
        let next = match self.slots[idx as usize] {
            Slot::Vacant { next_free } => next_free,
            Slot::Occupied(_) => unreachable!("corrupted slab freelist"),
        };
        self.slots[idx as usize] = Slot::Occupied(value);
        self.free_head = next;
        self.len += 1;
        Some(idx)
    }

    #[inline(always)]
    pub fn remove(&mut self, idx: u32) -> Option<T> {
        let slot = self.slots.get_mut(idx as usize)?;
        if matches!(slot, Slot::Vacant { .. }) {
            return None;
        }
        let prev = std::mem::replace(
            slot,
            Slot::Vacant {
                next_free: self.free_head,
            },
        );
        self.free_head = idx;
        self.len -= 1;
        match prev {
            Slot::Occupied(v) => Some(v),
            Slot::Vacant { .. } => None,
        }
    }

    #[inline(always)]
    pub fn get(&self, idx: u32) -> Option<&T> {
        match self.slots.get(idx as usize)? {
            Slot::Occupied(v) => Some(v),
            Slot::Vacant { .. } => None,
        }
    }

    #[inline(always)]
    pub fn get_mut(&mut self, idx: u32) -> Option<&mut T> {
        match self.slots.get_mut(idx as usize)? {
            Slot::Occupied(v) => Some(v),
            Slot::Vacant { .. } => None,
        }
    }

    pub fn for_each_occupied<F: FnMut(u32, &mut T)>(&mut self, mut f: F) {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if let Slot::Occupied(ref mut val) = slot {
                f(i as u32, val);
            }
        }
    }
}

/// Sentinel handle indicating no pooled buffer is currently leased (bufferless fast path!).
pub const NO_BUF: u32 = u32::MAX;

/// Pre-allocated page-aligned contiguous memory arena providing fixed power-of-2 ring chunks.
/// Connections lease a chunk ONLY on write backpressure (`EAGAIN`) and release it immediately
/// once drained — keeping idle connection overhead at ~128 bytes instead of 64 KiB!
pub struct BufferPool {
    base: *mut u8,
    total_bytes: usize,
    chunk_size: usize,
    chunk_mask: usize,
    num_chunks: usize,
    free_stack: Vec<u32>,
}

unsafe impl Send for BufferPool {}

impl BufferPool {
    pub fn new(num_chunks: usize, chunk_size: usize) -> io::Result<Self> {
        assert!(chunk_size.is_power_of_two() && chunk_size >= 4096);
        let num_chunks = num_chunks.max(1);
        let total_bytes = num_chunks * chunk_size;
        let base = sys::alloc_page_aligned(total_bytes)?;
        let mut free_stack = Vec::with_capacity(num_chunks);
        for i in (0..num_chunks as u32).rev() {
            free_stack.push(i);
        }
        Ok(Self {
            base,
            total_bytes,
            chunk_size,
            chunk_mask: chunk_size - 1,
            num_chunks,
            free_stack,
        })
    }

    #[inline(always)]
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    #[inline(always)]
    pub fn chunk_mask(&self) -> usize {
        self.chunk_mask
    }

    #[inline(always)]
    pub fn available(&self) -> usize {
        self.free_stack.len()
    }

    #[inline(always)]
    pub fn in_use(&self) -> usize {
        self.num_chunks - self.free_stack.len()
    }

    #[inline(always)]
    pub fn acquire(&mut self) -> Option<u32> {
        self.free_stack.pop()
    }

    #[inline(always)]
    pub fn release(&mut self, handle: u32) {
        if handle != NO_BUF {
            debug_assert!((handle as usize) < self.num_chunks);
            self.free_stack.push(handle);
        }
    }

    #[inline(always)]
    pub fn chunk_slice(&self, handle: u32) -> &[u8] {
        debug_assert!((handle as usize) < self.num_chunks);
        let off = (handle as usize) * self.chunk_size;
        unsafe { std::slice::from_raw_parts(self.base.add(off), self.chunk_size) }
    }

    #[inline(always)]
    pub fn chunk_slice_mut(&mut self, handle: u32) -> &mut [u8] {
        debug_assert!((handle as usize) < self.num_chunks);
        let off = (handle as usize) * self.chunk_size;
        unsafe { std::slice::from_raw_parts_mut(self.base.add(off), self.chunk_size) }
    }
}

impl Drop for BufferPool {
    fn drop(&mut self) {
        unsafe {
            sys::free_page_aligned(self.base, self.total_bytes);
        }
    }
}

/// Compact 16-byte ring-buffer cursor state attached to one direction of a TCP connection.
/// Uses zero buffer memory until backpressure occurs (`handle == NO_BUF`).
#[derive(Clone, Copy, Debug)]
pub struct PooledRing {
    pub handle: u32,
    pub head: u32,
    pub tail: u32,
}

impl Default for PooledRing {
    #[inline(always)]
    fn default() -> Self {
        Self::empty()
    }
}

impl PooledRing {
    #[inline(always)]
    pub const fn empty() -> Self {
        Self {
            handle: NO_BUF,
            head: 0,
            tail: 0,
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.tail.wrapping_sub(self.head) as usize
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    #[inline(always)]
    pub fn free_space(&self, pool: &BufferPool) -> usize {
        if self.handle == NO_BUF {
            pool.chunk_size()
        } else {
            pool.chunk_size() - self.len()
        }
    }

    /// Append bytes into the pooled ring buffer (acquiring a chunk lazily if needed).
    /// Returns number of bytes copied.
    #[inline]
    pub fn push_bytes(&mut self, pool: &mut BufferPool, src: &[u8]) -> usize {
        if src.is_empty() {
            return 0;
        }
        if self.handle == NO_BUF {
            match pool.acquire() {
                Some(h) => {
                    self.handle = h;
                    self.head = 0;
                    self.tail = 0;
                }
                None => return 0,
            }
        }
        let cap = pool.chunk_size();
        let mask = pool.chunk_mask();
        let avail = cap - self.len();
        let to_copy = avail.min(src.len());
        if to_copy == 0 {
            return 0;
        }
        let tail_idx = (self.tail as usize) & mask;
        let first = (cap - tail_idx).min(to_copy);
        let chunk = pool.chunk_slice_mut(self.handle);
        chunk[tail_idx..tail_idx + first].copy_from_slice(&src[..first]);
        if to_copy > first {
            chunk[0..(to_copy - first)].copy_from_slice(&src[first..to_copy]);
        }
        self.tail = self.tail.wrapping_add(to_copy as u32);
        to_copy
    }

    /// Return up to 2 contiguous readable slices for zero-copy `writev`.
    #[inline]
    pub fn readable_slices<'a>(&self, pool: &'a BufferPool) -> (&'a [u8], &'a [u8]) {
        let len = self.len();
        if len == 0 || self.handle == NO_BUF {
            return (&[], &[]);
        }
        let cap = pool.chunk_size();
        let mask = pool.chunk_mask();
        let head_idx = (self.head as usize) & mask;
        let first = (cap - head_idx).min(len);
        let chunk = pool.chunk_slice(self.handle);
        if len > first {
            (&chunk[head_idx..head_idx + first], &chunk[0..(len - first)])
        } else {
            (&chunk[head_idx..head_idx + first], &[])
        }
    }

    /// Consume `n` bytes; if empty, immediately release chunk back to `BufferPool`!
    #[inline]
    pub fn consume(&mut self, pool: &mut BufferPool, n: usize) {
        self.head = self.head.wrapping_add(n as u32);
        if self.head == self.tail && self.handle != NO_BUF {
            pool.release(self.handle);
            self.handle = NO_BUF;
            self.head = 0;
            self.tail = 0;
        }
    }

    /// Force release of any held buffer on connection teardown.
    #[inline]
    pub fn release_if_held(&mut self, pool: &mut BufferPool) {
        if self.handle != NO_BUF {
            pool.release(self.handle);
            self.handle = NO_BUF;
            self.head = 0;
            self.tail = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slab_insert_remove_reuse() {
        let mut slab = Slab::with_capacity(4);
        let a = slab.insert(10u32).unwrap();
        let b = slab.insert(20u32).unwrap();
        let c = slab.insert(30u32).unwrap();
        let d = slab.insert(40u32).unwrap();
        assert!(slab.insert(50).is_none());
        assert_eq!(slab.len(), 4);
        assert_eq!(slab.remove(b), Some(20));
        let e = slab.insert(99).unwrap();
        assert_eq!(e, b);
        assert_eq!(slab.get(a), Some(&10));
        assert_eq!(slab.get(c), Some(&30));
        assert_eq!(slab.get(d), Some(&40));
        assert_eq!(slab.get(e), Some(&99));
    }

    #[test]
    fn pooled_ring_wraparound_and_lazy_release() {
        let mut pool = BufferPool::new(4, 4096).unwrap();
        assert_eq!(pool.available(), 4);
        let mut ring = PooledRing::empty();
        assert_eq!(ring.push_bytes(&mut pool, &[0xAB; 3000]), 3000);
        assert_eq!(pool.available(), 3);
        ring.consume(&mut pool, 2500);
        assert_eq!(ring.len(), 500);
        // Push 3000 bytes -> wraps past 4096 boundary!
        assert_eq!(ring.push_bytes(&mut pool, &[0xCD; 3000]), 3000);
        let (s1, s2) = ring.readable_slices(&pool);
        assert_eq!(s1.len() + s2.len(), 3500);
        assert!(s2.len() > 0);
        ring.consume(&mut pool, 3500);
        assert!(ring.is_empty());
        assert_eq!(ring.handle, NO_BUF);
        assert_eq!(pool.available(), 4);
    }
}
