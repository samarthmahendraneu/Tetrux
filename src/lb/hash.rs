//! High-speed 64-bit flow hashing (WyHash-style 128-bit multiply-xor), fast Xorshift64 PRNG,
//! and branchless modulo 65537 for Maglev consistent hashing.

use crate::sys::EndpointV4;

const K0: u64 = 0xa076_1d64_78bd_642f;
const K1: u64 = 0xe703_7ed1_a0b4_28db;
const K2: u64 = 0x8ebc_6af0_9c88_c6e3;

#[inline(always)]
pub fn wymix(a: u64, b: u64) -> u64 {
    let t = (a as u128).wrapping_mul(b as u128);
    (t as u64) ^ ((t >> 64) as u64)
}

#[inline(always)]
pub fn hash_u64(x: u64) -> u64 {
    wymix(x ^ K0, K1)
}

#[inline(always)]
pub fn hash_endpoint(ep: EndpointV4) -> u64 {
    let packed = ((ep.ip as u64) << 16) | (ep.port as u64);
    wymix(packed ^ K0, K1)
}

#[inline(always)]
pub fn hash_5tuple(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) -> u64 {
    let a = ((src_ip as u64) << 32) | (dst_ip as u64);
    let b = ((src_port as u64) << 24) | ((dst_port as u64) << 8) | (proto as u64);
    wymix(a ^ K0, b ^ K1) ^ K2
}

#[inline(always)]
pub fn hash_bytes(bytes: &[u8], seed: u64) -> u64 {
    let mut h = seed ^ K0;
    let mut i = 0;
    while i + 8 <= bytes.len() {
        let chunk = u64::from_le_bytes([
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
            bytes[i + 4],
            bytes[i + 5],
            bytes[i + 6],
            bytes[i + 7],
        ]);
        h = wymix(h ^ chunk, K1);
        i += 8;
    }
    if i < bytes.len() {
        let mut tail = 0u64;
        for (shift, &b) in bytes[i..].iter().enumerate() {
            tail |= (b as u64) << (shift * 8);
        }
        h = wymix(h ^ tail, K2);
    }
    wymix(h ^ (bytes.len() as u64), K0)
}

/// Fast division-free exact `x % 65537` using Fermat prime 2^16 ≡ -1 (mod 65537).
#[inline(always)]
pub fn fast_mod_65537(x: u64) -> usize {
    // x = c0 + c1*2^16 + c2*2^32 + c3*2^48
    // ≡ (c0 - c1 + c2 - c3) mod 65537
    let c0 = (x & 0xffff) as i64;
    let c1 = ((x >> 16) & 0xffff) as i64;
    let c2 = ((x >> 32) & 0xffff) as i64;
    let c3 = (x >> 48) as i64;
    let mut r = (c0 + c2) - (c1 + c3);
    // Range of r is [-131070, 131070]
    if r < 0 {
        r += 65537;
        if r < 0 {
            r += 65537;
        }
    } else if r >= 65537 {
        r -= 65537;
        if r >= 65537 {
            r -= 65537;
        }
    }
    r as usize
}

/// Ultra-fast thread-local PRNG for Power-of-Two-Choices (P2C) backend selection.
#[derive(Clone, Copy, Debug)]
pub struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    #[inline(always)]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
        }
    }

    #[inline(always)]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    #[inline(always)]
    pub fn next_bounded(&mut self, bound: usize) -> usize {
        // Lemire's fast range mapping (zero division!)
        (((self.next_u64() as u128) * (bound as u128)) >> 64) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_mod_65537_matches_exact() {
        let mut rng = Xorshift64::new(42);
        for v in [0u64, 1, 65536, 65537, 65538, u64::MAX, u64::MAX - 1] {
            assert_eq!(fast_mod_65537(v), (v % 65537) as usize);
        }
        for _ in 0..100_000 {
            let v = rng.next_u64();
            assert_eq!(fast_mod_65537(v), (v % 65537) as usize);
        }
    }
}
