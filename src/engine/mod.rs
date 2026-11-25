//! Pluggable high-performance L4 dataplane engines:
//! - `tcp`: Thread-per-core batched `kqueue`/`epoll` L4 TCP NLB with adaptive busy-poll,
//!          bufferless L1-hot fast path, lazy pooled ring buffers, and fair work budgeting
//! - `udp`: Syscall-batched L4 UDP NLB (`recvmsg_x`/`sendmsg_x` on macOS, `recvmmsg`/`sendmmsg` on Linux)
//! - `bypass`: True userspace zero-copy kernel-bypass UMEM packet engine (AF_XDP / DPDK model)
//!             with vectorized 64-pkt burst loop, prefetching, RFC 1624 O(1) incremental checksums,
//!             NAT & DSR modes, and ZERO syscalls / ZERO allocations on the hot path
//! - `linux_bypass`: Bare-metal Linux `AF_XDP` (`XDP_ZEROCOPY`) and `io_uring` (`IORING_SETUP_SQPOLL`)
//!                   ABI definitions and syscall setup layer

pub mod bypass;
pub mod linux_bypass;
pub mod tcp;
pub mod udp;
