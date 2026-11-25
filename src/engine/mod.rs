//! Pluggable high-performance L4 dataplane engines:
//! - `tcp`: Thread-per-core batched `kqueue`/`epoll` L4 TCP NLB with adaptive busy-poll,
//!          bufferless L1-hot fast path, lazy pooled ring buffers, and fair work budgeting
//! - `udp`: Syscall-batched L4 UDP NLB (`recvmsg_x`/`sendmsg_x` on macOS, `recvmmsg`/`sendmmsg` on Linux)

pub mod tcp;
pub mod udp;
