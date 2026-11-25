//! Bare-metal Linux kernel-bypass ABI definitions & setup wrappers:
//! - `AF_XDP` (`XDP_ZEROCOPY`, `XDP_UMEM_REG`, RX/TX/Fill/Completion mmap rings)
//! - `io_uring` (`IORING_SETUP_SQPOLL`, `IORING_SETUP_SINGLE_ISSUER` zero-syscall submission)
//!
//! ABI structs compile on all targets for layout verification; actual syscalls activate
//! under `#[cfg(target_os = "linux")]`.

/// Exact Linux `struct xdp_umem_reg` (uapi/linux/if_xdp.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct XdpUmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
    pub tx_metadata_len: u32,
}

/// Exact Linux `struct sockaddr_xdp` (uapi/linux/if_xdp.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SockAddrXdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

/// Exact Linux `struct xdp_ring_offset` (uapi/linux/if_xdp.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct XdpRingOffset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

/// Exact Linux `struct xdp_mmap_offsets` (uapi/linux/if_xdp.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct XdpMmapOffsets {
    pub rx: XdpRingOffset,
    pub tx: XdpRingOffset,
    pub fr: XdpRingOffset,
    pub cr: XdpRingOffset,
}

/// Exact Linux `struct io_uring_sqe` (64 bytes, uapi/linux/io_uring.h).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off_or_addr2: u64,
    pub addr_or_splice_off_in: u64,
    pub len: u32,
    pub op_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub addr3: u64,
    pub _pad: u64,
}

/// Exact Linux `struct io_uring_cqe` (16 bytes, uapi/linux/io_uring.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

/// Exact Linux `struct io_uring_params` (120 bytes, uapi/linux/io_uring.h).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: [u32; 10],
    pub cq_off: [u32; 10],
}

#[cfg(target_os = "linux")]
pub mod linux_syscalls {
    use super::*;
    use crate::engine::bypass::{UmemArena, FRAME_HEADROOM, FRAME_SIZE};
    use crate::sys::linux::{
        AF_XDP, IORING_SETUP_COOP_TASKRUN, IORING_SETUP_SINGLE_ISSUER, IORING_SETUP_SQPOLL,
        SOCK_RAW, SOL_XDP, XDP_RX_RING, XDP_TX_RING, XDP_UMEM_COMPLETION_RING,
        XDP_UMEM_FILL_RING, XDP_UMEM_REG, XDP_USE_NEED_WAKEUP, XDP_ZEROCOPY,
    };
    use std::ffi::c_void;
    use std::io;
    use std::mem::{size_of, zeroed};

    const SYS_IO_URING_SETUP: i64 = 425;
    const SYS_IO_URING_ENTER: i64 = 426;

    extern "C" {
        fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
        fn bind(fd: i32, addr: *const c_void, len: u32) -> i32;
        fn setsockopt(fd: i32, level: i32, opt: i32, val: *const c_void, len: u32) -> i32;
        fn syscall(num: i64, ...) -> i64;
    }

    /// Create and bind an `AF_XDP` zero-copy NIC queue socket over `UmemArena`.
    pub fn open_af_xdp_socket(
        ifindex: u32,
        queue_id: u32,
        ring_entries: u32,
        umem: &UmemArena,
    ) -> io::Result<i32> {
        let fd = unsafe { socket(AF_XDP, SOCK_RAW, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let reg = XdpUmemReg {
            addr: umem.base_ptr() as u64,
            len: umem.total_bytes() as u64,
            chunk_size: FRAME_SIZE as u32,
            headroom: FRAME_HEADROOM as u32,
            flags: 0,
            tx_metadata_len: 0,
        };
        unsafe {
            if setsockopt(
                fd,
                SOL_XDP,
                XDP_UMEM_REG,
                &reg as *const _ as *const c_void,
                size_of::<XdpUmemReg>() as u32,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            for opt in [
                XDP_UMEM_FILL_RING,
                XDP_UMEM_COMPLETION_RING,
                XDP_RX_RING,
                XDP_TX_RING,
            ] {
                if setsockopt(
                    fd,
                    SOL_XDP,
                    opt,
                    &ring_entries as *const u32 as *const c_void,
                    size_of::<u32>() as u32,
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            let sa = SockAddrXdp {
                sxdp_family: AF_XDP as u16,
                sxdp_flags: XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
                sxdp_ifindex: ifindex,
                sxdp_queue_id: queue_id,
                sxdp_shared_umem_fd: 0,
            };
            if bind(fd, &sa as *const _ as *const c_void, size_of::<SockAddrXdp>() as u32) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(fd)
    }

    /// Initialize an `io_uring` instance with `IORING_SETUP_SQPOLL` (kernel-side submission
    /// poller thread enabling zero-syscall async I/O submissions!).
    pub fn setup_io_uring_sqpoll(entries: u32, sq_idle_ms: u32) -> io::Result<(i32, IoUringParams)> {
        let mut params: IoUringParams = unsafe { zeroed() };
        params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_COOP_TASKRUN;
        params.sq_thread_idle = sq_idle_ms;
        let fd = unsafe { syscall(SYS_IO_URING_SETUP, entries as i64, &mut params as *mut _) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok((fd as i32, params))
        }
    }

    pub fn io_uring_enter(fd: i32, to_submit: u32, min_complete: u32, flags: u32) -> io::Result<i32> {
        let rc = unsafe {
            syscall(
                SYS_IO_URING_ENTER,
                fd as i64,
                to_submit as i64,
                min_complete as i64,
                flags as i64,
                0i64,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc as i32)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn verify_linux_bypass_abi_sizes() {
        assert_eq!(size_of::<XdpUmemReg>(), 32);
        assert_eq!(size_of::<SockAddrXdp>(), 16);
        assert_eq!(size_of::<XdpMmapOffsets>(), 128);
        assert_eq!(size_of::<IoUringSqe>(), 64);
        assert_eq!(size_of::<IoUringCqe>(), 16);
        assert_eq!(size_of::<IoUringParams>(), 120);
    }
}
