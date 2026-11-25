//! Linux low-level syscall bindings:
//! - `epoll` (EPOLLET) + `eventfd` wakeups
//! - `accept4(..., SOCK_NONBLOCK)` (1 syscall accept)
//! - `recvmmsg` / `sendmmsg` batched UDP I/O
//! - `splice` zero-copy kernel-to-kernel pipe forwarding
//! - `sched_setaffinity` 1:1 CPU core pinning
//! - Raw `io_uring` (`IORING_SETUP_SQPOLL`) & `AF_XDP` (`XDP_ZEROCOPY`) ABI constants/wrappers

use super::{EndpointV4, Fd, PollEvent, ProcessMetrics};
use std::ffi::c_void;
use std::io;
use std::mem::{size_of, zeroed};
use std::ptr;

pub const AF_INET: i32 = 2;
pub const AF_XDP: i32 = 44;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_RAW: i32 = 3;
pub const SOCK_NONBLOCK: i32 = 0o4000;
pub const SOCK_CLOEXEC: i32 = 0o2000000;

pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_IPV6: i32 = 41;
pub const SOL_SOCKET: i32 = 1;
pub const SOL_XDP: i32 = 283;
pub const SO_REUSEADDR: i32 = 2;
pub const SO_KEEPALIVE: i32 = 9;
pub const SO_REUSEPORT: i32 = 15;
pub const SO_SNDBUF: i32 = 7;
pub const SO_RCVBUF: i32 = 8;
pub const SO_ERROR: i32 = 4;

pub const TCP_NODELAY: i32 = 1;
pub const TCP_KEEPIDLE: i32 = 4;
pub const TCP_KEEPINTVL: i32 = 5;
pub const TCP_KEEPCNT: i32 = 6;
pub const TCP_USER_TIMEOUT: i32 = 18;
pub const TCP_FASTOPEN: i32 = 23;
pub const IPV6_V6ONLY: i32 = 26;
pub const MSG_DONTWAIT: i32 = 0x40;
pub const MSG_NOSIGNAL: i32 = 0x4000;

pub const EAGAIN: i32 = 11;
pub const EINPROGRESS: i32 = 115;
pub const EINTR: i32 = 4;
pub const SHUT_WR: i32 = 1;

// AF_XDP socket option constants (Linux uapi/linux/if_xdp.h)
pub const XDP_MMAP_OFFSETS: i32 = 1;
pub const XDP_RX_RING: i32 = 2;
pub const XDP_TX_RING: i32 = 3;
pub const XDP_UMEM_REG: i32 = 4;
pub const XDP_UMEM_FILL_RING: i32 = 5;
pub const XDP_UMEM_COMPLETION_RING: i32 = 6;
pub const XDP_ZEROCOPY: u16 = 1 << 2;
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

// io_uring constants (Linux uapi/linux/io_uring.h)
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
pub const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;
pub const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;

const EPOLL_CTL_ADD: i32 = 1;
const EPOLL_CTL_DEL: i32 = 2;
const EPOLL_CTL_MOD: i32 = 3;
const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLET: u32 = 1 << 31;

const SPLICE_F_MOVE: u32 = 0x01;
const SPLICE_F_NONBLOCK: u32 = 0x02;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

impl SockAddrIn {
    #[inline(always)]
    pub fn from_endpoint(ep: EndpointV4) -> Self {
        Self {
            sin_family: AF_INET as u16,
            sin_port: ep.port.to_be(),
            sin_addr: ep.ip.to_be(),
            sin_zero: [0; 8],
        }
    }

    #[inline(always)]
    pub fn to_endpoint(self) -> EndpointV4 {
        EndpointV4 {
            ip: u32::from_be(self.sin_addr),
            port: u16::from_be(self.sin_port),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoVec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MsgHdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: u32,
    pub msg_iov: *mut IoVec,
    pub msg_iovlen: usize,
    pub msg_control: *mut c_void,
    pub msg_controllen: usize,
    pub msg_flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MMsgHdr {
    pub msg_hdr: MsgHdr,
    pub msg_len: u32,
}

/// Compatible alias used by the cross-platform UDP batch engine.
pub type MsgHdrX = MMsgHdr;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TimeSpec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TimeVal {
    tv_sec: i64,
    tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RUsage {
    ru_utime: TimeVal,
    ru_stime: TimeVal,
    ru_maxrss: i64,
    ru_ixrss: i64,
    ru_idrss: i64,
    ru_isrss: i64,
    ru_minflt: i64,
    ru_majflt: i64,
    ru_nswap: i64,
    ru_inblock: i64,
    ru_oublock: i64,
    ru_msgsnd: i64,
    ru_msgrcv: i64,
    ru_nsignals: i64,
    ru_nvcsw: i64,
    ru_nivcsw: i64,
}

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn bind(fd: i32, addr: *const SockAddrIn, len: u32) -> i32;
    fn listen(fd: i32, backlog: i32) -> i32;
    fn accept4(fd: i32, addr: *mut SockAddrIn, len: *mut u32, flags: i32) -> i32;
    fn connect(fd: i32, addr: *const SockAddrIn, len: u32) -> i32;
    fn setsockopt(fd: i32, level: i32, optname: i32, optval: *const c_void, optlen: u32) -> i32;
    fn getsockopt(fd: i32, level: i32, optname: i32, optval: *mut c_void, optlen: *mut u32) -> i32;
    fn getsockname(fd: i32, addr: *mut SockAddrIn, len: *mut u32) -> i32;
    fn close(fd: i32) -> i32;
    fn shutdown(fd: i32, how: i32) -> i32;
    fn read(fd: i32, buf: *mut c_void, count: usize) -> isize;
    fn write(fd: i32, buf: *const c_void, count: usize) -> isize;
    fn readv(fd: i32, iov: *const IoVec, iovcnt: i32) -> isize;
    fn writev(fd: i32, iov: *const IoVec, iovcnt: i32) -> isize;
    fn recvfrom(
        fd: i32,
        buf: *mut c_void,
        len: usize,
        flags: i32,
        src: *mut SockAddrIn,
        addrlen: *mut u32,
    ) -> isize;
    fn sendto(
        fd: i32,
        buf: *const c_void,
        len: usize,
        flags: i32,
        dst: *const SockAddrIn,
        addrlen: u32,
    ) -> isize;
    fn recvmmsg(
        fd: i32,
        msgvec: *mut MMsgHdr,
        vlen: u32,
        flags: i32,
        timeout: *mut TimeSpec,
    ) -> i32;
    fn sendmmsg(fd: i32, msgvec: *mut MMsgHdr, vlen: u32, flags: i32) -> i32;
    fn splice(
        fd_in: i32,
        off_in: *mut i64,
        fd_out: i32,
        off_out: *mut i64,
        len: usize,
        flags: u32,
    ) -> isize;
    fn epoll_create1(flags: i32) -> i32;
    fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut EpollEvent) -> i32;
    fn epoll_wait(epfd: i32, events: *mut EpollEvent, maxevents: i32, timeout: i32) -> i32;
    fn eventfd(initval: u32, flags: i32) -> i32;
    fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const u64) -> i32;
    fn getrusage(who: i32, usage: *mut RUsage) -> i32;
    fn clock_gettime(clk_id: i32, tp: *mut TimeSpec) -> i32;
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
}

pub fn alloc_page_aligned(size: usize) -> io::Result<*mut u8> {
    let ptr = unsafe { mmap(ptr::null_mut(), size, 0x3, 0x22, -1, 0) };
    if ptr as isize == -1 || ptr.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(ptr as *mut u8)
    }
}

pub unsafe fn free_page_aligned(ptr: *mut u8, size: usize) {
    if !ptr.is_null() {
        munmap(ptr as *mut c_void, size);
    }
}

#[inline]
pub fn monotonic_clock_ns() -> u64 {
    let mut ts = TimeSpec::default();
    unsafe {
        clock_gettime(1, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

#[inline]
pub fn thread_cpu_time_ns() -> u64 {
    let mut ts = TimeSpec::default();
    unsafe {
        clock_gettime(3, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

pub fn raise_nofile_limit(target: u64) -> u64 {
    #[repr(C)]
    struct RLimit {
        rlim_cur: u64,
        rlim_max: u64,
    }
    extern "C" {
        fn getrlimit(resource: i32, rlp: *mut RLimit) -> i32;
        fn setrlimit(resource: i32, rlp: *const RLimit) -> i32;
    }
    let mut rl = RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        if getrlimit(7, &mut rl) == 0 {
            let desired = target.min(rl.rlim_max);
            if rl.rlim_cur < desired {
                rl.rlim_cur = desired;
                let _ = setrlimit(7, &rl);
                let _ = getrlimit(7, &mut rl);
            }
            return rl.rlim_cur;
        }
    }
    1024
}

pub fn pin_thread_performance(core_id: usize) {
    let mut mask = [0u64; 16];
    let word = (core_id / 64) % 16;
    mask[word] = 1u64 << (core_id % 64);
    unsafe {
        let _ = sched_setaffinity(0, size_of::<[u64; 16]>(), mask.as_ptr());
    }
}

pub fn sample_process_metrics() -> ProcessMetrics {
    let mut ru = RUsage::default();
    unsafe {
        getrusage(0, &mut ru);
    }
    let peak_rss_bytes = (ru.ru_maxrss.max(0) as u64) * 1024;
    let current_rss_bytes = std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4096)
        .unwrap_or(peak_rss_bytes);
    ProcessMetrics {
        user_time_us: (ru.ru_utime.tv_sec as u64) * 1_000_000 + (ru.ru_utime.tv_usec as u64),
        sys_time_us: (ru.ru_stime.tv_sec as u64) * 1_000_000 + (ru.ru_stime.tv_usec as u64),
        voluntary_ctx_switches: ru.ru_nvcsw.max(0) as u64,
        involuntary_ctx_switches: ru.ru_nivcsw.max(0) as u64,
        peak_rss_bytes,
        current_rss_bytes,
    }
}

#[inline]
fn set_sockopt_i32(fd: Fd, level: i32, opt: i32, val: i32) -> io::Result<()> {
    let rc = unsafe {
        setsockopt(
            fd,
            level,
            opt,
            &val as *const i32 as *const c_void,
            size_of::<i32>() as u32,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn get_socket_error(fd: Fd) -> io::Result<i32> {
    let mut err: i32 = 0;
    let mut len = size_of::<i32>() as u32;
    let rc = unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_ERROR,
            &mut err as *mut i32 as *mut c_void,
            &mut len,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(err)
    }
}

pub fn local_endpoint(fd: Fd) -> io::Result<EndpointV4> {
    let mut sa = SockAddrIn::default();
    let mut len = size_of::<SockAddrIn>() as u32;
    if unsafe { getsockname(fd, &mut sa, &mut len) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sa.to_endpoint())
    }
}

pub fn close_fd(fd: Fd) {
    if fd >= 0 {
        unsafe {
            close(fd);
        }
    }
}

pub fn shutdown_write(fd: Fd) {
    unsafe {
        shutdown(fd, SHUT_WR);
    }
}

/// Enable Linux TCP keepalive + `TCP_USER_TIMEOUT` for dead half-open peer reaping.
#[inline]
pub fn enable_tcp_keepalive(fd: Fd, idle_secs: i32, intvl_secs: i32, count: i32) {
    if idle_secs <= 0 {
        return;
    }
    let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_KEEPALIVE, 1);
    let _ = set_sockopt_i32(fd, IPPROTO_TCP, TCP_KEEPIDLE, idle_secs);
    let _ = set_sockopt_i32(fd, IPPROTO_TCP, TCP_KEEPINTVL, intvl_secs.max(1));
    let _ = set_sockopt_i32(fd, IPPROTO_TCP, TCP_KEEPCNT, count.max(1));
    let user_timeout_ms = (idle_secs + intvl_secs.max(1) * count.max(1)) * 1000;
    let _ = set_sockopt_i32(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, user_timeout_ms);
}

pub fn create_tcp_listener(
    ep: EndpointV4,
    backlog: i32,
    reuse_port: bool,
    buf_bytes: i32,
) -> io::Result<(Fd, EndpointV4)> {
    let fd = unsafe { socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let res = (|| -> io::Result<EndpointV4> {
        set_sockopt_i32(fd, SOL_SOCKET, SO_REUSEADDR, 1)?;
        if reuse_port {
            let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_REUSEPORT, 1);
        }
        let _ = set_sockopt_i32(fd, IPPROTO_TCP, TCP_NODELAY, 1);
        if buf_bytes > 0 {
            let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_RCVBUF, buf_bytes);
            let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_SNDBUF, buf_bytes);
        }
        let sa = SockAddrIn::from_endpoint(ep);
        if unsafe { bind(fd, &sa, size_of::<SockAddrIn>() as u32) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { listen(fd, backlog) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let _ = set_sockopt_i32(fd, IPPROTO_TCP, TCP_FASTOPEN, 128);
        local_endpoint(fd)
    })();
    match res {
        Ok(b) => Ok((fd, b)),
        Err(e) => {
            close_fd(fd);
            Err(e)
        }
    }
}

pub fn accept_nonblock(listen_fd: Fd, ensure_opts: bool) -> io::Result<Option<(Fd, EndpointV4)>> {
    let mut sa = SockAddrIn::default();
    let mut len = size_of::<SockAddrIn>() as u32;
    let fd = unsafe { accept4(listen_fd, &mut sa, &mut len, SOCK_NONBLOCK | SOCK_CLOEXEC) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0);
        if code == EAGAIN || code == EINTR {
            return Ok(None);
        }
        return Err(err);
    }
    if ensure_opts {
        let _ = set_sockopt_i32(fd, IPPROTO_TCP, TCP_NODELAY, 1);
    }
    Ok(Some((fd, sa.to_endpoint())))
}

pub fn connect_nonblock(ep: EndpointV4, buf_bytes: i32) -> io::Result<(Fd, bool)> {
    let fd = unsafe { socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let _ = set_sockopt_i32(fd, IPPROTO_TCP, TCP_NODELAY, 1);
    if buf_bytes > 0 {
        let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_RCVBUF, buf_bytes);
        let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_SNDBUF, buf_bytes);
    }
    let sa = SockAddrIn::from_endpoint(ep);
    let rc = unsafe { connect(fd, &sa, size_of::<SockAddrIn>() as u32) };
    if rc == 0 {
        Ok((fd, true))
    } else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(EINPROGRESS) {
            Ok((fd, false))
        } else {
            close_fd(fd);
            Err(err)
        }
    }
}

pub fn create_udp_socket(
    ep: EndpointV4,
    reuse_port: bool,
    buf_bytes: i32,
) -> io::Result<(Fd, EndpointV4)> {
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_REUSEADDR, 1);
    if reuse_port {
        let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_REUSEPORT, 1);
    }
    if buf_bytes > 0 {
        let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_RCVBUF, buf_bytes);
        let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_SNDBUF, buf_bytes);
    }
    let sa = SockAddrIn::from_endpoint(ep);
    if unsafe { bind(fd, &sa, size_of::<SockAddrIn>() as u32) } < 0 {
        close_fd(fd);
        return Err(io::Error::last_os_error());
    }
    Ok((fd, local_endpoint(fd)?))
}

pub fn connect_udp_socket(ep: EndpointV4, buf_bytes: i32) -> io::Result<Fd> {
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    if buf_bytes > 0 {
        let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_RCVBUF, buf_bytes);
        let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_SNDBUF, buf_bytes);
    }
    let sa = SockAddrIn::from_endpoint(ep);
    if unsafe { connect(fd, &sa, size_of::<SockAddrIn>() as u32) } < 0 {
        close_fd(fd);
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Zero-copy kernel-to-kernel TCP forwarding via `splice` + pipe on Linux.
#[inline]
pub fn splice_zero_copy(src_fd: Fd, pipe_wr: Fd, pipe_rd: Fd, dst_fd: Fd, max_len: usize) -> isize {
    let n = unsafe {
        splice(
            src_fd,
            ptr::null_mut(),
            pipe_wr,
            ptr::null_mut(),
            max_len,
            SPLICE_F_MOVE | SPLICE_F_NONBLOCK,
        )
    };
    if n <= 0 {
        return n;
    }
    unsafe {
        splice(
            pipe_rd,
            ptr::null_mut(),
            dst_fd,
            ptr::null_mut(),
            n as usize,
            SPLICE_F_MOVE | SPLICE_F_NONBLOCK,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoStatus {
    Ok(usize),
    WouldBlock,
    Eof,
    Error(i32),
}

pub fn read_nb(fd: Fd, buf: &mut [u8]) -> IoStatus {
    let n = unsafe { read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
    if n > 0 {
        IoStatus::Ok(n as usize)
    } else if n == 0 {
        IoStatus::Eof
    } else {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == EAGAIN || err == EINTR {
            IoStatus::WouldBlock
        } else {
            IoStatus::Error(err)
        }
    }
}

pub fn write_nb(fd: Fd, buf: &[u8]) -> IoStatus {
    let n = unsafe { write(fd, buf.as_ptr() as *const c_void, buf.len()) };
    if n >= 0 {
        IoStatus::Ok(n as usize)
    } else {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == EAGAIN || err == EINTR {
            IoStatus::WouldBlock
        } else {
            IoStatus::Error(err)
        }
    }
}

pub fn writev2_nb(fd: Fd, a: &[u8], b: &[u8]) -> IoStatus {
    if b.is_empty() {
        return write_nb(fd, a);
    }
    let iovs = [
        IoVec {
            iov_base: a.as_ptr() as *mut c_void,
            iov_len: a.len(),
        },
        IoVec {
            iov_base: b.as_ptr() as *mut c_void,
            iov_len: b.len(),
        },
    ];
    let n = unsafe { writev(fd, iovs.as_ptr(), 2) };
    if n >= 0 {
        IoStatus::Ok(n as usize)
    } else {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == EAGAIN || err == EINTR {
            IoStatus::WouldBlock
        } else {
            IoStatus::Error(err)
        }
    }
}

pub fn readv2_nb(fd: Fd, a: &mut [u8], b: &mut [u8]) -> IoStatus {
    if b.is_empty() {
        return read_nb(fd, a);
    }
    let iovs = [
        IoVec {
            iov_base: a.as_mut_ptr() as *mut c_void,
            iov_len: a.len(),
        },
        IoVec {
            iov_base: b.as_mut_ptr() as *mut c_void,
            iov_len: b.len(),
        },
    ];
    let n = unsafe { readv(fd, iovs.as_ptr(), 2) };
    if n > 0 {
        IoStatus::Ok(n as usize)
    } else if n == 0 {
        IoStatus::Eof
    } else {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == EAGAIN || err == EINTR {
            IoStatus::WouldBlock
        } else {
            IoStatus::Error(err)
        }
    }
}

pub fn recvfrom_nb(fd: Fd, buf: &mut [u8]) -> Result<Option<(usize, EndpointV4)>, i32> {
    let mut sa = SockAddrIn::default();
    let mut len = size_of::<SockAddrIn>() as u32;
    let n = unsafe {
        recvfrom(
            fd,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            MSG_DONTWAIT,
            &mut sa,
            &mut len,
        )
    };
    if n >= 0 {
        Ok(Some((n as usize, sa.to_endpoint())))
    } else {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == EAGAIN || err == EINTR {
            Ok(None)
        } else {
            Err(err)
        }
    }
}

pub fn sendto_nb(fd: Fd, buf: &[u8], dst: EndpointV4) -> Result<usize, i32> {
    let sa = SockAddrIn::from_endpoint(dst);
    let n = unsafe {
        sendto(
            fd,
            buf.as_ptr() as *const c_void,
            buf.len(),
            MSG_DONTWAIT | MSG_NOSIGNAL,
            &sa,
            size_of::<SockAddrIn>() as u32,
        )
    };
    if n >= 0 {
        Ok(n as usize)
    } else {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == EAGAIN || err == EINTR {
            Ok(0)
        } else {
            Err(err)
        }
    }
}

pub fn recv_udp_batch(fd: Fd, msgs: &mut [MMsgHdr]) -> Result<usize, i32> {
    let n = unsafe {
        recvmmsg(
            fd,
            msgs.as_mut_ptr(),
            msgs.len() as u32,
            MSG_DONTWAIT,
            ptr::null_mut(),
        )
    };
    if n >= 0 {
        Ok(n as usize)
    } else {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == EAGAIN || err == EINTR {
            Ok(0)
        } else {
            Err(err)
        }
    }
}

pub fn send_udp_batch(fd: Fd, msgs: &mut [MMsgHdr]) -> Result<usize, i32> {
    let n = unsafe { sendmmsg(fd, msgs.as_mut_ptr(), msgs.len() as u32, MSG_DONTWAIT) };
    if n >= 0 {
        Ok(n as usize)
    } else {
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err == EAGAIN || err == EINTR {
            Ok(0)
        } else {
            Err(err)
        }
    }
}

const WAKE_TOKEN: u64 = u64::MAX;

#[derive(Clone, Copy)]
pub struct WakeHandle {
    efd: Fd,
}

unsafe impl Send for WakeHandle {}
unsafe impl Sync for WakeHandle {}

impl WakeHandle {
    pub fn wake(&self) {
        let val: u64 = 1;
        unsafe {
            write(self.efd, &val as *const u64 as *const c_void, 8);
        }
    }
}

pub struct Poller {
    epfd: Fd,
    efd: Fd,
    raw_events: Vec<EpollEvent>,
}

impl Poller {
    pub fn new(max_events: usize) -> io::Result<Self> {
        let epfd = unsafe { epoll_create1(0o2000000) };
        if epfd < 0 {
            return Err(io::Error::last_os_error());
        }
        let efd = unsafe { eventfd(0, 0o4000 | 0o2000000) };
        if efd < 0 {
            close_fd(epfd);
            return Err(io::Error::last_os_error());
        }
        let mut ev = EpollEvent {
            events: EPOLLIN | EPOLLET,
            data: WAKE_TOKEN,
        };
        unsafe {
            epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &mut ev);
        }
        Ok(Self {
            epfd,
            efd,
            raw_events: vec![unsafe { zeroed() }; max_events.max(64)],
        })
    }

    pub fn wake_handle(&self) -> WakeHandle {
        WakeHandle { efd: self.efd }
    }

    pub fn add_read(&mut self, fd: Fd, token: u64, edge_triggered: bool) {
        let mut ev = EpollEvent {
            events: EPOLLIN | EPOLLRDHUP | if edge_triggered { EPOLLET } else { 0 },
            data: token,
        };
        unsafe {
            if epoll_ctl(self.epfd, EPOLL_CTL_ADD, fd, &mut ev) < 0 {
                epoll_ctl(self.epfd, EPOLL_CTL_MOD, fd, &mut ev);
            }
        }
    }

    pub fn arm_write_oneshot(&mut self, fd: Fd, token: u64) {
        let mut ev = EpollEvent {
            events: EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET,
            data: token,
        };
        unsafe {
            if epoll_ctl(self.epfd, EPOLL_CTL_MOD, fd, &mut ev) < 0 {
                epoll_ctl(self.epfd, EPOLL_CTL_ADD, fd, &mut ev);
            }
        }
    }

    pub fn add_connect_write(&mut self, fd: Fd, token: u64) {
        let mut ev = EpollEvent {
            events: EPOLLOUT | EPOLLONESHOT,
            data: token,
        };
        unsafe {
            epoll_ctl(self.epfd, EPOLL_CTL_ADD, fd, &mut ev);
        }
    }

    pub fn del_read(&mut self, fd: Fd) {
        unsafe {
            epoll_ctl(self.epfd, EPOLL_CTL_DEL, fd, ptr::null_mut());
        }
    }

    pub fn disable_read(&mut self, fd: Fd) {
        let mut ev = EpollEvent { events: 0, data: 0 };
        unsafe {
            epoll_ctl(self.epfd, EPOLL_CTL_MOD, fd, &mut ev);
        }
    }

    pub fn enable_read(&mut self, fd: Fd, token: u64) {
        self.add_read(fd, token, false);
    }

    pub fn poll(&mut self, out: &mut Vec<PollEvent>, timeout_ns: Option<u64>) -> io::Result<usize> {
        out.clear();
        let timeout_ms = match timeout_ns {
            None => -1,
            Some(0) => 0,
            Some(ns) => ((ns + 999_999) / 1_000_000).min(i32::MAX as u64) as i32,
        };
        let n = unsafe {
            epoll_wait(
                self.epfd,
                self.raw_events.as_mut_ptr(),
                self.raw_events.len() as i32,
                timeout_ms,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(EINTR) {
                return Ok(0);
            }
            return Err(err);
        }
        for i in 0..(n as usize) {
            let ev = self.raw_events[i];
            let token = ev.data;
            if token == WAKE_TOKEN {
                let mut drain = 0u64;
                unsafe {
                    read(self.efd, &mut drain as *mut u64 as *mut c_void, 8);
                }
                out.push(PollEvent {
                    token: 0,
                    readable: false,
                    writable: false,
                    eof: false,
                    error: false,
                    is_user: true,
                    data_hint: 0,
                });
                continue;
            }
            out.push(PollEvent {
                token,
                readable: (ev.events & EPOLLIN) != 0,
                writable: (ev.events & EPOLLOUT) != 0,
                eof: (ev.events & (EPOLLHUP | EPOLLRDHUP)) != 0,
                error: (ev.events & EPOLLERR) != 0,
                is_user: false,
                data_hint: 0,
            });
        }
        Ok(out.len())
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        close_fd(self.epfd);
        close_fd(self.efd);
    }
}
