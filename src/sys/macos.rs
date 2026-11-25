//! macOS / Darwin (XNU) low-level syscall bindings:
//! - `kqueue` + batched `kevent` (single-syscall changelist submission + event retrieval)
//! - `EVFILT_USER` coalesced cross-thread wakeups
//! - `recvmsg_x` / `sendmsg_x` multi-packet batched UDP syscalls (up to 64 pkts/mode-switch)
//! - `readv` / `writev` vectored scatter-gather I/O
//! - `SO_NOSIGPIPE`, `TCP_NODELAY`, `TCP_FASTOPEN`, `SO_REUSEPORT`
//! - `pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE)` for Apple Silicon P-core scheduling
//! - `getrusage` + `mach_task_basic_info` for exact CPU, context-switch, and RSS telemetry

use super::{EndpointV4, Fd, PollEvent, ProcessMetrics};
use std::ffi::c_void;
use std::io;
use std::mem::{size_of, zeroed};
use std::ptr;

pub const AF_INET: i32 = 2;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;

pub const SOL_SOCKET: i32 = 0xffff;
pub const SO_REUSEADDR: i32 = 0x0004;
pub const SO_REUSEPORT: i32 = 0x0200;
pub const SO_SNDBUF: i32 = 0x1001;
pub const SO_RCVBUF: i32 = 0x1002;
pub const SO_ERROR: i32 = 0x1007;
pub const SO_NOSIGPIPE: i32 = 0x1022;

pub const TCP_NODELAY: i32 = 0x01;
pub const TCP_NOPUSH: i32 = 0x04;
pub const TCP_FASTOPEN: i32 = 0x105;

pub const F_GETFL: i32 = 3;
pub const F_SETFL: i32 = 4;
pub const O_NONBLOCK: i32 = 0x0004;

pub const MSG_DONTWAIT: i32 = 0x80;

pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

pub const EAGAIN: i32 = 35;
pub const EINPROGRESS: i32 = 36;
pub const EINTR: i32 = 4;
pub const EPIPE: i32 = 32;
pub const ECONNRESET: i32 = 54;

// kqueue constants (verified against MacOSX.sdk/usr/include/sys/event.h)
const EVFILT_READ: i16 = -1;
const EVFILT_WRITE: i16 = -2;
const EVFILT_USER: i16 = -10;

const EV_ADD: u16 = 0x0001;
const EV_DELETE: u16 = 0x0002;
const EV_ENABLE: u16 = 0x0004;
const EV_DISABLE: u16 = 0x0008;
const EV_ONESHOT: u16 = 0x0010;
const EV_CLEAR: u16 = 0x0020;
const EV_ERROR: u16 = 0x4000;
const EV_EOF: u16 = 0x8000;

const NOTE_TRIGGER: u32 = 0x0100_0000;

const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;
const RUSAGE_SELF: i32 = 0;
const MACH_TASK_BASIC_INFO: u32 = 20;
const MACH_TASK_BASIC_INFO_COUNT: u32 = 12;
const CLOCK_UPTIME_RAW: i32 = 8;

const USER_WAKE_IDENT: usize = 0x5445_5452_5558_0001; // "TETRUX\0\1"

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    pub sin_len: u8,
    pub sin_family: u8,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

impl Default for SockAddrIn {
    #[inline(always)]
    fn default() -> Self {
        Self {
            sin_len: size_of::<Self>() as u8,
            sin_family: AF_INET as u8,
            sin_port: 0,
            sin_addr: 0,
            sin_zero: [0; 8],
        }
    }
}

impl SockAddrIn {
    #[inline(always)]
    pub fn from_endpoint(ep: EndpointV4) -> Self {
        Self {
            sin_len: size_of::<Self>() as u8,
            sin_family: AF_INET as u8,
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

/// XNU `struct msghdr_x` (56 bytes on 64-bit Darwin) for batched `recvmsg_x` / `sendmsg_x`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MsgHdrX {
    pub msg_name: *mut c_void,
    pub msg_namelen: u32,
    pub msg_iov: *mut IoVec,
    pub msg_iovlen: i32,
    pub msg_control: *mut c_void,
    pub msg_controllen: u32,
    pub msg_flags: i32,
    pub msg_datalen: usize,
}

impl Default for MsgHdrX {
    #[inline(always)]
    fn default() -> Self {
        Self {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            msg_datalen: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Kevent {
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: *mut c_void,
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
    tv_usec: i32,
    _pad: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RUsage {
    ru_utime: TimeVal,
    ru_stime: TimeVal,
    ru_maxrss: isize,
    ru_ixrss: isize,
    ru_idrss: isize,
    ru_isrss: isize,
    ru_minflt: isize,
    ru_majflt: isize,
    ru_nswap: isize,
    ru_inblock: isize,
    ru_oublock: isize,
    ru_msgsnd: isize,
    ru_msgrcv: isize,
    ru_nsignals: isize,
    ru_nvcsw: isize,
    ru_nivcsw: isize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TimeValueT {
    seconds: i32,
    microseconds: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MachTaskBasicInfo {
    virtual_size: u64,
    resident_size: u64,
    resident_size_max: u64,
    user_time: TimeValueT,
    system_time: TimeValueT,
    policy: i32,
    suspend_count: i32,
}

extern "C" {
    static mach_task_self_: u32;

    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn bind(fd: i32, addr: *const SockAddrIn, len: u32) -> i32;
    fn listen(fd: i32, backlog: i32) -> i32;
    fn accept(fd: i32, addr: *mut SockAddrIn, len: *mut u32) -> i32;
    fn connect(fd: i32, addr: *const SockAddrIn, len: u32) -> i32;
    fn setsockopt(fd: i32, level: i32, optname: i32, optval: *const c_void, optlen: u32) -> i32;
    fn getsockopt(fd: i32, level: i32, optname: i32, optval: *mut c_void, optlen: *mut u32) -> i32;
    fn getsockname(fd: i32, addr: *mut SockAddrIn, len: *mut u32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
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
        src_addr: *mut SockAddrIn,
        addrlen: *mut u32,
    ) -> isize;
    fn sendto(
        fd: i32,
        buf: *const c_void,
        len: usize,
        flags: i32,
        dest_addr: *const SockAddrIn,
        addrlen: u32,
    ) -> isize;

    fn recvmsg_x(fd: i32, msgp: *mut MsgHdrX, cnt: u32, flags: i32) -> isize;
    fn sendmsg_x(fd: i32, msgp: *const MsgHdrX, cnt: u32, flags: i32) -> isize;

    fn kqueue() -> i32;
    fn kevent(
        kq: i32,
        changelist: *const Kevent,
        nchanges: i32,
        eventlist: *mut Kevent,
        nevents: i32,
        timeout: *const TimeSpec,
    ) -> i32;

    fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    fn getrusage(who: i32, usage: *mut RUsage) -> i32;
    fn task_info(
        target_task: u32,
        flavor: u32,
        task_info_out: *mut c_void,
        task_info_cnt: *mut u32,
    ) -> i32;
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

const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const MAP_PRIVATE: i32 = 0x0002;
const MAP_ANON: i32 = 0x1000;
const MAP_FAILED: *mut c_void = !0usize as *mut c_void;

/// Allocate page-aligned anonymous virtual memory (suitable for UMEM / slab arenas).
pub fn alloc_page_aligned(size: usize) -> io::Result<*mut u8> {
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == MAP_FAILED || ptr.is_null() {
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
        clock_gettime(CLOCK_UPTIME_RAW, &mut ts);
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// Request Apple Silicon Performance-core (P-core) scheduling via QoS USER_INTERACTIVE.
pub fn pin_thread_performance(_core_id: usize) {
    unsafe {
        let _ = pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    }
}

pub fn sample_process_metrics() -> ProcessMetrics {
    let mut ru = RUsage::default();
    unsafe {
        getrusage(RUSAGE_SELF, &mut ru);
    }
    let user_time_us = (ru.ru_utime.tv_sec as u64) * 1_000_000 + (ru.ru_utime.tv_usec as u64);
    let sys_time_us = (ru.ru_stime.tv_sec as u64) * 1_000_000 + (ru.ru_stime.tv_usec as u64);
    // On macOS, ru_maxrss is already in bytes!
    let peak_rss_bytes = ru.ru_maxrss.max(0) as u64;

    let mut info = MachTaskBasicInfo::default();
    let mut count = MACH_TASK_BASIC_INFO_COUNT;
    let current_rss_bytes = unsafe {
        let kr = task_info(
            mach_task_self_,
            MACH_TASK_BASIC_INFO,
            &mut info as *mut _ as *mut c_void,
            &mut count,
        );
        if kr == 0 {
            info.resident_size
        } else {
            peak_rss_bytes
        }
    };

    ProcessMetrics {
        user_time_us,
        sys_time_us,
        voluntary_ctx_switches: ru.ru_nvcsw.max(0) as u64,
        involuntary_ctx_switches: ru.ru_nivcsw.max(0) as u64,
        peak_rss_bytes,
        current_rss_bytes,
    }
}

#[inline]
pub fn set_nonblocking(fd: Fd) -> io::Result<()> {
    unsafe {
        let flags = fcntl(fd, F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if (flags & O_NONBLOCK) == 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
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

#[inline]
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

#[inline]
pub fn local_endpoint(fd: Fd) -> io::Result<EndpointV4> {
    let mut sa = SockAddrIn::default();
    let mut len = size_of::<SockAddrIn>() as u32;
    let rc = unsafe { getsockname(fd, &mut sa, &mut len) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sa.to_endpoint())
    }
}

#[inline]
pub fn close_fd(fd: Fd) {
    if fd >= 0 {
        unsafe {
            close(fd);
        }
    }
}

#[inline]
pub fn shutdown_write(fd: Fd) {
    unsafe {
        shutdown(fd, SHUT_WR);
    }
}

/// Create a tuned non-blocking TCP listening socket.
/// On macOS, accepted sockets inherit `O_NONBLOCK`, `TCP_NODELAY`, `SO_NOSIGPIPE`,
/// and buffer sizes from the listener, eliminating 4 syscalls per accepted connection!
pub fn create_tcp_listener(
    ep: EndpointV4,
    backlog: i32,
    reuse_port: bool,
    buf_bytes: i32,
) -> io::Result<(Fd, EndpointV4)> {
    let fd = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let res = (|| -> io::Result<EndpointV4> {
        set_nonblocking(fd)?;
        set_sockopt_i32(fd, SOL_SOCKET, SO_REUSEADDR, 1)?;
        if reuse_port {
            let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_REUSEPORT, 1);
        }
        let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_NOSIGPIPE, 1);
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
        // Enable TCP Fast Open passively if supported by XNU
        let _ = set_sockopt_i32(fd, IPPROTO_TCP, TCP_FASTOPEN, 1);
        local_endpoint(fd)
    })();

    match res {
        Ok(bound) => Ok((fd, bound)),
        Err(e) => {
            close_fd(fd);
            Err(e)
        }
    }
}

/// Non-blocking accept. Returns `Ok(None)` on `EAGAIN`.
/// Because macOS inherits `O_NONBLOCK`, `TCP_NODELAY`, and `SO_NOSIGPIPE` from the listener,
/// `ensure_opts = false` skips redundant per-connection syscalls on the hot accept path.
#[inline]
pub fn accept_nonblock(listen_fd: Fd, ensure_opts: bool) -> io::Result<Option<(Fd, EndpointV4)>> {
    let mut sa = SockAddrIn::default();
    let mut len = size_of::<SockAddrIn>() as u32;
    let fd = unsafe { accept(listen_fd, &mut sa, &mut len) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0);
        if code == EAGAIN || code == EINTR {
            return Ok(None);
        }
        return Err(err);
    }
    if ensure_opts {
        let _ = set_nonblocking(fd);
        let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_NOSIGPIPE, 1);
        let _ = set_sockopt_i32(fd, IPPROTO_TCP, TCP_NODELAY, 1);
    }
    Ok(Some((fd, sa.to_endpoint())))
}

/// Non-blocking outbound TCP connect.
/// Returns `(fd, connected_immediately)`.
#[inline]
pub fn connect_nonblock(ep: EndpointV4, buf_bytes: i32) -> io::Result<(Fd, bool)> {
    let fd = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let setup = (|| -> io::Result<bool> {
        set_nonblocking(fd)?;
        let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_NOSIGPIPE, 1);
        let _ = set_sockopt_i32(fd, IPPROTO_TCP, TCP_NODELAY, 1);
        if buf_bytes > 0 {
            let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_RCVBUF, buf_bytes);
            let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_SNDBUF, buf_bytes);
        }
        let sa = SockAddrIn::from_endpoint(ep);
        let rc = unsafe { connect(fd, &sa, size_of::<SockAddrIn>() as u32) };
        if rc == 0 {
            Ok(true)
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(EINPROGRESS) {
                Ok(false)
            } else {
                Err(err)
            }
        }
    })();

    match setup {
        Ok(immediate) => Ok((fd, immediate)),
        Err(e) => {
            close_fd(fd);
            Err(e)
        }
    }
}

/// Create a tuned non-blocking UDP socket.
pub fn create_udp_socket(
    ep: EndpointV4,
    reuse_port: bool,
    buf_bytes: i32,
) -> io::Result<(Fd, EndpointV4)> {
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let res = (|| -> io::Result<EndpointV4> {
        set_nonblocking(fd)?;
        set_sockopt_i32(fd, SOL_SOCKET, SO_REUSEADDR, 1)?;
        if reuse_port {
            let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_REUSEPORT, 1);
        }
        let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_NOSIGPIPE, 1);
        if buf_bytes > 0 {
            let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_RCVBUF, buf_bytes);
            let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_SNDBUF, buf_bytes);
        }
        let sa = SockAddrIn::from_endpoint(ep);
        if unsafe { bind(fd, &sa, size_of::<SockAddrIn>() as u32) } < 0 {
            return Err(io::Error::last_os_error());
        }
        local_endpoint(fd)
    })();
    match res {
        Ok(bound) => Ok((fd, bound)),
        Err(e) => {
            close_fd(fd);
            Err(e)
        }
    }
}

/// Connect a UDP socket to a single backend endpoint (skips route lookup per send!).
pub fn connect_udp_socket(ep: EndpointV4, buf_bytes: i32) -> io::Result<Fd> {
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let res = (|| -> io::Result<()> {
        set_nonblocking(fd)?;
        let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_NOSIGPIPE, 1);
        if buf_bytes > 0 {
            let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_RCVBUF, buf_bytes);
            let _ = set_sockopt_i32(fd, SOL_SOCKET, SO_SNDBUF, buf_bytes);
        }
        let sa = SockAddrIn::from_endpoint(ep);
        if unsafe { connect(fd, &sa, size_of::<SockAddrIn>() as u32) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    match res {
        Ok(()) => Ok(fd),
        Err(e) => {
            close_fd(fd);
            Err(e)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoStatus {
    Ok(usize),
    WouldBlock,
    Eof,
    Error(i32),
}

#[inline(always)]
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

#[inline(always)]
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

/// Zero-copy vectored write for wrap-around ring buffers (up to 2 slices in 1 syscall).
#[inline(always)]
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

/// Zero-copy vectored read for wrap-around ring buffers.
#[inline(always)]
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

#[inline(always)]
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

#[inline(always)]
pub fn sendto_nb(fd: Fd, buf: &[u8], dst: EndpointV4) -> Result<usize, i32> {
    let sa = SockAddrIn::from_endpoint(dst);
    let n = unsafe {
        sendto(
            fd,
            buf.as_ptr() as *const c_void,
            buf.len(),
            MSG_DONTWAIT,
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

/// Receive up to `msgs.len()` UDP datagrams in a SINGLE Darwin `recvmsg_x` syscall.
#[inline(always)]
pub fn recv_udp_batch(fd: Fd, msgs: &mut [MsgHdrX]) -> Result<usize, i32> {
    let n = unsafe { recvmsg_x(fd, msgs.as_mut_ptr(), msgs.len() as u32, MSG_DONTWAIT) };
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

/// Send up to `msgs.len()` UDP datagrams in a SINGLE Darwin `sendmsg_x` syscall.
#[inline(always)]
pub fn send_udp_batch(fd: Fd, msgs: &[MsgHdrX]) -> Result<usize, i32> {
    let n = unsafe { sendmsg_x(fd, msgs.as_ptr(), msgs.len() as u32, MSG_DONTWAIT) };
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

/// Batched `kqueue` event poller that folds all pending FD interest updates into the
/// same `kevent()` syscall used to harvest ready events — drastically minimizing mode switches.
pub struct Poller {
    kq: Fd,
    changelist: Vec<Kevent>,
    raw_events: Vec<Kevent>,
}

// SAFETY: `Kevent::udata` only stores integer tokens (never dereferenced pointers),
// and `kq` is an OS file descriptor safe to transfer across threads.
unsafe impl Send for Poller {}

/// Thread-safe handle to trigger a coalesced `EVFILT_USER` wakeup on a sleeping `Poller`.
#[derive(Clone, Copy)]
pub struct WakeHandle {
    kq: Fd,
}

unsafe impl Send for WakeHandle {}
unsafe impl Sync for WakeHandle {}

impl WakeHandle {
    #[inline]
    pub fn wake(&self) {
        let ev = Kevent {
            ident: USER_WAKE_IDENT,
            filter: EVFILT_USER,
            flags: 0,
            fflags: NOTE_TRIGGER,
            data: 0,
            udata: ptr::null_mut(),
        };
        let ts = TimeSpec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            kevent(self.kq, &ev, 1, ptr::null_mut(), 0, &ts);
        }
    }
}

impl Poller {
    pub fn new(max_events: usize) -> io::Result<Self> {
        let kq = unsafe { kqueue() };
        if kq < 0 {
            return Err(io::Error::last_os_error());
        }
        // Register persistent EVFILT_USER wakeup event (EV_CLEAR resets automatically on delivery)
        let wake_reg = Kevent {
            ident: USER_WAKE_IDENT,
            filter: EVFILT_USER,
            flags: EV_ADD | EV_CLEAR,
            fflags: 0,
            data: 0,
            udata: ptr::null_mut(),
        };
        let rc = unsafe { kevent(kq, &wake_reg, 1, ptr::null_mut(), 0, ptr::null()) };
        if rc < 0 {
            close_fd(kq);
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            kq,
            changelist: Vec::with_capacity(512),
            raw_events: vec![unsafe { zeroed() }; max_events.max(64)],
        })
    }

    #[inline]
    pub fn wake_handle(&self) -> WakeHandle {
        WakeHandle { kq: self.kq }
    }

    #[inline(always)]
    fn push_change(&mut self, ev: Kevent) {
        if self.changelist.len() == self.changelist.capacity() {
            // Flush pending changes in a single batch if changelist is full
            let _ = self.flush_changes();
        }
        self.changelist.push(ev);
    }

    /// Register persistent read interest (deferred into next `poll()` syscall — 0 syscalls now!).
    #[inline(always)]
    pub fn add_read(&mut self, fd: Fd, token: u64, edge_triggered: bool) {
        let flags = if edge_triggered {
            EV_ADD | EV_ENABLE | EV_CLEAR
        } else {
            EV_ADD | EV_ENABLE
        };
        self.push_change(Kevent {
            ident: fd as usize,
            filter: EVFILT_READ,
            flags,
            fflags: 0,
            data: 0,
            udata: token as usize as *mut c_void,
        });
    }

    /// Arm one-shot write readiness (used only on `EAGAIN` backpressure or async `connect`).
    #[inline(always)]
    pub fn arm_write_oneshot(&mut self, fd: Fd, token: u64) {
        self.push_change(Kevent {
            ident: fd as usize,
            filter: EVFILT_WRITE,
            flags: EV_ADD | EV_ENABLE | EV_ONESHOT,
            fflags: 0,
            data: 0,
            udata: token as usize as *mut c_void,
        });
    }

    /// Register both read and one-shot write (e.g. non-blocking backend connect).
    #[inline(always)]
    pub fn add_connect_write(&mut self, fd: Fd, token: u64) {
        self.arm_write_oneshot(fd, token);
    }

    /// Explicitly remove read filter before close if desired (note: `close(fd)` auto-removes in kqueue,
    /// saving syscalls when closing!).
    #[inline(always)]
    pub fn del_read(&mut self, fd: Fd) {
        self.push_change(Kevent {
            ident: fd as usize,
            filter: EVFILT_READ,
            flags: EV_DELETE,
            fflags: 0,
            data: 0,
            udata: ptr::null_mut(),
        });
    }

    /// Temporarily pause read notifications during backpressure (batched in changelist, 0 syscalls!).
    #[inline(always)]
    pub fn disable_read(&mut self, fd: Fd) {
        self.push_change(Kevent {
            ident: fd as usize,
            filter: EVFILT_READ,
            flags: EV_DISABLE,
            fflags: 0,
            data: 0,
            udata: ptr::null_mut(),
        });
    }

    /// Re-enable read notifications once backpressure clears (batched in changelist, 0 syscalls!).
    #[inline(always)]
    pub fn enable_read(&mut self, fd: Fd, token: u64) {
        self.push_change(Kevent {
            ident: fd as usize,
            filter: EVFILT_READ,
            flags: EV_ENABLE,
            fflags: 0,
            data: 0,
            udata: token as usize as *mut c_void,
        });
    }

    /// Flush changelist without waiting.
    #[inline]
    pub fn flush_changes(&mut self) -> io::Result<()> {
        if self.changelist.is_empty() {
            return Ok(());
        }
        let ts = TimeSpec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let rc = unsafe {
            kevent(
                self.kq,
                self.changelist.as_ptr(),
                self.changelist.len() as i32,
                ptr::null_mut(),
                0,
                &ts,
            )
        };
        self.changelist.clear();
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Single-syscall batched change submission + event retrieval.
    /// `timeout_ns = Some(0)` performs a non-blocking poll (used during adaptive busy-poll!).
    /// `timeout_ns = None` waits indefinitely until an event or `WakeHandle::wake()`.
    #[inline]
    pub fn poll(&mut self, out: &mut Vec<PollEvent>, timeout_ns: Option<u64>) -> io::Result<usize> {
        out.clear();
        let ts = timeout_ns.map(|ns| TimeSpec {
            tv_sec: (ns / 1_000_000_000) as i64,
            tv_nsec: (ns % 1_000_000_000) as i64,
        });
        let ts_ptr = match ts {
            Some(ref t) => t as *const TimeSpec,
            None => ptr::null(),
        };
        let nchanges = self.changelist.len() as i32;
        let change_ptr = if nchanges > 0 {
            self.changelist.as_ptr()
        } else {
            ptr::null()
        };

        let n = unsafe {
            kevent(
                self.kq,
                change_ptr,
                nchanges,
                self.raw_events.as_mut_ptr(),
                self.raw_events.len() as i32,
                ts_ptr,
            )
        };
        self.changelist.clear();

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(EINTR) {
                return Ok(0);
            }
            return Err(err);
        }

        let count = n as usize;
        for i in 0..count {
            let ev = self.raw_events[i];
            // Ignore benign EV_ERROR receipts from batched EV_DELETE/closed fds
            if (ev.flags & EV_ERROR) != 0 && ev.filter != EVFILT_READ && ev.filter != EVFILT_WRITE {
                continue;
            }
            if ev.filter == EVFILT_USER {
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
                token: ev.udata as usize as u64,
                readable: ev.filter == EVFILT_READ,
                writable: ev.filter == EVFILT_WRITE,
                eof: (ev.flags & EV_EOF) != 0,
                error: (ev.flags & EV_ERROR) != 0,
                is_user: false,
                data_hint: ev.data as i64,
            });
        }
        Ok(out.len())
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        close_fd(self.kq);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_darwin_abi_sizes() {
        assert_eq!(size_of::<Kevent>(), 32);
        assert_eq!(size_of::<SockAddrIn>(), 16);
        assert_eq!(size_of::<IoVec>(), 16);
        assert_eq!(size_of::<MsgHdrX>(), 56);
        assert_eq!(size_of::<RUsage>(), 144);
        assert_eq!(size_of::<MachTaskBasicInfo>(), 48);
    }
}
