use std::libc::{c_int, perror};
use std::option;
use std::result;
use std::cast;
use std::ptr;
use std::str;
use std::vec;
use std::sys;


#[nolink]
mod c {
    use std::libc::{c_int, c_uint, c_char, c_void};
    pub type c_str = *c_char;

    pub static SOCK_STREAM: c_int = 1_i32;
    pub static SOCK_DGRAM: c_int = 2_i32;
    pub static SOCK_RAW: c_int = 3_i32;

    pub static SOL_SOCKET: c_int = 0xffff_i32;

    pub static SO_DEBUG: c_int = 0x0001_i32;             // turn on debugging info recording
    pub static SO_ACCEPTCONN: c_int = 0x0002_i32;   // socket has had listen()
    pub static SO_REUSEADDR: c_int = 0x0004_i32;   // allow local address reuse
    pub static SO_KEEPALIVE: c_int = 0x0008_i32;   // keep connections alive
    pub static SO_DONTROUTE: c_int = 0x0010_i32;   // just use interface addresses
    pub static SO_BROADCAST: c_int = 0x0020_i32;   // permit sending of broadcast msgs
    pub static SO_LINGER: c_int = 0x1080_i32;   // linger on close if data present (in seconds)
    pub static SO_OOBINLINE: c_int = 0x0100_i32;   // leave received OOB data in line
    pub static SO_SNDBUF: c_int = 0x1001_i32;   // send buffer size
    pub static SO_RCVBUF: c_int = 0x1002_i32;   // receive buffer size
    pub static SO_SNDLOWAT: c_int = 0x1003_i32;   // send low-water mark
    pub static SO_RCVLOWAT: c_int = 0x1004_i32;   // receive low-water mark
    pub static SO_SNDTIMEO: c_int = 0x1005_i32;   // send timeout
    pub static SO_RCVTIMEO: c_int = 0x1006_i32;   // receive timeout
    pub static SO_ERROR: c_int = 0x1007_i32;   // get error status and clear
    pub static SO_TYPE	: c_int = 0x1008_i32;   // get socket type
    // TODO: there are a bunch of Linux specific socket options that should be added

    pub static AF_UNSPEC: c_int = 0_i32;
    pub static AF_UNIX: c_int = 1_i32;
    pub static AF_INET: c_int = 2_i32;
    pub static AF_INET6: c_int = 30_i32;

    pub static AI_PASSIVE: c_int = 0x0001_i32;
    pub static AI_CANONNAME: c_int = 0x0002_i32;
    pub static AI_NUMERICHOST: c_int = 0x0004_i32;
    pub static AI_NUMERICSERV: c_int = 0x1000_i32;

    pub static INET6_ADDRSTRLEN: u32 = 46;

    // Type names are not CamelCase to match the C versions.
    pub type socklen_t = u32;    // 32-bit on Mac (__darwin_socklen_t in _types.h) and Ubuntu Linux (__socklen_t in types.h)
    pub type x = u8;

    pub struct sockaddr_basic {
        sin_family: i16,
        padding: (
            x, x, x, x,
            x, x, x, x,
            x, x, x, x,
            x, x, x, x,
            x, x, x, x,
            x, x, x, x,
            x, x)
    }
    pub struct sockaddr4_in {
        sin_family: i16,
        sin_port: u16,
        sin_addr: in4_addr,
        sin_zero: (
            x, x, x, x,
            x, x, x, x,
            x, x, x, x,
            x, x, x, x,
            x, x, x, x)
    }
    pub struct in4_addr {
        s_addr: c_uint
    }

    pub struct sockaddr6_in {
        sin6_family: u16,
        sin6_port: u16,
        sin6_flowinfo: u32,
        sin6_addr: in6_addr,
        sin6_scope_id: u32
    }

    pub struct in6_addr {
        s6_addr: (
            x, x, x, x,
            x, x, x, x,
            x, x, x, x,
            x, x, x, x)
    }

    pub enum sockaddr {
        unix(sockaddr_basic),
        ipv4(sockaddr4_in),
        ipv6(sockaddr6_in)
    }

    // TODO: think something like [u8]/128 is supported now, but not sure how to initialize it.
    //
    // On both Linux and Mac this struct is supposed to be 128 bytes. Rather than wrestle with
    // alignment we simply make contents 128 bytes which should be fine because the C API
    // always uses pointers to sockaddr_storage.
#[cfg(target_os = "freebsd")]
#[cfg(target_os = "macos")]
    pub struct sockaddr_storage {
        ss_len: u8,
        ss_family: u8,
        contents: (u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8) 
    }

#[cfg(target_os = "linux")]
    pub struct sockaddr_storage {
        ss_family: libc::c_ushort,
        contents: (u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8,
                   u8, u8, u8, u8)
    }

#[cfg(target_os = "freebsd")]
#[cfg(target_os = "win32")]
#[cfg(target_os = "macos")]
    pub struct addrinfo {
        ai_flags: c_int,
        ai_family: c_int,
        ai_socktype: c_int,
        ai_protocol: c_int,
        ai_addrlen: socklen_t,
        ai_canonname: *u8,
        ai_addr: *sockaddr_storage,
        ai_next: *u8
    } //XXX ai_next should be *addrinfo

#[cfg(target_os = "linux")]
    pub struct addrinfo {
         ai_flags: c_int,
         ai_family: c_int,
         ai_socktype: c_int,
         ai_protocol: c_int,
         ai_addrlen: socklen_t,
         ai_addr: *sockaddr_storage,
         ai_canonname: *u8,
         ai_next: *u8
    } //XXX ai_next should be *addrinfo

    extern {
        fn socket(af: c_int, typ: c_int, protocol: c_int) -> c_int;
        fn bind(s: c_int, name: *sockaddr_storage, namelen: socklen_t) -> c_int;
        fn connect(s: c_int, name: *sockaddr_storage, namelen: socklen_t) -> c_int;
        fn listen(s: c_int, backlog: c_int) -> c_int;
        fn accept(sockfd: c_int, name: *sockaddr_storage, namelen: *socklen_t) -> c_int;
        fn send(sd: c_int, buf: *u8, len: c_int, flags: c_int) -> c_int;
        fn recv(sd: c_int, buf: *u8, len: c_int, flags: c_int) -> c_int;
        fn sendto(s: c_int, msg: *u8, len: c_int, flags: c_int,
                  to: *sockaddr_storage, tolen: socklen_t) -> c_int;
        fn recvfrom(s: c_int, msg: *u8, len: c_int, flags: c_int,
                    from: *sockaddr_storage, fromlen: *socklen_t) -> c_int;
        fn close(s: c_int);
        fn setsockopt(sockfd: c_int, level: c_int, optname: c_int,
                      optval: *u8, optlen: socklen_t) -> c_int;
        fn getsockopt(sockfd: c_int, level: c_int, optname: c_int,
                      optval: *u8, optlen: socklen_t) -> c_int;

        fn htons(hostshort: u16) -> u16;
        fn htonl(hostlong: u32) -> u32;
        fn ntohs(netshort: u16) -> u16;
        fn ntohl(netlong: u32) -> u32;

        fn inet_ntop(af: c_int, src: *c_void, dst: *u8, size: socklen_t) -> c_str;
        fn inet_pton(af: c_int, src: c_str, dst: *c_void) -> c_int;

        fn gai_strerror(ecode: c_int) -> c_str;
        fn getaddrinfo(node: c_str, service: c_str, hints: *addrinfo, res: **addrinfo) -> c_int;
        fn freeaddrinfo(ai: *addrinfo);
    }
}

pub fn sockaddr_to_string(saddr: &c::sockaddr) -> ~str
{
    unsafe
    {
        match *saddr
        {
            c::unix(_basic) =>
            {
                ~"unix"		// TODO: is sockaddr_basic supposed to be a sockaddr_un?
            }
            c::ipv4(addr4) =>
            {
                let buffer = vec::from_elem(c::INET6_ADDRSTRLEN as uint + 1u, 0u8);
                c::inet_ntop(
                    c::AF_INET,
                    cast::transmute(&ptr::to_unsafe_ptr(&addr4.sin_addr)),
                    vec::raw::to_ptr(buffer),
                    c::INET6_ADDRSTRLEN);
                str::raw::from_buf(vec::raw::to_ptr(buffer))
            }
            c::ipv6(addr6) =>
            {
                let buffer = vec::from_elem(c::INET6_ADDRSTRLEN as uint + 1u, 0u8);
                c::inet_ntop(
                    c::AF_INET6,
                    cast::transmute(&ptr::to_unsafe_ptr(&addr6.sin6_addr)),
                    vec::raw::to_ptr(buffer),
                    c::INET6_ADDRSTRLEN);
                str::raw::from_buf(vec::raw::to_ptr(buffer))
            }
        }
    }
}

#[cfg(target_os = "freebsd")]
#[cfg(target_os = "macos")]
pub fn mk_default_storage() -> c::sockaddr_storage
{
    c::sockaddr_storage {
        ss_len: 0u8,
        ss_family: 0u8,
        contents: (
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0)
    }
}

#[cfg(target_os = "linux")]
pub fn mk_default_storage() -> c::sockaddr_storage
{
    c::sockaddr_storage {
        ss_family: 0,
        contents: (
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0)
    }
}

#[cfg(target_os = "freebsd")]
#[cfg(target_os = "win32")]
#[cfg(target_os = "macos")]
pub fn mk_default_addrinfo() -> c::addrinfo
{
    c::addrinfo {
        ai_flags: 0i32,
        ai_family: 0i32,
        ai_socktype: 0i32,
        ai_protocol: 0i32,
        ai_addrlen: 0u32,
        ai_canonname: ptr::null(),
        ai_addr: ptr::null(),
        ai_next: ptr::null()
    }
}

#[cfg(target_os = "linux")]
pub fn mk_default_addrinfo() -> c::addrinfo
{
    c::addrinfo {
        ai_flags: 0i32,
        ai_family: 0i32,
        ai_socktype: 0i32,
        ai_protocol: 0i32,
        ai_addrlen: 0u32,
        ai_addr: ptr::null(),
        ai_canonname: ptr::null(),
        ai_next: ptr::null()
    }
}

pub unsafe fn getaddrinfo(host: &str, port: u16, f: &fn(a: c::addrinfo) -> bool) -> Option<~str>
{
    let mut hints: c::addrinfo = mk_default_addrinfo();
    hints.ai_family = c::AF_UNSPEC;
    hints.ai_socktype = c::SOCK_STREAM;

    let servinfo: *c::addrinfo = ptr::null();
    let s_port = fmt!("%u", port as uint);
    let mut result: Option<~str> = None;

    do str::as_c_str(host) |host| {
        do str::as_c_str(s_port) |port| {
            let status = c::getaddrinfo(host, port, ptr::to_unsafe_ptr(&hints),
                                        ptr::to_unsafe_ptr(&servinfo));
            if status == 0i32 {
                let mut p = servinfo;
                while p != ptr::null() {
                    if !f(*p) {
                        break;
                    }
                    p = cast::transmute(&(*p).ai_next);
                }
            } else {
                warn!("getaddrinfo returned %? (%s)", status, str::raw::from_c_str(c::gai_strerror(status)));
                result = Some(~"getaddrinfo failed");
            }
        }
    }
    c::freeaddrinfo(servinfo); 
    result.clone()
}

pub fn inet_ntop(address: &c::addrinfo) -> ~str
{
    unsafe {
        let buffer = vec::from_elem(c::INET6_ADDRSTRLEN as uint + 1u, 0u8);
        c::inet_ntop(address.ai_family,
            if address.ai_family == c::AF_INET {
                let addr: *c::sockaddr4_in = cast::transmute(&address.ai_addr);
                cast::transmute(&ptr::to_unsafe_ptr(&(*addr).sin_addr))
            } else {
                let addr: *c::sockaddr6_in = cast::transmute(&address.ai_addr);
                cast::transmute(&ptr::to_unsafe_ptr(&(*addr).sin6_addr))
            },
            vec::raw::to_ptr(buffer), c::INET6_ADDRSTRLEN);

        str::raw::from_buf(vec::raw::to_ptr(buffer))
    }
}

// TODO: there is no portable way to get errno from rust so, for now, we'll just write them to stderr
// See #2269.
pub fn log_err(mesg: &str)
{
    unsafe {
        do str::as_c_str(mesg) |buffer| {perror(buffer)};
    }
}

// TODO: Isn't c::socket_handle redundant?
pub struct socket_handle {
    sockfd: c_int,
}

impl Drop for socket_handle {
    fn drop(&self)
    {
        unsafe { c::close(self.sockfd); }
    }
}

pub fn socket_handle(x: c_int) -> socket_handle
{
    socket_handle {sockfd: x}
}

pub unsafe fn bind_socket(host: &str, port: u16) -> result::Result<@socket_handle, ~str>
{
    let err = for getaddrinfo(host, port) |ai| {
        if ai.ai_family == c::AF_INET || ai.ai_family == c::AF_INET6    // TODO: should do something to support AF_UNIX
        {
            let sockfd = c::socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
            if sockfd != -1_i32 {
                let val = 1;
                let _ = c::setsockopt(sockfd, c::SOL_SOCKET, c::SO_REUSEADDR,    // this shouldn't be critical so we'll ignore errors from it
                                      cast::transmute(&ptr::to_unsafe_ptr(&val)),
                                      sys::size_of::<int>() as c::socklen_t);

                if c::bind(sockfd, ai.ai_addr, ai.ai_addrlen) == -1_i32 {
                    c::close(sockfd);
                } else {
                    debug!("   bound to socket %?", sockfd);
                    return result::Ok(@socket_handle(sockfd));
                }
            } else {
                log_err(fmt!("socket(%s) error", inet_ntop(&ai)));
            }
        }
    };
    match err
    {
        option::Some(mesg)  => {result::Err(copy(mesg))}
        option::None        => {result::Err(~"bind failed to find an address")}
    }
}

pub unsafe fn connect(host: &str, port: u16) -> result::Result<@socket_handle, ~str>
{
    info!("connecting to %s:%?", host, port);
    let err = for getaddrinfo(host, port) |ai| {
        if ai.ai_family == c::AF_INET || ai.ai_family == c::AF_INET6    // TODO: should do something to support AF_UNIX
        {
            debug!("   trying %s", inet_ntop(&ai));
            let sockfd = c::socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
            if sockfd != -1_i32 {
                if c::connect(sockfd, ai.ai_addr, ai.ai_addrlen) == -1_i32 {
                    c::close(sockfd);
                } else {
                    info!("   connected to socket %?", sockfd);
                    return result::Ok(@socket_handle(sockfd));
                }
            } else {
                log_err(fmt!("socket(%s, %?) error", host, port));
            }
        }
    };
    match err
    {
        option::Some(mesg)  => {result::Err(copy(mesg))}
        option::None        => {result::Err(~"connect failed to find an address")}
    }
}

pub fn listen(sock: @socket_handle, backlog: i32) -> result::Result<@socket_handle, ~str>
{
    unsafe {
        if c::listen(sock.sockfd, backlog) == -1_i32 {
            log_err(~"listen error");
            result::Err(~"listen failed")
        } else {
            result::Ok(sock)
        }
    }
}

// Returns a fd to allow multi-threaded servers to send the fd to a task.
pub struct accept_socket {
    fd: c_int,
    remote_addr: ~str
}

pub unsafe fn accept(sock: @socket_handle) -> result::Result<accept_socket, ~str>
{
    info!("accepting with socket %?", sock.sockfd);
    let addr = mk_default_storage();
    let unused: c::socklen_t = sys::size_of::<c::sockaddr>() as c::socklen_t;
    let fd = c::accept(sock.sockfd, ptr::to_unsafe_ptr(&addr), ptr::to_unsafe_ptr(&unused));

    if fd == -1_i32 {
        log_err(fmt!("accept error"));
        result::Err(~"accept failed")
    } else {
        let their_addr = if addr.ss_family as u8 == c::AF_INET as u8 {
                       c::ipv4(*(ptr::to_unsafe_ptr(&addr) as *c::sockaddr4_in))
                   } else if addr.ss_family as u8 == c::AF_INET6 as u8 {
                       c::ipv6(*(ptr::to_unsafe_ptr(&addr) as *c::sockaddr6_in))
                   } else {
                       c::unix(*(ptr::to_unsafe_ptr(&addr) as *c::sockaddr_basic))
                   };
        info!("accepted socket %? (%s)", fd, sockaddr_to_string(&their_addr));
        result::Ok(accept_socket{
            fd: fd,
            remote_addr: sockaddr_to_string(&their_addr)
        })
    }
}

pub unsafe fn send(sock: @socket_handle, buf: &[u8]) -> result::Result<uint, ~str>
{
    let amt = c::send(sock.sockfd, vec::raw::to_ptr(buf),
                      buf.len() as c_int, 0i32);
    if amt == -1_i32 {
        log_err(fmt!("send error"));
        result::Err(~"send failed")
    } else {
        result::Ok(amt as uint)
    }
}

// Useful for sending str data (where you want to use as_buf instead of as_buffer).
pub unsafe fn send_buf(sock: @socket_handle, buf: *u8, len: uint) -> result::Result<uint, ~str>
{
    let amt = c::send(sock.sockfd, buf, len as c_int, 0i32);
    if amt == -1_i32 {
        log_err(fmt!("send error"));
        result::Err(~"send_buf failed")
    } else {
        result::Ok(amt as uint)
    }
}

pub struct recv_buffer {
    buffer: ~[u8],
    bytes: uint
}

pub unsafe fn recv(sock: @socket_handle, len: uint) -> result::Result<~recv_buffer, ~str>
{
    let buf = vec::from_elem(len + 1u, 0u8);
    let bytes = c::recv(sock.sockfd, vec::raw::to_ptr(buf), len as c_int, 0i32);
    if bytes == -1_i32 {
        log_err(fmt!("recv error"));
        result::Err(~"recv failed")
    } else {
        result::Ok(~recv_buffer {
            buffer: buf,
            bytes: bytes as uint}
        )
    }
}

pub unsafe fn sendto(sock: @socket_handle, buf: &[u8], to: &c::sockaddr)
    -> result::Result<uint, ~str>
{
    let (to_saddr, to_len) = match *to {
      c::ipv4(s)  => { (*(ptr::to_unsafe_ptr(&s) as *c::sockaddr_storage),
                 sys::size_of::<c::sockaddr4_in>()) }
      c::ipv6(s)  => { (*(ptr::to_unsafe_ptr(&s) as *c::sockaddr_storage),
                 sys::size_of::<c::sockaddr6_in>()) }
      c::unix(s)  => { (*(ptr::to_unsafe_ptr(&s) as *c::sockaddr_storage),
                 sys::size_of::<c::sockaddr_basic>()) }
    };
    let amt = c::sendto(sock.sockfd, vec::raw::to_ptr(buf), buf.len() as c_int, 0i32,
                        ptr::to_unsafe_ptr(&to_saddr), to_len as u32);
    if amt == -1_i32 {
        log_err(fmt!("sendto error"));
        result::Err(~"sendto failed")
    } else {
        result::Ok(amt as uint)
    }
}

pub unsafe fn recvfrom(sock: @socket_handle, len: uint)
        -> result::Result<(~[u8], uint, c::sockaddr), ~str>
{
    let from_saddr = mk_default_storage();
    let unused: c::socklen_t = 0u32;
    let buf = vec::from_elem(len + 1u, 0u8);
    let amt = c::recvfrom(sock.sockfd, vec::raw::to_ptr(buf), buf.len() as c_int, 0i32,
                          ptr::to_unsafe_ptr(&from_saddr), ptr::to_unsafe_ptr(&unused));
    if amt == -1_i32 {
        log_err(fmt!("recvfrom error"));
        result::Err(~"recvfrom failed")
    } else {
        result::Ok((buf.clone(), amt as uint,
                   if from_saddr.ss_family as u8 == c::AF_INET as u8 {
                       c::ipv4(*(ptr::to_unsafe_ptr(&from_saddr) as *c::sockaddr4_in))
                   } else if from_saddr.ss_family as u8 == c::AF_INET6 as u8 {
                       c::ipv6(*(ptr::to_unsafe_ptr(&from_saddr) as *c::sockaddr6_in))
                   } else {
                       c::unix(*(ptr::to_unsafe_ptr(&from_saddr) as *c::sockaddr_basic))
                   }))
    }
}

pub unsafe fn setsockopt(sock: @socket_handle, option: int, value: int)
    -> result::Result<c_int, ~str>
{
    let val = value;
    let r = c::setsockopt(sock.sockfd, c::SOL_SOCKET, option as c_int,
                          cast::transmute(&ptr::to_unsafe_ptr(&val)),
                          sys::size_of::<int>() as c::socklen_t);
    if r == -1_i32 {
        log_err(fmt!("setsockopt error"));
        result::Err(~"setsockopt failed")
    } else {
        result::Ok(r)
    }
}

pub unsafe fn enablesockopt(sock: @socket_handle, option: int)
    -> result::Result<c_int, ~str>
{
    setsockopt(sock, option, 1)
}

pub unsafe fn disablesockopt(sock: @socket_handle, option: int)
    -> result::Result<c_int, ~str>
{
    setsockopt(sock, option, 0)
}

pub fn htons(hostshort: u16) -> u16
{
    unsafe { c::htons(hostshort) }
}

pub fn htonl(hostlong: u32) -> u32
{
    unsafe { c::htonl(hostlong) }
}

pub fn ntohs(netshort: u16) -> u16
{
    unsafe { c::ntohs(netshort) }
}

pub fn ntohl(netlong: u32) -> u32
{
    unsafe {c::ntohl(netlong) }
}

#[test]
fn test_server_client()
{
    unsafe {
        fn run_client(test_str: &str, port: u16)
        {
            let ts = test_str.to_owned();
            unsafe {
                do task::spawn {
                    unsafe {
                        match connect(~"localhost", port) {
                            result::Ok(handle) => {
                                let f: &fn(*u8, uint) -> result::Result<uint, ~str> = |
                                        buf, _len| {
                                    send_buf(handle, buf, ts.len())
                                };
                                let res = str::as_buf(ts, f);
                                assert!(result::is_ok(&res));
                            }
                            result::Err(err) => {
                                error!("Error %s connecting", err);
                                assert!(false);
                            }
                        }
                    }
                }
            }
        }

        unsafe fn run_server(test_str: &str, s: @socket_handle)
        {
             match accept(s)
             {
                 result::Ok(args) =>
                 {
                     if !str::eq(&~"127.0.0.1", &args.remote_addr) && !str::eq(&~"::1", &args.remote_addr)
                     {
                         error!("Expected 127.0.0.1 or ::1 for remote addr but found %s", args.remote_addr);
                         assert!(false)
                     }
                     let c = @socket_handle(args.fd);
                     match recv(c, 1024u)
                     {
                         result::Ok(res) =>
                         {
                             assert!(res.bytes == str::len(test_str));
                             assert!(vec::slice(res.buffer, 0u, res.bytes) == str::to_bytes(test_str));
                         }
                         result::Err(err) =>
                         {
                             error!("Error %s with recv", err);
                             assert!(false);
                         }
                     }
                 }
                 result::Err(err) =>
                 {
                     error!("Error %s accepting", err);
                     assert!(false);
                 }
             }
        }

        info!("---- test_server_client ------------------------");
        let port = 48006u16;
        let test_str = ~"testing";

        match bind_socket(~"localhost", port)
        {
            result::Ok(s) =>
            {
                match listen(s, 1i32)
                {
                    result::Ok(s) =>
                    {
                        run_client(test_str, port);
                        run_server(test_str, s);
                    }
                    result::Err(err) =>
                    {
                        error!("Error %s listening", err);
                        assert!(false);
                    }
                }
            }
            result::Err(err) =>
            {
                error!("Error %s binding", err);
                assert!(false);
            }
        }
    }
}

#[test]
fn test_getaddrinfo_localhost()
{
    info!("---- test_getaddrinfo_localhost ------------------------");
    let mut hints = mk_default_addrinfo();
    hints.ai_family = c::AF_UNSPEC;
    hints.ai_socktype = c::SOCK_STREAM;

    let servinfo: *c::addrinfo = ptr::null();
    let port = 48007u16;
    unsafe {
        do str::as_c_str(~"localhost") |host| {
            do str::as_c_str(fmt!("%u", port as uint)) |p| {
                let status = c::getaddrinfo(host, p, ptr::to_unsafe_ptr(&hints), ptr::to_unsafe_ptr(&servinfo));
                assert!(status == 0_i32);
                unsafe {
                    assert!(servinfo != ptr::null());
                    let p = *servinfo;

                    let ipstr = inet_ntop(&p);
                    assert!(str::eq(&~"127.0.0.1", &ipstr) || str::eq(&~"::1", &ipstr));
                }
                c::freeaddrinfo(servinfo)
            }
        }
    }
}

pub unsafe fn getaddrinfo2(host: &str, service: &str, f: &fn(a: c::addrinfo) -> bool) -> Option<~str>
{
    let mut hints = mk_default_addrinfo();

    hints.ai_family = c::AF_INET;
    hints.ai_socktype = c::SOCK_STREAM;

    let servinfo: *c::addrinfo = ptr::null();
    let mut result = option::None;
    do str::as_c_str(host) |host| {
        do str::as_c_str(service) |port| {
                     let status = c::getaddrinfo(host, port, ptr::to_unsafe_ptr(&hints),
                                                 ptr::to_unsafe_ptr(&servinfo));
                     if status == 0i32 {
                         let mut p = servinfo;
                         while p != ptr::null() {
                             if !f(*p) {
                                 break;
                             }
                             p = cast::transmute(&(*p).ai_next);
                         }
                     } else {
                         warn!("getaddrinfo returned %? (%s)", status, str::raw::from_c_str(c::gai_strerror(status)));
                         result = option::Some(~"getaddrinfo failed");
                     }
        }
    }
    c::freeaddrinfo(servinfo); 
    result
}

//pub fn getaddrinfo(host: &str, port: u16, f: fn(addrinfo) -> bool) -> Option<~str> unsafe {

//pub fn mk_default_addrinfo() -> addrinfo {
//    {ai_flags: 0i32, ai_family: 0i32, ai_socktype: 0i32, ai_protocol: 0i32, ai_addrlen: 0u32,
//     ai_canonname: ptr::null(), ai_addr: ptr::null(), ai_next: ptr::null()}
//}

