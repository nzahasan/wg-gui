//! macOS `utun` virtual network device.
//!
//! A utun device is created by connecting a PF_SYSTEM socket to the
//! `com.apple.net.utun_control` kernel control. The kernel then hands us
//! IP packets on that socket (each prefixed with a 4-byte address family
//! header) and anything we write to it is delivered to the network stack.
//! The interface disappears when the socket is closed.

use std::ffi::{c_int, c_void};
use std::io;
use std::time::Duration;

const PF_SYSTEM: c_int = 32;
const SOCK_DGRAM: c_int = 2;
const SYSPROTO_CONTROL: c_int = 2;
const AF_SYS_CONTROL: u16 = 2;
const CTLIOCGINFO: u64 = 0xc064_4e03;
const UTUN_OPT_IFNAME: c_int = 2;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
const MAX_KCTL_NAME: usize = 96;
const SOL_SOCKET: c_int = 0xffff;
const SO_RCVTIMEO: c_int = 0x1006;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;

/// Enough for any IP packet that can traverse the tunnel.
const MAX_PACKET: usize = 65536;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; MAX_KCTL_NAME],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i32,
}

unsafe extern "C" {
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn ioctl(fd: c_int, request: u64, ...) -> c_int;
    fn connect(fd: c_int, addr: *const SockaddrCtl, len: u32) -> c_int;
    fn getsockopt(fd: c_int, level: c_int, name: c_int, value: *mut u8, len: *mut u32) -> c_int;
    fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, len: u32) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, len: usize) -> isize;
    fn write(fd: c_int, buf: *const c_void, len: usize) -> isize;
    fn close(fd: c_int) -> c_int;
}

pub struct Tun {
    fd: c_int,
    pub name: String,
}

impl Tun {
    /// Creates a new utun device; the kernel picks the next free number.
    pub fn open() -> io::Result<Tun> {
        let fd = unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Ask the kernel for the id of the utun control.
        let mut info = CtlInfo { ctl_id: 0, ctl_name: [0; MAX_KCTL_NAME] };
        info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);
        if unsafe { ioctl(fd, CTLIOCGINFO, &mut info) } < 0 {
            let err = io::Error::last_os_error();
            unsafe { close(fd) };
            return Err(err);
        }

        // Connecting to the control creates the interface. sc_unit = 0 lets
        // the kernel choose the unit number (utun0, utun1, ...).
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: PF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        if unsafe { connect(fd, &addr, std::mem::size_of::<SockaddrCtl>() as u32) } < 0 {
            let err = io::Error::last_os_error();
            unsafe { close(fd) };
            return Err(err);
        }

        // Find out which name the kernel gave us.
        let mut name_buf = [0u8; 32];
        let mut name_len = name_buf.len() as u32;
        let rc = unsafe {
            getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name_buf.as_mut_ptr(), &mut name_len)
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            unsafe { close(fd) };
            return Err(err);
        }
        let name = String::from_utf8_lossy(&name_buf[..name_len as usize])
            .trim_end_matches('\0')
            .to_string();

        Ok(Tun { fd, name })
    }

    /// Makes `read_packet` give up after `timeout` with `WouldBlock`, so a
    /// reader thread can notice that the tunnel is being stopped.
    pub fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
        let tv = Timeval { tv_sec: timeout.as_secs() as i64, tv_usec: timeout.subsec_micros() as i32 };
        let len = std::mem::size_of::<Timeval>() as u32;
        if unsafe { setsockopt(self.fd, SOL_SOCKET, SO_RCVTIMEO, (&tv as *const Timeval).cast(), len) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Blocks until the network stack hands us an IP packet (or the read
    /// timeout passes). Returns the packet without the 4-byte address
    /// family header.
    pub fn read_packet(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_PACKET];
        let n = unsafe { read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short utun packet"));
        }
        buf.truncate(n);
        buf.drain(..4);
        Ok(buf)
    }

    /// Delivers an IP packet to the network stack.
    pub fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() {
            return Ok(());
        }
        // The IP version lives in the top nibble of the first byte.
        let family = if packet[0] >> 4 == 6 { AF_INET6 } else { AF_INET };
        let mut framed = Vec::with_capacity(packet.len() + 4);
        framed.extend_from_slice(&[0, 0, 0, family]);
        framed.extend_from_slice(packet);

        let n = unsafe { write(self.fd, framed.as_ptr().cast(), framed.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}
