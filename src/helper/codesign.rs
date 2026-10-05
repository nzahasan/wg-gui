//! Who is on the other end of the socket. The helper runs as root and
//! changes routes and DNS, so it only serves processes whose code
//! signature satisfies `requirement()`: the wg-gui app, signed by our team.

use std::ffi::c_void;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use wg_common::ipc::APP_ID;

/// Set when building a release (see packaging/macos/build-app.sh).
const TEAM_ID: Option<&str> = option_env!("WG_TEAM_ID");

const SOL_LOCAL: i32 = 0;
const LOCAL_PEERTOKEN: i32 = 0x006;
const UTF8: u32 = 0x0800_0100;

type CFTypeRef = *const c_void;

/// Opaque CFDictionary callback tables; only their address is used.
#[repr(C)]
struct CallBacks {
    _private: [u8; 0],
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeDictionaryKeyCallBacks: CallBacks;
    static kCFTypeDictionaryValueCallBacks: CallBacks;
    fn CFDataCreate(allocator: CFTypeRef, bytes: *const u8, length: isize) -> CFTypeRef;
    fn CFDictionaryCreate(
        allocator: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: isize,
        key_callbacks: *const CallBacks,
        value_callbacks: *const CallBacks,
    ) -> CFTypeRef;
    fn CFStringCreateWithBytes(allocator: CFTypeRef, bytes: *const u8, length: isize, encoding: u32, external: u8) -> CFTypeRef;
    fn CFRelease(cf: CFTypeRef);
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributeAudit: CFTypeRef;
    fn SecCodeCopyGuestWithAttributes(host: CFTypeRef, attributes: CFTypeRef, flags: u32, guest: *mut CFTypeRef) -> i32;
    fn SecRequirementCreateWithString(text: CFTypeRef, flags: u32, requirement: *mut CFTypeRef) -> i32;
    fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> i32;
}

unsafe extern "C" {
    fn getsockopt(socket: i32, level: i32, name: i32, value: *mut c_void, len: *mut u32) -> i32;
}

/// The code requirement clients must meet, or None when this helper was
/// built without a team id and so cannot check anyone.
pub fn requirement() -> Option<String> {
    TEAM_ID.filter(|t| !t.is_empty()).map(|team| {
        format!("identifier \"{APP_ID}\" and anchor apple generic and certificate leaf[subject.OU] = \"{team}\"")
    })
}

/// Checks the peer of `stream` against `requirement`.
pub fn check_peer(stream: &UnixStream, requirement: &str) -> Result<(), String> {
    // The audit token names the exact process, unlike a pid, which could
    // be reused between the lookup and the check.
    let mut token = [0u8; 32];
    let mut len = token.len() as u32;
    let rc = unsafe {
        getsockopt(stream.as_raw_fd(), SOL_LOCAL, LOCAL_PEERTOKEN, token.as_mut_ptr().cast(), &mut len)
    };
    if rc != 0 || len as usize != token.len() {
        return Err(format!("cannot read the peer's audit token: {}", std::io::Error::last_os_error()));
    }

    unsafe {
        let data = Owned(CFDataCreate(std::ptr::null(), token.as_ptr(), token.len() as isize));
        let keys = [kSecGuestAttributeAudit];
        let values = [data.0];
        let attributes = Owned(CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            &raw const kCFTypeDictionaryKeyCallBacks,
            &raw const kCFTypeDictionaryValueCallBacks,
        ));
        let mut code = std::ptr::null();
        let status = SecCodeCopyGuestWithAttributes(std::ptr::null(), attributes.0, 0, &mut code);
        if status != 0 {
            return Err(format!("cannot find the peer's code (OSStatus {status})"));
        }
        let code = Owned(code);

        let text = Owned(CFStringCreateWithBytes(std::ptr::null(), requirement.as_ptr(), requirement.len() as isize, UTF8, 0));
        let mut compiled = std::ptr::null();
        let status = SecRequirementCreateWithString(text.0, 0, &mut compiled);
        if status != 0 {
            return Err(format!("bad code requirement (OSStatus {status})"));
        }
        let compiled = Owned(compiled);

        match SecCodeCheckValidity(code.0, 0, compiled.0) {
            0 => Ok(()),
            status => Err(format!("peer is not a signed wg-gui (OSStatus {status})")),
        }
    }
}

/// Releases a Core Foundation object when dropped.
struct Owned(CFTypeRef);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_is_checked_against_the_requirement() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        // The peer is this test process; "always" and "never" are the
        // requirement language's constants.
        assert_eq!(check_peer(&ours, "always"), Ok(()));
        assert!(check_peer(&theirs, "never").is_err());
        assert!(check_peer(&ours, &format!("identifier \"{APP_ID}\" and anchor apple generic")).is_err());
    }

    #[test]
    fn requirement_names_the_app_and_team() {
        if let Some(requirement) = requirement() {
            assert!(requirement.contains(APP_ID) && requirement.contains("subject.OU"));
        }
    }
}
