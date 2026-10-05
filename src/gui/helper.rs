//! Installing `wg-helper`, the root daemon that brings tunnels up for us,
//! through SMAppService (macOS 13+). Its launchd plist ships inside
//! wg-gui.app; registering it asks macOS to run it, and the user approves
//! it once in System Settings → General → Login Items.
//!
//! With WG_HELPER_SOCKET set (a helper started by hand, for development)
//! none of this is needed.

use objc2::msg_send;
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject};
use objc2_foundation::{NSError, NSString};

use wg_common::ipc::{HELPER_LABEL, SOCKET_ENV};

#[link(name = "ServiceManagement", kind = "framework")]
unsafe extern "C" {}

// SMAppServiceStatus
const NOT_REGISTERED: isize = 0;
const ENABLED: isize = 1;
const REQUIRES_APPROVAL: isize = 2;

#[derive(Debug, Clone, PartialEq)]
pub enum HelperState {
    Ready,
    /// Registered, waiting for the user to allow it in Login Items.
    NeedsApproval,
    /// Not registered, e.g. after "Uninstall Helper…"; it can be
    /// installed again.
    NotInstalled,
    /// Cannot be used; the text says why.
    Missing(String),
}

/// The helper's state, registering it first if it is not yet.
pub fn ensure_registered() -> HelperState {
    if is_manual() {
        return HelperState::Ready;
    }
    let Some(service) = service() else {
        return no_service();
    };
    if status(&service) == NOT_REGISTERED {
        let result: Result<(), Retained<NSError>> = unsafe { msg_send![&*service, registerAndReturnError: _] };
        if let Err(error) = result {
            eprintln!("warning: cannot register the helper: {}", error.localizedDescription());
            return HelperState::Missing(format!("Cannot install the helper: {}", error.localizedDescription()));
        }
    }
    state_of(&service)
}

/// Unregisters the helper: launchd stops it (taking any tunnel down) and
/// it no longer starts at boot or shows in Login Items.
pub fn uninstall() -> Result<(), String> {
    if is_manual() {
        return Err(format!("The helper was started by hand ({SOCKET_ENV}); stop it there"));
    }
    let service = service().ok_or("This macOS has no SMAppService")?;
    // Not registered, or not found (e.g. an ad-hoc signed or unbundled
    // build): there is nothing to remove.
    if !matches!(status(&service), ENABLED | REQUIRES_APPROVAL) {
        return Ok(());
    }
    let result: Result<(), Retained<NSError>> = unsafe { msg_send![&*service, unregisterAndReturnError: _] };
    result.map_err(|error| format!("Cannot uninstall the helper: {}", error.localizedDescription()))
}

/// True when the helper was started by hand for development, so it is
/// not ours to register or remove.
fn is_manual() -> bool {
    std::env::var_os(SOCKET_ENV).is_some()
}

/// The helper's state as it is now; cheap enough to poll.
pub fn state() -> HelperState {
    if is_manual() {
        return HelperState::Ready;
    }
    match service() {
        Some(service) => state_of(&service),
        None => no_service(),
    }
}

fn no_service() -> HelperState {
    HelperState::Missing("This macOS has no SMAppService (needs macOS 13 or later)".to_string())
}

/// Opens System Settings at Login Items, where the helper is allowed.
pub fn open_login_items() {
    if let Some(class) = AnyClass::get(c"SMAppService") {
        let _: () = unsafe { msg_send![class, openSystemSettingsLoginItems] };
    }
}

fn state_of(service: &AnyObject) -> HelperState {
    match status(service) {
        ENABLED => HelperState::Ready,
        REQUIRES_APPROVAL => HelperState::NeedsApproval,
        NOT_REGISTERED => HelperState::NotInstalled,
        _ => HelperState::Missing(format!(
            "The helper is not installed. Open wg-gui from /Applications, or for development run \
             `sudo wg-helper --dev --socket /tmp/wg.sock` and start wg-gui with {SOCKET_ENV}=/tmp/wg.sock."
        )),
    }
}

fn service() -> Option<Retained<AnyObject>> {
    let class = AnyClass::get(c"SMAppService")?;
    let plist = NSString::from_str(&format!("{HELPER_LABEL}.plist"));
    unsafe { msg_send![class, daemonServiceWithPlistName: &*plist] }
}

fn status(service: &AnyObject) -> isize {
    unsafe { msg_send![service, status] }
}
