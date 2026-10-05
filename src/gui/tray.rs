//! The macOS integration outside iced: the Dock icon, the menu-bar (tray)
//! icon with Show application / Disconnect / Uninstall Helper / Exit,
//! activating the app,
//! and locking the window's size (no zoom).
//!
//! All of these need the AppKit event loop to be running, so they are set up when
//! the window opens (see `Message::Opened`), on the main thread.

use std::cell::Cell;

use iced::Subscription;
use iced::futures::SinkExt;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use crate::app::Message;

const DOCK_ICON_PNG: &[u8] = include_bytes!("../../assets/icons/1-AppIcon-macOS/AppIcon-1024.png");
/// Menu-bar icons (assets/icons/3-MenuBar), drawn on the menu bar's 22 pt
/// canvas. While no tunnel is up ("off") the icon is a template, so macOS
/// picks its colour; while one is connected ("on") it carries a green dot
/// (#34C759), so the outline is drawn white for a dark menu bar and black
/// for a light one.
const MENU_BAR_ICON_SVG: &[u8] = include_bytes!("../../assets/icons/3-MenuBar/vpn-tray-off-template.svg");
const MENU_BAR_ACTIVE_DARK_SVG: &[u8] = include_bytes!("../../assets/icons/3-MenuBar/vpn-tray-on-dark.svg");
const MENU_BAR_ACTIVE_LIGHT_SVG: &[u8] = include_bytes!("../../assets/icons/3-MenuBar/vpn-tray-on-light.svg");
/// The icons are drawn at 2× (44 px, for Retina); tray-icon shows them
/// 22 pt tall.
const MENU_BAR_ICON_SCALE: f32 = 2.0;

const SHOW_ID: &str = "show";
const DISCONNECT_ID: &str = "disconnect";
const UNINSTALL_HELPER_ID: &str = "uninstall-helper";
const EXIT_ID: &str = "exit";

/// Keeps the menu-bar icon alive; dropping it removes the icon.
pub struct Tray {
    icon: TrayIcon,
    disconnect: MenuItem,
    /// The icon currently shown.
    look: Cell<Look>,
}

#[derive(Clone, Copy, PartialEq)]
enum Look {
    Idle,
    Connected { dark: bool },
}

impl Tray {
    pub fn new() -> Result<Tray, String> {
        let show = MenuItem::with_id(SHOW_ID, "Show application", true, None);
        let disconnect = MenuItem::with_id(DISCONNECT_ID, "Disconnect", false, None);
        let uninstall = MenuItem::with_id(UNINSTALL_HELPER_ID, "Uninstall Helper…", true, None);
        let exit = MenuItem::with_id(EXIT_ID, "Exit", true, None);
        let menu = Menu::new();
        menu.append_items(&[&show, &disconnect, &PredefinedMenuItem::separator(), &uninstall, &exit])
            .map_err(|e| format!("cannot build the menu-bar menu: {e}"))?;

        let icon = TrayIconBuilder::new()
            .with_icon_templated(menu_bar_icon(MENU_BAR_ICON_SVG)?)
            .with_tooltip("wg-gui")
            .with_menu(Box::new(menu))
            .build()
            .map_err(|e| format!("cannot create the menu-bar icon: {e}"))?;
        Ok(Tray { icon, disconnect, look: Cell::new(Look::Idle) })
    }

    /// "Disconnect" is only offered while a tunnel is up or coming up
    /// (`can_disconnect`); the icon shows the green dot once it is
    /// connected, outlined to suit a `dark` or light menu bar. Called after
    /// every message, including appearance changes.
    pub fn set_status(&self, can_disconnect: bool, connected: bool, dark: bool) {
        self.disconnect.set_enabled(can_disconnect);
        let look = if connected { Look::Connected { dark } } else { Look::Idle };
        if look == self.look.get() {
            return;
        }
        let (svg, template) = match look {
            Look::Idle => (MENU_BAR_ICON_SVG, true),
            Look::Connected { dark: true } => (MENU_BAR_ACTIVE_DARK_SVG, false),
            Look::Connected { dark: false } => (MENU_BAR_ACTIVE_LIGHT_SVG, false),
        };
        let shown = menu_bar_icon(svg).and_then(|icon| {
            let icon = Some(icon);
            let result = if template { self.icon.set_icon_templated(icon) } else { self.icon.set_icon(icon) };
            result.map_err(|e| e.to_string())
        });
        match shown {
            Ok(()) => self.look.set(look),
            Err(e) => eprintln!("warning: cannot update the menu-bar icon: {e}"),
        }
    }
}

/// Menu clicks, as app messages. The menu reports them on a global channel;
/// a thread waits on it and forwards each one.
pub fn events() -> Subscription<Message> {
    Subscription::run(|| {
        iced::stream::channel(8, async |output| {
            std::thread::spawn(move || {
                let mut output = output;
                while let Ok(event) = MenuEvent::receiver().recv() {
                    let message = match event.id.0.as_str() {
                        SHOW_ID => Message::ShowWindow,
                        DISCONNECT_ID => Message::Disconnect,
                        UNINSTALL_HELPER_ID => Message::UninstallHelper,
                        EXIT_ID => Message::CloseRequested,
                        _ => continue,
                    };
                    if iced::futures::executor::block_on(output.send(message)).is_err() {
                        break; // The app is gone.
                    }
                }
            });
            std::future::pending::<()>().await;
        })
    })
}

/// A menu-bar icon SVG, rasterised.
fn menu_bar_icon(svg: &[u8]) -> Result<Icon, String> {
    let (rgba, width, height) = menu_bar_rgba(svg)?;
    Icon::from_rgba(rgba, width, height).map_err(|e| format!("bad menu-bar icon: {e}"))
}

/// Straight RGBA pixels of a menu-bar icon, and its size.
fn menu_bar_rgba(svg: &[u8]) -> Result<(Vec<u8>, u32, u32), String> {
    use resvg::{tiny_skia, usvg};

    let tree = usvg::Tree::from_data(svg, &usvg::Options::default()).map_err(|e| format!("bad menu-bar icon: {e}"))?;
    let size = tree.size().to_int_size().scale_by(MENU_BAR_ICON_SCALE).ok_or("empty menu-bar icon")?;
    let mut pixmap = tiny_skia::Pixmap::new(size.width(), size.height()).ok_or("empty menu-bar icon")?;
    let scale = tiny_skia::Transform::from_scale(MENU_BAR_ICON_SCALE, MENU_BAR_ICON_SCALE);
    resvg::render(&tree, scale, &mut pixmap.as_mut());

    // tiny-skia stores premultiplied colour; icons expect straight RGBA.
    let rgba: Vec<u8> = pixmap
        .pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect();
    Ok((rgba, size.width(), size.height()))
}

/// Shows the app icon in the Dock. A bare binary has none of its own.
pub fn set_dock_icon() {
    use objc2::{AllocAnyThread, MainThreadMarker};
    use objc2_app_kit::{NSApplication, NSImage};
    use objc2_foundation::NSData;

    let Some(main_thread) = MainThreadMarker::new() else {
        return;
    };
    let data = NSData::with_bytes(DOCK_ICON_PNG);
    if let Some(image) = NSImage::initWithData(NSImage::alloc(), &data) {
        unsafe { NSApplication::sharedApplication(main_thread).setApplicationIconImage(Some(&image)) };
    }
}

/// Brings the app forward and gives it keyboard focus, which also lets
/// macOS show its cursors (the hand over buttons). Returns whether the
/// app is now active: since macOS 14 the system may refuse a request
/// from a process started in a terminal.
pub fn activate_app() -> bool {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSApplicationActivationOptions, NSRunningApplication};

    let Some(main_thread) = MainThreadMarker::new() else {
        return false;
    };
    #[allow(deprecated)]
    let options = NSApplicationActivationOptions::ActivateAllWindows
        | NSApplicationActivationOptions::ActivateIgnoringOtherApps;
    NSRunningApplication::currentApplication().activateWithOptions(options);
    let app = NSApplication::sharedApplication(main_thread);
    app.activate();
    app.isActive()
}

/// The accent colour picked in System Settings → Appearance, or None for
/// Multicolor, where macOS leaves the colour to each app.
///
/// `controlAccentColor` is a dynamic colour with a brighter variant for
/// dark mode, so it is resolved in the app's current appearance, as Apple
/// recommends for colours used outside of view drawing.
pub fn system_accent() -> Option<iced::Color> {
    use std::cell::Cell;

    use block2::RcBlock;
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSColor, NSColorSpace};
    use objc2_foundation::{NSString, NSUserDefaults};

    // Multicolor is the absence of the setting.
    let key = NSString::from_str("AppleAccentColor");
    NSUserDefaults::standardUserDefaults().objectForKey(&key)?;

    let resolved = Cell::new(None);
    let resolve = || {
        resolved.set(NSColor::controlAccentColor().colorUsingColorSpace(&NSColorSpace::sRGBColorSpace()).map(|c| {
            iced::Color::from_rgb(c.redComponent() as f32, c.greenComponent() as f32, c.blueComponent() as f32)
        }));
    };
    match MainThreadMarker::new() {
        Some(main_thread) => NSApplication::sharedApplication(main_thread)
            .effectiveAppearance()
            .performAsCurrentDrawingAppearance(&RcBlock::new(resolve)),
        None => resolve(),
    }
    resolved.get()
}

/// Accent colour changes in System Settings, as app messages. AppKit posts
/// NSSystemColorsDidChangeNotification when they happen (the documented
/// signal, also the one WebKit and Chromium listen for), so nothing is
/// polled.
pub fn accent_changes() -> Subscription<Message> {
    Subscription::run(|| {
        iced::stream::channel(4, async |mut output| {
            use iced::futures::StreamExt;

            let mut changes = observe_system_colors();
            while changes.next().await.is_some() {
                if output.send(Message::AccentChanged).await.is_err() {
                    break; // The app is gone.
                }
            }
        })
    })
}

/// Registers for NSSystemColorsDidChangeNotification; each one arrives as a
/// unit on the returned channel. The observer stays for the app's lifetime.
fn observe_system_colors() -> iced::futures::channel::mpsc::UnboundedReceiver<()> {
    use std::ptr::NonNull;

    use block2::RcBlock;
    use objc2_app_kit::NSSystemColorsDidChangeNotification;
    use objc2_foundation::{NSNotification, NSNotificationCenter};

    let (sender, receiver) = iced::futures::channel::mpsc::unbounded();
    let block = RcBlock::new(move |_: NonNull<NSNotification>| {
        let _ = sender.unbounded_send(());
    });
    // SAFETY: no object filter; with no queue the block runs on the posting
    // thread, and it only sends on a thread-safe channel.
    let observer = unsafe {
        NSNotificationCenter::defaultCenter().addObserverForName_object_queue_usingBlock(
            Some(NSSystemColorsDidChangeNotification),
            None,
            None,
            &block,
        )
    };
    std::mem::forget(observer);
    receiver
}

/// Bounces the Dock icon once: the usual hint when an app could not take
/// focus by itself.
pub fn request_attention() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSRequestUserAttentionType};

    let Some(main_thread) = MainThreadMarker::new() else {
        return;
    };
    NSApplication::sharedApplication(main_thread).requestUserAttention(NSRequestUserAttentionType::InformationalRequest);
}

/// Keeps the fixed-size window from being zoomed: greys out the green
/// zoom button and refuses zooming (a title-bar double-click set to
/// "Zoom").
pub fn lock_window_layout() {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSWindowButton};

    let Some(main_thread) = MainThreadMarker::new() else {
        return;
    };
    for window in NSApplication::sharedApplication(main_thread).windows().iter() {
        if let Some(zoom) = window.standardWindowButton(NSWindowButton::ZoomButton) {
            zoom.setEnabled(false);
        }
        if let Some(delegate) = window.delegate() {
            refuse_zoom(AsRef::<objc2::runtime::AnyObject>::as_ref(&*delegate));
        }
    }
}

/// Adds `windowShouldZoom:toFrame:` answering NO to the window delegate's
/// class (winit's, which does not implement it). Adding it again is a
/// no-op.
fn refuse_zoom(delegate: &objc2::runtime::AnyObject) {
    use objc2::runtime::{AnyClass, AnyObject, Bool, Imp, Sel};
    use objc2::sel;

    #[repr(C)]
    struct Rect([f64; 4]);

    unsafe extern "C-unwind" fn should_zoom(_: *mut AnyObject, _: Sel, _: *mut AnyObject, _: Rect) -> Bool {
        Bool::NO
    }

    // BOOL is `bool` on Apple silicon and `signed char` on Intel.
    #[cfg(target_arch = "aarch64")]
    const TYPES: &std::ffi::CStr = c"B@:@{CGRect={CGPoint=dd}{CGSize=dd}}";
    #[cfg(not(target_arch = "aarch64"))]
    const TYPES: &std::ffi::CStr = c"c@:@{CGRect={CGPoint=dd}{CGSize=dd}}";

    let class: *const AnyClass = delegate.class();
    unsafe {
        let imp: Imp = std::mem::transmute(
            should_zoom as unsafe extern "C-unwind" fn(*mut AnyObject, Sel, *mut AnyObject, Rect) -> Bool,
        );
        objc2::ffi::class_addMethod(class as *mut AnyClass, sel!(windowShouldZoom:toFrame:), imp, TYPES.as_ptr());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn menu_bar_icons_are_drawn() {
        for svg in [super::MENU_BAR_ICON_SVG, super::MENU_BAR_ACTIVE_DARK_SVG, super::MENU_BAR_ACTIVE_LIGHT_SVG] {
            let (rgba, width, height) = super::menu_bar_rgba(svg).unwrap();
            assert_eq!((width, height), (44, 44));
            let opaque = rgba.chunks(4).filter(|px| px[3] > 128).count();
            let total = (width * height) as usize;
            assert!(opaque > total / 20 && opaque < total * 9 / 10, "{opaque} of {total} pixels drawn");
        }
    }
}
