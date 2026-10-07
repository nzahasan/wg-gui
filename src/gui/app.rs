//! Application state and the update loop. The screens in `screens/` only
//! read this state and emit `Message`s.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iced::animation::{Animation, Easing};
use iced::widget::{container, float, stack};
use iced::{Color, Element, Event, Length, Subscription, Task, Vector, event, window};

use wg_common::config::{self, Cidr};
use wg_common::{base64, noise};
use wg_common::ipc::{HelperClient, Started};
use wg_common::netconfig::Route;
use wg_common::tunnel::{LinkState, Stats};

use crate::graph::History;
use crate::helper::{self, HelperState};
use crate::storage::{self, Profile, Store};
use crate::{format, screens, theme, tray};

const TOAST_TIME: Duration = Duration::from_millis(2800);
/// Dropping several files sends one event per file; wait this long for
/// the rest before importing.
const DROP_BATCH_DELAY: Duration = Duration::from_millis(80);
/// macOS often drops an activation request made while the app is still
/// launching; ask once more after this long.
const ACTIVATE_RETRY_DELAY: Duration = Duration::from_millis(150);
/// How far a new screen slides in while it fades up from the background.
const SLIDE_DISTANCE: f32 = 28.0;

#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    Profiles,
    Import,
    /// A profile typed in by hand.
    Create,
    Connection,
    /// The read-only config of a profile.
    Config(String),
}

impl Screen {
    /// Depth in the navigation; deeper screens slide in from the right.
    fn depth(&self) -> u8 {
        match self {
            Screen::Profiles => 0,
            Screen::Create => 2,
            _ => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Status {
    /// Bringing the tunnel up, or up but no handshake yet.
    Connecting,
    Connected,
    /// Was connected, but the server stopped answering (a handshake
    /// unanswered, or traffic with no reply); the tunnel keeps trying.
    Reconnecting,
    /// Was connected, but there is no network (Wi-Fi off, cable out).
    /// The tunnel stays configured and picks up when the network returns.
    Offline,
    Disconnecting,
}

/// What the Connection screen shows about a running tunnel: the profile's
/// config plus what the helper reported when it brought the tunnel up.
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub tun_name: String,
    pub endpoint_text: String,
    pub server: SocketAddr,
    pub addresses: Vec<Cidr>,
    pub dns: Vec<IpAddr>,
    pub dns_changed: bool,
    pub mtu: u16,
    pub routes: Vec<Route>,
    pub allowed_ips: Vec<Cidr>,
}

pub struct Active {
    pub profile: String,
    pub status: Status,
    pub info: Option<TunnelInfo>,
    /// When the tunnel came up.
    pub started: Option<Instant>,
    pub history: History,
    pub stats: Stats,
    last_sample: Option<(Instant, Stats)>,
}

impl Active {
    pub fn seconds(&self) -> u64 {
        self.started.map_or(0, |t| t.elapsed().as_secs())
    }
}

/// A single dropped or picked file waiting for review.
#[derive(Debug, Clone)]
pub struct Pending {
    pub file_name: String,
    /// Where the file was imported from.
    pub source: PathBuf,
    pub name: String,
    pub text: String,
    pub summary: config::Summary,
}

/// A profile being typed in on the Create screen; each field as entered.
#[derive(Debug, Clone, Default)]
pub struct Draft {
    pub name: String,
    pub private_key: String,
    pub address: String,
    pub dns: String,
    pub mtu: String,
    pub peer_public_key: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub preshared_key: String,
    pub keepalive: String,
}

#[derive(Debug, Clone, Copy)]
pub enum DraftField {
    Name,
    PrivateKey,
    Address,
    Dns,
    Mtu,
    PeerPublicKey,
    Endpoint,
    AllowedIps,
    PresharedKey,
    Keepalive,
}

impl Draft {
    /// An empty form with a fresh private key and a full tunnel.
    fn new() -> Draft {
        Draft {
            private_key: base64::encode_key(&noise::generate_private_key()),
            allowed_ips: "0.0.0.0/0, ::/0".to_string(),
            ..Draft::default()
        }
    }

    fn field(&mut self, field: DraftField) -> &mut String {
        match field {
            DraftField::Name => &mut self.name,
            DraftField::PrivateKey => &mut self.private_key,
            DraftField::Address => &mut self.address,
            DraftField::Dns => &mut self.dns,
            DraftField::Mtu => &mut self.mtu,
            DraftField::PeerPublicKey => &mut self.peer_public_key,
            DraftField::Endpoint => &mut self.endpoint,
            DraftField::AllowedIps => &mut self.allowed_ips,
            DraftField::PresharedKey => &mut self.preshared_key,
            DraftField::Keepalive => &mut self.keepalive,
        }
    }

    /// The public key of the private key, if that is a valid key.
    pub fn public_key(&self) -> Option<String> {
        let private = base64::decode_key(self.private_key.trim()).ok()?;
        Some(base64::encode_key(&noise::public_key(&private)))
    }

    /// The form as a wg-quick config; empty fields are left out.
    fn to_conf(&self) -> String {
        let section = |title: &str, lines: &[(&str, &String)]| {
            let mut text = format!("[{title}]\n");
            for (key, value) in lines {
                let value = value.trim();
                if !value.is_empty() {
                    text.push_str(&format!("{key} = {value}\n"));
                }
            }
            text
        };
        let interface = section(
            "Interface",
            &[("PrivateKey", &self.private_key), ("Address", &self.address), ("DNS", &self.dns), ("MTU", &self.mtu)],
        );
        let peer = section(
            "Peer",
            &[
                ("PublicKey", &self.peer_public_key),
                ("PresharedKey", &self.preshared_key),
                ("Endpoint", &self.endpoint),
                ("AllowedIPs", &self.allowed_ips),
                ("PersistentKeepalive", &self.keepalive),
            ],
        );
        format!("{interface}\n{peer}")
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Tick,
    /// A display frame while a transition runs.
    Frame(Instant),
    GoProfiles,
    GoImport,
    /// Open the Create screen with a fresh form.
    GoCreate,
    DraftChanged(DraftField, String),
    /// Replace the draft's private key with a new one.
    GenerateKey,
    CopyPrivateKey,
    CopyPublicKey,
    SaveDraft,
    ViewConfig(String),
    Delete(String),
    /// A profile row was clicked: connect, or show the running connection.
    ProfilePressed(String),
    Disconnect,
    Started(String, Result<TunnelInfo, String>),
    Stopped,
    Browse,
    Picked(Vec<PathBuf>),
    FileHovered,
    HoverLeft,
    FileDropped(PathBuf),
    DropBatchReady,
    PendingName(String),
    ToggleConnectAfter(bool),
    CancelPending,
    AddPending,
    /// The window has just opened.
    Opened(window::Id),
    /// Retry activating the app after launch.
    Activate,
    /// "Show application" in the menu-bar menu.
    ShowWindow,
    /// Open System Settings to allow the helper.
    OpenLoginItems,
    /// The system switched between light and dark mode.
    ThemeChanged(iced::theme::Mode),
    /// The accent colour was changed in System Settings.
    AccentChanged,
    /// Register the helper again after it was uninstalled.
    InstallHelper,
    /// "Uninstall Helper…" in the menu-bar menu; asks first.
    UninstallHelper,
    UninstallConfirmed(bool),
    HelperUninstalled(Result<(), String>),
    CloseRequested,
}

pub struct App {
    pub store: Option<Store>,
    pub store_error: Option<String>,
    /// Whether the root helper that brings tunnels up can be used.
    pub helper: HelperState,
    pub screen: Screen,
    pub profiles: Vec<Profile>,
    pub active: Option<Active>,
    /// Our link to the helper while a tunnel is up; the tunnel goes down
    /// when it is dropped. Shared with the worker threads that start and
    /// stop the tunnel, since both block on the helper.
    connection: Arc<Mutex<Option<HelperClient>>>,
    pub pending: Option<Pending>,
    pub import_error: Option<String>,
    pub connect_after: bool,
    pub draft: Draft,
    pub drag_over: bool,
    dropped: Vec<PathBuf>,
    /// The profile shown on the Config screen, keys masked.
    pub config_text: String,
    /// Progress of the current screen change, and the time it is drawn at.
    transition: Animation<bool>,
    /// +1 when the new screen comes from the right, -1 from the left.
    transition_direction: f32,
    now: Instant,
    toast: Option<(String, Instant)>,
    pub highlight: Option<String>,
    /// Connect to this once the current tunnel is down.
    queued: Option<String>,
    quitting: bool,
    /// The menu-bar icon; created once the window is open.
    tray: Option<tray::Tray>,
}

impl App {
    /// The initial state, and a request for the system appearance (the
    /// answer arrives as `ThemeChanged`).
    pub fn new() -> (App, Task<Message>) {
        theme::set_accent(tray::system_accent());
        let (store, store_error) = match Store::open() {
            Ok(store) => (Some(store), None),
            Err(e) => (None, Some(e)),
        };
        let profiles = store.as_ref().map(Store::list).unwrap_or_default();
        let app = App {
            store,
            store_error,
            helper: helper::ensure_registered(),
            screen: Screen::Profiles,
            profiles,
            active: None,
            connection: Arc::new(Mutex::new(None)),
            pending: None,
            import_error: None,
            connect_after: true,
            draft: Draft::default(),
            drag_over: false,
            dropped: Vec::new(),
            config_text: String::new(),
            transition: Animation::new(true),
            transition_direction: 1.0,
            now: Instant::now(),
            toast: None,
            highlight: None,
            queued: None,
            quitting: false,
            tray: None,
        };
        (app, iced::system::theme().map(Message::ThemeChanged))
    }

    pub fn toast(&self) -> Option<&str> {
        self.toast.as_ref().map(|(text, _)| text.as_str())
    }

    pub fn profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    pub fn is_active(&self, name: &str) -> bool {
        self.active.as_ref().is_some_and(|a| a.profile == name)
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        let task = self.handle(message);
        if let Some(tray) = &self.tray {
            let status = self.active.as_ref().map(|a| a.status);
            tray.set_status(status.is_some_and(|s| s != Status::Disconnecting), status == Some(Status::Connected));
        }
        task
    }

    fn handle(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => return self.tick(),
            Message::Frame(now) => self.now = now,
            Message::GoProfiles => {
                self.go(Screen::Profiles);
                self.pending = None;
                self.import_error = None;
            }
            Message::GoImport => {
                self.go(Screen::Import);
                self.pending = None;
                self.import_error = None;
            }
            Message::GoCreate => {
                self.go(Screen::Create);
                self.draft = Draft::new();
                self.import_error = None;
            }
            Message::DraftChanged(field, value) => *self.draft.field(field) = value,
            Message::GenerateKey => self.draft.private_key = base64::encode_key(&noise::generate_private_key()),
            Message::CopyPrivateKey => {
                let key = self.draft.private_key.trim().to_string();
                if !key.is_empty() {
                    self.show_toast("Private key copied".to_string());
                    return iced::clipboard::write(key);
                }
            }
            Message::CopyPublicKey => {
                if let Some(key) = self.draft.public_key() {
                    self.show_toast("Public key copied".to_string());
                    return iced::clipboard::write(key);
                }
            }
            Message::SaveDraft => return self.save_draft(),
            Message::ViewConfig(name) => {
                let Some(profile) = self.profile(&name).filter(|p| !p.stale) else {
                    return Task::none();
                };
                self.config_text = match std::fs::read_to_string(&profile.path) {
                    Ok(text) => storage::mask_keys(&text),
                    Err(e) => format!("# cannot read {}: {e}", profile.path.display()),
                };
                self.go(Screen::Config(name));
            }
            Message::Delete(name) => {
                if self.is_active(&name) {
                    return Task::none();
                }
                if let Some(store) = &self.store {
                    match store.delete(&name) {
                        Ok(()) => self.show_toast(format!("Profile “{name}” deleted")),
                        Err(e) => self.show_toast(e),
                    }
                }
                self.reload();
            }
            Message::ProfilePressed(name) => {
                if self.is_active(&name) {
                    self.go(Screen::Connection);
                } else {
                    return self.connect(name);
                }
            }
            Message::Disconnect => return self.disconnect(),
            Message::Started(name, result) => return self.started(name, result),
            Message::Stopped => return self.stopped(),
            Message::Browse => {
                let dialog = rfd::AsyncFileDialog::new().add_filter("WireGuard profile", &["conf"]);
                return Task::perform(dialog.pick_files(), |files| {
                    Message::Picked(files.unwrap_or_default().iter().map(|f| f.path().to_path_buf()).collect())
                });
            }
            Message::Picked(paths) => self.handle_files(paths),
            Message::FileHovered => self.drag_over = true,
            Message::HoverLeft => self.drag_over = false,
            Message::FileDropped(path) => {
                self.drag_over = false;
                self.dropped.push(path);
                if self.dropped.len() == 1 {
                    return Task::perform(background(|| std::thread::sleep(DROP_BATCH_DELAY)), |_| {
                        Message::DropBatchReady
                    });
                }
            }
            Message::DropBatchReady => {
                let paths = std::mem::take(&mut self.dropped);
                self.handle_files(paths);
            }
            Message::PendingName(name) => {
                if let Some(pending) = &mut self.pending {
                    pending.name = name;
                }
            }
            Message::ToggleConnectAfter(on) => self.connect_after = on,
            Message::CancelPending => self.pending = None,
            Message::AddPending => return self.add_pending(),
            Message::Opened(id) => {
                tray::set_dock_icon();
                tray::lock_window_layout();
                match tray::Tray::new() {
                    Ok(tray) => self.tray = Some(tray),
                    Err(e) => eprintln!("warning: {e}"),
                }
                // Launched from a terminal, the window would
                // otherwise open behind it. Lift it above everything once,
                // then let it behave like a normal window again. Raising
                // the window is not enough: the app must also be active, or
                // macOS keeps showing the terminal's cursor over it.
                tray::activate_app();
                return Task::batch([
                    window::set_level(id, window::Level::AlwaysOnTop),
                    window::gain_focus(id),
                ])
                .chain(window::set_level(id, window::Level::Normal))
                .chain(Task::perform(background(|| std::thread::sleep(ACTIVATE_RETRY_DELAY)), |_| {
                    Message::Activate
                }));
            }
            Message::Activate => {
                if !tray::activate_app() {
                    tray::request_attention();
                }
            }
            Message::ShowWindow => {
                tray::activate_app();
                return window::latest().and_then(|id| Task::batch([window::minimize(id, false), window::gain_focus(id)]));
            }
            Message::OpenLoginItems => helper::open_login_items(),
            Message::ThemeChanged(mode) => {
                theme::set_dark(mode == iced::theme::Mode::Dark);
                // The accent has a variant for each appearance.
                theme::set_accent(tray::system_accent());
            }
            Message::AccentChanged => theme::set_accent(tray::system_accent()),
            Message::InstallHelper => {
                self.helper = helper::ensure_registered();
                if self.helper == HelperState::NeedsApproval {
                    helper::open_login_items();
                }
            }
            Message::UninstallHelper => {
                if self.active.is_some() {
                    self.show_toast("Disconnect before uninstalling the helper".to_string());
                    return Task::none();
                }
                let dialog = rfd::AsyncMessageDialog::new()
                    .set_level(rfd::MessageLevel::Warning)
                    .set_title("Uninstall the wg-gui helper?")
                    .set_description(
                        "The helper runs as root to bring tunnels up. Uninstalling stops it and removes it from \
                         Login Items; do this before deleting wg-gui. You can install it again from the Profiles screen.",
                    )
                    .set_buttons(rfd::MessageButtons::OkCancelCustom("Uninstall".to_string(), "Cancel".to_string()));
                return Task::perform(dialog.show(), |result| {
                    Message::UninstallConfirmed(result == rfd::MessageDialogResult::Custom("Uninstall".to_string()))
                });
            }
            Message::UninstallConfirmed(false) => {}
            Message::UninstallConfirmed(true) => {
                return Task::perform(background(helper::uninstall), Message::HelperUninstalled);
            }
            Message::HelperUninstalled(result) => {
                self.helper = helper::state();
                match result {
                    Ok(()) => self.show_toast("Helper uninstalled".to_string()),
                    Err(e) => self.show_toast(e),
                }
            }
            Message::CloseRequested => {
                self.quitting = true;
                if self.active.is_none() {
                    return iced::exit();
                }
                return self.disconnect();
            }
        }
        Task::none()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let tick = iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick);
        let events = event::listen_with(|event, _status, id| match event {
            Event::Window(window::Event::Opened { .. }) => Some(Message::Opened(id)),
            Event::Window(window::Event::FileHovered(_)) => Some(Message::FileHovered),
            Event::Window(window::Event::FilesHoveredLeft) => Some(Message::HoverLeft),
            Event::Window(window::Event::FileDropped(path)) => Some(Message::FileDropped(path)),
            Event::Window(window::Event::CloseRequested) => Some(Message::CloseRequested),
            _ => None,
        });
        let frames = if self.transition.is_animating(self.now) {
            window::frames().map(Message::Frame)
        } else {
            Subscription::none()
        };
        Subscription::batch([
            tick,
            events,
            frames,
            tray::events(),
            iced::system::theme_changes().map(Message::ThemeChanged),
            tray::accent_changes(),
        ])
    }

    pub fn view(&self) -> Element<'_, Message> {
        let screen = match &self.screen {
            Screen::Profiles => screens::profiles::view(self),
            Screen::Import => screens::import::view(self),
            Screen::Create => screens::create::view(self),
            Screen::Connection => screens::connection::view(self),
            Screen::Config(name) => screens::config::view(self, name),
        };
        let mut layers = stack![self.animate(screen)].width(Length::Fill).height(Length::Fill);
        if self.drag_over {
            layers = layers.push(screens::drop_overlay());
        }
        if let Some(text) = self.toast() {
            layers = layers.push(screens::toast(text));
        }
        container(layers).style(theme::page).into()
    }

    // -- navigation ----------------------------------------------------------

    /// Switches screens with a short slide-and-fade.
    fn go(&mut self, screen: Screen) {
        if screen == self.screen {
            return;
        }
        self.transition_direction = if screen.depth() >= self.screen.depth() { 1.0 } else { -1.0 };
        self.screen = screen;
        self.now = Instant::now();
        self.transition = Animation::new(false).duration(Duration::from_millis(220)).easing(Easing::EaseOutCubic).go(true, self.now);
    }

    /// The screen shifted sideways and veiled by the page colour while the
    /// transition runs; untouched once it is over.
    fn animate<'a>(&self, screen: Element<'a, Message>) -> Element<'a, Message> {
        if !self.transition.is_animating(self.now) {
            return screen;
        }
        let progress: f32 = self.transition.interpolate(0.0, 1.0, self.now);
        let offset = (1.0 - progress) * SLIDE_DISTANCE * self.transition_direction;
        let veil = container(iced::widget::space())
            .width(Length::Fill)
            .height(Length::Fill)
            .style(theme::filled(Color { a: 1.0 - progress, ..theme::palette().bg }, 0.0));
        float(stack![screen, veil]).translate(move |_, _| Vector::new(offset, 0.0)).into()
    }

    // -- connecting --------------------------------------------------------

    fn connect(&mut self, name: String) -> Task<Message> {
        // The file may have gone since the list was read.
        if self.profile(&name).is_some_and(|p| p.stale || !p.path.exists()) {
            self.reload();
            self.show_toast(format!("The config file of “{name}” is missing"));
            return Task::none();
        }
        self.helper = helper::state();
        match &self.helper {
            HelperState::Ready => {}
            HelperState::NeedsApproval => {
                self.show_toast("Allow wg-gui in Login Items first".to_string());
                return Task::none();
            }
            HelperState::NotInstalled => {
                self.show_toast("Install the helper first".to_string());
                return Task::none();
            }
            HelperState::Missing(e) => {
                self.show_toast(e.clone());
                return Task::none();
            }
        }
        if let Some(active) = &self.active {
            // One tunnel at a time: bring the current one down first.
            if active.status != Status::Disconnecting {
                self.queued = Some(name);
                return self.disconnect();
            }
            self.queued = Some(name);
            return Task::none();
        }
        let Some(profile) = self.profile(&name) else {
            return Task::none();
        };
        let path = profile.path.clone();
        self.active = Some(Active {
            profile: name.clone(),
            status: Status::Connecting,
            info: None,
            started: None,
            history: History::default(),
            stats: Stats::default(),
            last_sample: None,
        });
        self.go(Screen::Connection);

        let slot = Arc::clone(&self.connection);
        Task::perform(
            background(move || {
                let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                let config = config::parse(&text)?;
                let mut client = HelperClient::connect()?;
                let started = client.start(&text)?;
                let info = tunnel_info(&config, started);
                *slot.lock().unwrap() = Some(client);
                Ok(info)
            }),
            move |result| Message::Started(name.clone(), result),
        )
    }

    fn started(&mut self, name: String, result: Result<TunnelInfo, String>) -> Task<Message> {
        match result {
            Ok(info) => {
                self.log(format!(
                    "connected \"{name}\" {} {} via {}",
                    info.tun_name,
                    join(&info.addresses.iter().map(|a| format!("{}/{}", a.ip, a.prefix)).collect::<Vec<_>>()),
                    info.server
                ));
                if let Some(active) = &mut self.active {
                    active.info = Some(info);
                    active.started = Some(Instant::now());
                }
                // A disconnect or quit arrived while we were starting.
                let wants_down = self.quitting
                    || self.queued.is_some()
                    || self.active.as_ref().is_some_and(|a| a.status == Status::Disconnecting);
                if wants_down {
                    if let Some(active) = &mut self.active {
                        active.status = Status::Connecting;
                    }
                    return self.disconnect();
                }
            }
            Err(e) => {
                self.log(format!("connect failed \"{name}\": {e}"));
                self.active = None;
                self.go(Screen::Profiles);
                self.show_toast(format!("Cannot connect: {e}"));
                if self.quitting {
                    return iced::exit();
                }
                if let Some(next) = self.queued.take() {
                    return self.connect(next);
                }
            }
        }
        Task::none()
    }

    fn disconnect(&mut self) -> Task<Message> {
        let Some(active) = &mut self.active else {
            return Task::none();
        };
        if active.status == Status::Disconnecting {
            return Task::none();
        }
        let still_starting = active.info.is_none();
        active.status = Status::Disconnecting;
        if still_starting {
            // `started` sees Disconnecting and comes back here.
            return Task::none();
        }
        let slot = Arc::clone(&self.connection);
        Task::perform(
            background(move || {
                if let Some(mut client) = slot.lock().unwrap().take()
                    && let Err(e) = client.stop()
                {
                    // Dropping the client closes the socket, and the
                    // helper stops the tunnel then anyway.
                    eprintln!("warning: {e}");
                }
            }),
            |_| Message::Stopped,
        )
    }

    fn stopped(&mut self) -> Task<Message> {
        if let Some(active) = self.active.take() {
            let stats = active.stats;
            self.log(format!(
                "disconnected \"{}\" after {}, rx {} tx {}",
                active.profile,
                format::duration(active.seconds()),
                format::bytes(stats.rx_bytes),
                format::bytes(stats.tx_bytes)
            ));
        }
        if self.quitting {
            return iced::exit();
        }
        if self.screen == Screen::Connection {
            self.go(Screen::Profiles);
        }
        match self.queued.take() {
            Some(next) => self.connect(next),
            None => Task::none(),
        }
    }

    fn tick(&mut self) -> Task<Message> {
        if self.toast.as_ref().is_some_and(|(_, at)| at.elapsed() >= TOAST_TIME) {
            self.toast = None;
            self.highlight = None;
        }
        if crate::stop_requested() && !self.quitting {
            return self.update(Message::CloseRequested);
        }

        if self.helper != HelperState::Ready {
            self.helper = helper::state();
        }

        let Some(active) = &mut self.active else {
            return Task::none();
        };
        if active.info.is_none() || active.status == Status::Disconnecting {
            return Task::none();
        }
        let Some(result) = self.connection.lock().unwrap().as_mut().map(HelperClient::stats) else {
            return Task::none();
        };
        let stats = match result {
            Ok(stats) => stats,
            Err(e) => {
                // The helper died or restarted; the tunnel is gone with it.
                self.connection.lock().unwrap().take();
                self.show_toast(format!("Connection lost: {e}"));
                return self.stopped();
            }
        };
        let Some(active) = &mut self.active else {
            return Task::none();
        };
        let now = Instant::now();
        if let Some((then, previous)) = active.last_sample {
            let seconds = now.duration_since(then).as_secs_f32().max(0.001);
            let rx = stats.rx_bytes.saturating_sub(previous.rx_bytes) as f32 / 1024.0 / seconds;
            let tx = stats.tx_bytes.saturating_sub(previous.tx_bytes) as f32 / 1024.0 / seconds;
            active.history.push(rx, tx);
        }
        active.last_sample = Some((now, stats));
        active.stats = stats;
        let next = match active.status {
            Status::Connecting if stats.last_handshake.is_some() => Status::Connected,
            // Once connected, the status follows the link.
            Status::Connected | Status::Reconnecting | Status::Offline => match stats.link {
                LinkState::Up => Status::Connected,
                LinkState::Stale => Status::Reconnecting,
                LinkState::Offline => Status::Offline,
            },
            status => status,
        };
        if next != active.status {
            let was_connected = active.status != Status::Connecting;
            active.status = next;
            let profile = active.profile.clone();
            match next {
                Status::Reconnecting => self.log(format!("lost contact with \"{profile}\", reconnecting")),
                Status::Offline => self.log(format!("network gone, \"{profile}\" waiting for it")),
                Status::Connected if was_connected => self.log(format!("reconnected \"{profile}\"")),
                _ => {}
            }
        }
        Task::none()
    }

    // -- importing -----------------------------------------------------------

    fn handle_files(&mut self, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }
        self.go(Screen::Import);
        self.pending = None;
        self.import_error = None;

        let confs: Vec<PathBuf> =
            paths.into_iter().filter(|p| p.extension().is_some_and(|ext| ext == "conf")).collect();
        if confs.is_empty() {
            self.import_error = Some("Only WireGuard .conf files can be imported.".to_string());
            return;
        }

        let mut read = Vec::new();
        let mut errors = Vec::new();
        for path in confs {
            let file_name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let parsed = std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|text| config::summary(&text).map(|summary| (text, summary)));
            let existing = parsed.as_ref().ok().and_then(|(text, _)| self.store.as_ref()?.find_duplicate(text));
            match parsed {
                Ok(_) if existing.is_some() => errors.push(format!(
                    "{file_name}: configuration already exists as profile “{}”",
                    existing.unwrap_or_default()
                )),
                Ok((text, summary)) => {
                    read.push(Pending { name: storage::suggested_name(&path), file_name, text, summary, source: path })
                }
                Err(e) => errors.push(format!("{file_name}: {e}")),
            }
        }
        if !errors.is_empty() {
            self.import_error = Some(errors.join("\n"));
        }

        match read.len() {
            0 => {}
            1 if errors.is_empty() => self.pending = read.pop(),
            _ => {
                let mut added = Vec::new();
                for pending in &read {
                    match self.save(pending) {
                        Ok(name) => added.push(name),
                        Err(e) => errors.push(e),
                    }
                }
                self.reload();
                self.highlight = added.last().cloned();
                if errors.is_empty() {
                    self.go(Screen::Profiles);
                } else {
                    self.import_error = Some(errors.join("\n"));
                }
                if !added.is_empty() {
                    self.show_toast(format!("{} profiles imported", added.len()));
                }
            }
        }
    }

    fn add_pending(&mut self) -> Task<Message> {
        let Some(pending) = self.pending.take() else {
            return Task::none();
        };
        let name = match self.save(&pending) {
            Ok(name) => name,
            Err(e) => {
                self.import_error = Some(e);
                self.pending = Some(pending);
                return Task::none();
            }
        };
        self.reload();
        self.highlight = Some(name.clone());
        self.go(Screen::Profiles);
        if self.connect_after {
            return self.connect(name);
        }
        self.show_toast(format!("Profile “{name}” added"));
        Task::none()
    }

    fn save_draft(&mut self) -> Task<Message> {
        let name = self.draft.name.trim().to_string();
        let text = self.draft.to_conf();
        let saved = if name.is_empty() {
            Err("Enter a profile name.".to_string())
        } else {
            config::summary(&text)
                .and_then(|_| self.store.as_ref().ok_or("no profile directory".to_string()))
                .and_then(|store| store.import(&name, &text, None))
        };
        let name = match saved {
            Ok(name) => name,
            Err(e) => {
                self.import_error = Some(e);
                return Task::none();
            }
        };
        self.import_error = None;
        self.reload();
        self.highlight = Some(name.clone());
        self.go(Screen::Profiles);
        if self.connect_after {
            return self.connect(name);
        }
        self.show_toast(format!("Profile “{name}” created"));
        Task::none()
    }

    fn save(&self, pending: &Pending) -> Result<String, String> {
        let store = self.store.as_ref().ok_or("no profile directory")?;
        let name = if pending.name.trim().is_empty() { &pending.file_name } else { &pending.name };
        store.import(name, &pending.text, Some(&pending.source))
    }

    fn reload(&mut self) {
        if let Some(store) = &self.store {
            self.profiles = store.list();
        }
    }

    fn show_toast(&mut self, text: String) {
        self.toast = Some((text, Instant::now()));
    }

    fn log(&self, event: String) {
        if let Some(store) = &self.store {
            store.log_event(&event);
        }
    }
}

fn tunnel_info(config: &config::Config, started: Started) -> TunnelInfo {
    TunnelInfo {
        tun_name: started.tun_name,
        endpoint_text: config.peer.endpoint_text.clone(),
        server: started.endpoint,
        addresses: config.addresses.clone(),
        dns: config.dns.clone(),
        dns_changed: started.dns_changed,
        mtu: started.mtu,
        routes: started.routes,
        allowed_ips: config.peer.allowed_ips.clone(),
    }
}

pub fn join(items: &[String]) -> String {
    items.join(", ")
}

/// Runs blocking work on its own thread and resolves when it is done.
fn background<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> impl Future<Output = T> {
    let (sender, receiver) = iced::futures::channel::oneshot::channel();
    std::thread::spawn(move || {
        let _ = sender.send(work());
    });
    async move { receiver.await.expect("worker thread finished without a result") }
}
