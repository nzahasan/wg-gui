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
use wg_common::connection::Connection;
use wg_common::netconfig::Route;
use wg_common::tunnel::Stats;

use crate::graph::History;
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
    Connection,
    /// The read-only config of a profile.
    Config(String),
}

impl Screen {
    /// Depth in the navigation; deeper screens slide in from the right.
    fn depth(&self) -> u8 {
        match self {
            Screen::Profiles => 0,
            _ => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Status {
    /// Bringing the tunnel up, or up but no handshake yet.
    Connecting,
    Connected,
    Disconnecting,
}

/// What the Connection screen shows about a running tunnel. Copied out of
/// the `Connection` so it can travel in a `Message`.
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
    pub name: String,
    pub text: String,
    pub summary: config::Summary,
}

#[derive(Debug, Clone)]
pub enum Message {
    Tick,
    /// A display frame while a transition runs.
    Frame(Instant),
    GoProfiles,
    GoImport,
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
    CloseRequested,
}

pub struct App {
    pub store: Option<Store>,
    pub store_error: Option<String>,
    pub is_root: bool,
    pub screen: Screen,
    pub profiles: Vec<Profile>,
    pub active: Option<Active>,
    /// The running tunnel; shared with the worker threads that start and
    /// stop it, since both block on system commands.
    connection: Arc<Mutex<Option<Connection>>>,
    pub pending: Option<Pending>,
    pub import_error: Option<String>,
    pub connect_after: bool,
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
    pub fn new(is_root: bool) -> App {
        let (store, store_error) = match Store::open() {
            Ok(store) => (Some(store), None),
            Err(e) => (None, Some(e)),
        };
        let profiles = store.as_ref().map(Store::list).unwrap_or_default();
        App {
            store,
            store_error,
            is_root,
            screen: Screen::Profiles,
            profiles,
            active: None,
            connection: Arc::new(Mutex::new(None)),
            pending: None,
            import_error: None,
            connect_after: true,
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
        }
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
            tray.set_status(
                status.is_some_and(|s| s != Status::Disconnecting),
                status == Some(Status::Connected),
            );
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
            Message::ViewConfig(name) => {
                let Some(profile) = self.profile(&name) else {
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
                // Launched from a terminal (under sudo), the window would
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
        Subscription::batch([tick, events, frames, tray::events()])
    }

    pub fn view(&self) -> Element<'_, Message> {
        let screen = match &self.screen {
            Screen::Profiles => screens::profiles::view(self),
            Screen::Import => screens::import::view(self),
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
            .style(theme::filled(Color { a: 1.0 - progress, ..theme::BG }, 0.0));
        float(stack![screen, veil]).translate(move |_, _| Vector::new(offset, 0.0)).into()
    }

    // -- connecting --------------------------------------------------------

    fn connect(&mut self, name: String) -> Task<Message> {
        if !self.is_root {
            self.show_toast("Run wg-gui with sudo to connect".to_string());
            return Task::none();
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
                let config = config::load(&path.to_string_lossy())?;
                let connection = Connection::start(config)?;
                let info = tunnel_info(&connection);
                *slot.lock().unwrap() = Some(connection);
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
                if let Some(connection) = slot.lock().unwrap().take() {
                    connection.stop();
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

        let Some(active) = &mut self.active else {
            return Task::none();
        };
        if active.info.is_none() {
            return Task::none();
        }
        let Some(stats) = self.connection.lock().unwrap().as_ref().map(Connection::stats) else {
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
        if active.status == Status::Connecting && stats.last_handshake.is_some() {
            active.status = Status::Connected;
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
            match parsed {
                Ok((text, summary)) => {
                    read.push(Pending { name: storage::suggested_name(&path), file_name, text, summary })
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
                self.show_toast(format!("{} profiles imported", added.len()));
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

    fn save(&self, pending: &Pending) -> Result<String, String> {
        let store = self.store.as_ref().ok_or("no profile directory")?;
        let name = if pending.name.trim().is_empty() { &pending.file_name } else { &pending.name };
        store.import(name, &pending.text)
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

fn tunnel_info(connection: &Connection) -> TunnelInfo {
    let config = &connection.config;
    TunnelInfo {
        tun_name: connection.tun_name.clone(),
        endpoint_text: config.peer.endpoint_text.clone(),
        server: config.peer.endpoint,
        addresses: config.addresses.clone(),
        dns: config.dns.clone(),
        dns_changed: connection.undo.dns_changed(),
        mtu: connection.undo.mtu,
        routes: connection.undo.routes.clone(),
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
