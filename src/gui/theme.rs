//! Design tokens from the mock (VPN Client.html) and the widget styles
//! built from them.

use iced::font::{Family, Weight};
use iced::widget::{button, checkbox, container, svg, text, text_input};
use iced::{Background, Border, Color, Element, Font, Length, Shadow, Theme, Vector};

pub const BG: Color = Color::from_rgb8(0xF4, 0xF2, 0xF2);
pub const SURFACE: Color = Color::WHITE;
pub const BORDER: Color = Color::from_rgb8(0xE6, 0xE0, 0xE0);
pub const TEXT: Color = Color::from_rgb8(0x1F, 0x1A, 0x1B);
pub const MUTED: Color = Color::from_rgb8(0x5E, 0x58, 0x59);
pub const ACCENT: Color = Color::from_rgb8(0x88, 0x17, 0x1A);
pub const ACCENT_DARK: Color = Color::from_rgb8(0x5E, 0x0F, 0x11);
pub const ACCENT_TINT: Color = Color::from_rgb8(0xF9, 0xED, 0xED);
pub const OK: Color = Color::from_rgb8(0x18, 0x79, 0x4E);
pub const OK_BORDER: Color = Color::from_rgb8(0xA7, 0xD7, 0xBC);
pub const OK_TINT: Color = Color::from_rgb8(0xE6, 0xF4, 0xEC);
pub const WARN: Color = Color::from_rgb8(0x8A, 0x5A, 0x00);
pub const WARN_TOGGLE: Color = Color::from_rgb8(0xC9, 0x8A, 0x1A);
pub const ERROR: Color = Color::from_rgb8(0x9F, 0x1D, 0x1D);
pub const ERROR_TINT: Color = Color::from_rgb8(0xFD, 0xEC, 0xEC);
pub const INPUT_BORDER: Color = Color::from_rgb8(0xC2, 0xBA, 0xBA);
pub const TOGGLE_OFF: Color = Color::from_rgb8(0xC9, 0xC2, 0xC2);
pub const GRID: Color = Color::from_rgb8(0xF1, 0xEC, 0xEC);
pub const AXIS: Color = Color::from_rgb8(0xDC, 0xD5, 0xD5);
/// Incoming traffic: a brighter green than OK, so it reads as data, not status.
pub const INCOMING: Color = Color::from_rgb8(0x1F, 0xA0, 0x6A);

pub const SANS_REGULAR_TTF: &[u8] = include_bytes!("../../assets/fonts/IBMPlexSans-Regular.ttf");
pub const SANS_MEDIUM_TTF: &[u8] = include_bytes!("../../assets/fonts/IBMPlexSans-Medium.ttf");
pub const SANS_SEMIBOLD_TTF: &[u8] = include_bytes!("../../assets/fonts/IBMPlexSans-SemiBold.ttf");
pub const SANS_BOLD_TTF: &[u8] = include_bytes!("../../assets/fonts/IBMPlexSans-Bold.ttf");
pub const MONO_REGULAR_TTF: &[u8] = include_bytes!("../../assets/fonts/ChivoMono-Regular.ttf");
pub const MONO_MEDIUM_TTF: &[u8] = include_bytes!("../../assets/fonts/ChivoMono-Medium.ttf");

const fn font(family: &'static str, weight: Weight) -> Font {
    Font { family: Family::Name(family), weight, ..Font::DEFAULT }
}

pub const SANS: Font = font("IBM Plex Sans", Weight::Normal);
pub const SANS_MEDIUM: Font = font("IBM Plex Sans", Weight::Medium);
pub const SANS_SEMIBOLD: Font = font("IBM Plex Sans", Weight::Semibold);
pub const SANS_BOLD: Font = font("IBM Plex Sans", Weight::Bold);
pub const MONO: Font = font("Chivo Mono", Weight::Normal);
pub const MONO_MEDIUM: Font = font("Chivo Mono", Weight::Medium);

// -- text ---------------------------------------------------------------------

pub fn label<'a>(content: impl text::IntoFragment<'a>, size: f32, color: Color) -> text::Text<'a> {
    text(content).size(size).color(color)
}

/// Chivo Mono, for a value that is entirely a number.
pub fn mono<'a>(content: impl text::IntoFragment<'a>, size: f32) -> text::Text<'a> {
    text(content).size(size).font(MONO).color(TEXT)
}

/// A value such as "612.0 MB", "UDP 51820" or "vpn.example.org": numbers
/// (including addresses and times) in Chivo Mono, words in Plex Sans.
pub fn value<'a, M: 'a>(content: impl AsRef<str>, size: f32, color: Color) -> Element<'a, M> {
    let words: Vec<Element<'a, M>> = content
        .as_ref()
        .split(' ')
        .filter(|word| !word.is_empty())
        .map(|word| {
            let font = if is_numeric(word) { MONO } else { SANS };
            text(word.to_string()).size(size).font(font).color(color).into()
        })
        .collect();
    iced::widget::Row::with_children(words).spacing(size * 0.3).into()
}

/// Digits first ("51820", "10.8.0.6/32", "00:12:34", "1,234") or an IPv6
/// address ("fd00::1/64").
fn is_numeric(word: &str) -> bool {
    let word = word.trim_end_matches(',');
    word.starts_with(|c: char| c.is_ascii_digit())
        || word.split('/').next().is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok())
}

/// Upper-case, letter-spaced section heading such as "CONNECTED".
pub fn section<'a>(content: &'a str, color: Color) -> text::Text<'a> {
    text(content).size(12).font(SANS_SEMIBOLD).color(color)
}

// -- containers ----------------------------------------------------------------

pub fn page(_: &Theme) -> container::Style {
    container::Style { background: Some(BG.into()), text_color: Some(TEXT), ..Default::default() }
}

pub fn header(_: &Theme) -> container::Style {
    container::Style { background: Some(SURFACE.into()), ..Default::default() }
}

pub fn card(border: Color, radius: f32) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(SURFACE.into()),
        border: Border { color: border, width: 1.0, radius: radius.into() },
        shadow: Shadow { color: Color { a: 0.06, ..TEXT }, offset: Vector::new(0.0, 1.0), blur_radius: 2.0 },
        ..Default::default()
    }
}

pub fn filled(color: Color, radius: f32) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(color.into()),
        border: Border { radius: radius.into(), ..Default::default() },
        ..Default::default()
    }
}

pub fn dashed_zone(border: Color, fill: Color) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(fill.into()),
        border: Border { color: border, width: 2.0, radius: 14.0.into() },
        ..Default::default()
    }
}

pub fn toast(_: &Theme) -> container::Style {
    container::Style {
        background: Some(TEXT.into()),
        text_color: Some(Color::WHITE),
        border: Border { radius: 10.0.into(), ..Default::default() },
        shadow: Shadow { color: Color { a: 0.25, ..TEXT }, offset: Vector::new(0.0, 6.0), blur_radius: 16.0 },
        ..Default::default()
    }
}

/// A one-pixel horizontal rule.
pub fn rule<'a, M: 'a>(color: Color) -> Element<'a, M> {
    container(iced::widget::space()).width(Length::Fill).height(1).style(filled(color, 0.0)).into()
}

// -- buttons -------------------------------------------------------------------

/// Borderless 44×44 icon button with a light hover wash.
pub fn icon_button(_: &Theme, status: button::Status) -> button::Style {
    let background = match status {
        button::Status::Hovered | button::Status::Pressed => Some(GRID.into()),
        _ => None,
    };
    button::Style { background, text_color: TEXT, border: Border::default().rounded(8), ..Default::default() }
}

/// The clickable body of a profile card: rounded only at the top, where
/// it meets the card's corners, and inset so the border stays visible.
pub fn row_button(_: &Theme, status: button::Status) -> button::Style {
    let background = match status {
        button::Status::Hovered | button::Status::Pressed => Some(Color::from_rgb8(0xFA, 0xF8, 0xF8).into()),
        _ => None,
    };
    let radius = iced::border::Radius { top_left: 9.0, top_right: 9.0, bottom_right: 0.0, bottom_left: 0.0 };
    button::Style { background, text_color: TEXT, border: Border { radius, ..Border::default() }, ..Default::default() }
}

/// Filled accent pill (BROWSE, ADD, DELETE).
pub fn pill_primary(_: &Theme, status: button::Status) -> button::Style {
    let color = match status {
        button::Status::Hovered | button::Status::Pressed => ACCENT_DARK,
        button::Status::Disabled => TOGGLE_OFF,
        button::Status::Active => ACCENT,
    };
    button::Style {
        background: Some(color.into()),
        text_color: Color::WHITE,
        border: Border::default().rounded(22),
        ..Default::default()
    }
}

/// Outlined pill (CANCEL).
pub fn pill_secondary(_: &Theme, status: button::Status) -> button::Style {
    let background = match status {
        button::Status::Hovered | button::Status::Pressed => GRID,
        _ => SURFACE,
    };
    button::Style {
        background: Some(background.into()),
        text_color: TEXT,
        border: Border { color: INPUT_BORDER, width: 1.0, radius: 22.0.into() },
        ..Default::default()
    }
}

/// The "add profile" button in the title bar: a small rounded square.
pub fn add_button(_: &Theme, status: button::Status) -> button::Style {
    let color = match status {
        button::Status::Hovered | button::Status::Pressed => ACCENT_DARK,
        _ => ACCENT,
    };
    button::Style {
        background: Some(color.into()),
        text_color: Color::WHITE,
        border: Border::default().rounded(8),
        ..Default::default()
    }
}

/// A button that only exists for its content (the status-card toggle).
pub fn bare(_: &Theme, _: button::Status) -> button::Style {
    button::Style { text_color: TEXT, ..Default::default() }
}

// -- inputs --------------------------------------------------------------------

pub fn input(_: &Theme, status: text_input::Status) -> text_input::Style {
    let border = match status {
        text_input::Status::Focused { .. } => ACCENT,
        _ => INPUT_BORDER,
    };
    text_input::Style {
        background: Background::Color(SURFACE),
        border: Border { color: border, width: 1.0, radius: 8.0.into() },
        icon: MUTED,
        placeholder: MUTED,
        value: TEXT,
        selection: ACCENT_TINT,
    }
}

pub fn check(_: &Theme, status: checkbox::Status) -> checkbox::Style {
    let checked = match status {
        checkbox::Status::Active { is_checked }
        | checkbox::Status::Hovered { is_checked }
        | checkbox::Status::Disabled { is_checked } => is_checked,
    };
    checkbox::Style {
        background: Background::Color(if checked { ACCENT } else { SURFACE }),
        icon_color: Color::WHITE,
        border: Border { color: if checked { ACCENT } else { INPUT_BORDER }, width: 1.0, radius: 4.0.into() },
        text_color: Some(TEXT),
    }
}

pub fn tint(color: Color) -> impl Fn(&Theme, svg::Status) -> svg::Style {
    move |_, _| svg::Style { color: Some(color) }
}
