//! Design tokens from the mock (VPN Client.html) and the widget styles
//! built from them.

use iced::font::{Family, Weight};
use iced::widget::{button, checkbox, container, svg, text, text_input};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use iced::{Background, Border, Color, Element, Font, Length, Shadow, Theme, Vector};

/// The colours that change between light and dark mode.
#[derive(Debug)]
pub struct Palette {
    pub bg: Color,
    pub surface: Color,
    pub border: Color,
    pub text: Color,
    pub muted: Color,
    pub ok: Color,
    pub ok_border: Color,
    pub ok_tint: Color,
    pub warn: Color,
    pub warn_toggle: Color,
    pub error: Color,
    pub error_tint: Color,
    pub input_border: Color,
    pub toggle_off: Color,
    pub grid: Color,
    pub axis: Color,
    /// A profile row under the pointer.
    pub row_hover: Color,
    pub toast: Color,
    pub toast_text: Color,
    pub shadow: Color,
    /// The primary colour while macOS is set to the Multicolor accent.
    brand: Color,
}

pub const LIGHT: Palette = Palette {
    bg: Color::from_rgb8(0xF4, 0xF2, 0xF2),
    surface: Color::WHITE,
    border: Color::from_rgb8(0xE6, 0xE0, 0xE0),
    text: Color::from_rgb8(0x1F, 0x1A, 0x1B),
    muted: Color::from_rgb8(0x5E, 0x58, 0x59),
    ok: Color::from_rgb8(0x18, 0x79, 0x4E),
    ok_border: Color::from_rgb8(0xA7, 0xD7, 0xBC),
    ok_tint: Color::from_rgb8(0xE6, 0xF4, 0xEC),
    warn: Color::from_rgb8(0x8A, 0x5A, 0x00),
    warn_toggle: Color::from_rgb8(0xC9, 0x8A, 0x1A),
    error: Color::from_rgb8(0x9F, 0x1D, 0x1D),
    error_tint: Color::from_rgb8(0xFD, 0xEC, 0xEC),
    input_border: Color::from_rgb8(0xC2, 0xBA, 0xBA),
    toggle_off: Color::from_rgb8(0xC9, 0xC2, 0xC2),
    grid: Color::from_rgb8(0xF1, 0xEC, 0xEC),
    axis: Color::from_rgb8(0xDC, 0xD5, 0xD5),
    row_hover: Color::from_rgb8(0xFA, 0xF8, 0xF8),
    toast: Color::from_rgb8(0x1F, 0x1A, 0x1B),
    toast_text: Color::WHITE,
    shadow: Color::from_rgb8(0x1F, 0x1A, 0x1B),
    // The logo's coral (#FF7277, assets/icons/4-Logo/vpn-icon-dark-tile.svg), darkened
    // until white text on it is readable (4.5:1).
    brand: Color::from_rgb8(0xD4, 0x3F, 0x48),
};

/// Dark mode, after Apple's dark system colours: a near-black window
/// (#1E1E1E), slightly raised cards, labels at about 85 % and 55 % white,
/// and the brighter dark variants of green, yellow and red. Kept a little
/// warm to match the light palette.
pub const DARK: Palette = Palette {
    bg: Color::from_rgb8(0x1C, 0x1A, 0x1A),
    surface: Color::from_rgb8(0x27, 0x24, 0x24),
    border: Color::from_rgb8(0x3A, 0x35, 0x35),
    text: Color::from_rgb8(0xF2, 0xEE, 0xEE),
    muted: Color::from_rgb8(0xA8, 0xA0, 0xA1),
    ok: Color::from_rgb8(0x30, 0xD1, 0x58),
    ok_border: Color::from_rgb8(0x1F, 0x5C, 0x36),
    ok_tint: Color::from_rgb8(0x18, 0x31, 0x23),
    warn: Color::from_rgb8(0xFF, 0xD6, 0x0A),
    warn_toggle: Color::from_rgb8(0xE0, 0xA0, 0x30),
    error: Color::from_rgb8(0xFF, 0x6B, 0x63),
    error_tint: Color::from_rgb8(0x3A, 0x1D, 0x1D),
    input_border: Color::from_rgb8(0x5A, 0x53, 0x53),
    toggle_off: Color::from_rgb8(0x4A, 0x44, 0x44),
    grid: Color::from_rgb8(0x2E, 0x2A, 0x2A),
    axis: Color::from_rgb8(0x46, 0x3F, 0x3F),
    row_hover: Color::from_rgb8(0x2D, 0x29, 0x29),
    toast: Color::from_rgb8(0x3A, 0x35, 0x35),
    toast_text: Color::from_rgb8(0xF2, 0xEE, 0xEE),
    shadow: Color::BLACK,
    // The darker end of the app icon's gradient: bright enough for text on
    // the dark background, like Apple's dark systemRed.
    brand: Color::from_rgb8(0xF0, 0x56, 0x5C),
};

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

// -- accent --------------------------------------------------------------------

static DARK_MODE: AtomicBool = AtomicBool::new(false);

/// Follows the system appearance; see `Message::ThemeChanged`.
pub fn set_dark(dark: bool) {
    DARK_MODE.store(dark, Ordering::Relaxed);
}

pub fn is_dark() -> bool {
    DARK_MODE.load(Ordering::Relaxed)
}

/// The palette for the current appearance.
pub fn palette() -> &'static Palette {
    if is_dark() { &DARK } else { &LIGHT }
}

/// The accent chosen in System Settings as 0xRRGGBB, or `BRAND` for
/// Multicolor. Updated by `set_accent` while the app runs.
static ACCENT_RGB: AtomicU32 = AtomicU32::new(BRAND);
const BRAND: u32 = u32::MAX;

/// Switches the primary colour; None means the brand coral.
pub fn set_accent(color: Option<Color>) {
    let rgb = color.map_or(BRAND, |c| {
        let [r, g, b, _] = c.into_rgba8();
        u32::from_be_bytes([0, r, g, b])
    });
    ACCENT_RGB.store(rgb, Ordering::Relaxed);
}

/// The primary colour: filled buttons, focus, outgoing traffic.
pub fn accent() -> Color {
    match ACCENT_RGB.load(Ordering::Relaxed) {
        BRAND => palette().brand,
        rgb => {
            let [_, r, g, b] = rgb.to_be_bytes();
            Color::from_rgb8(r, g, b)
        }
    }
}

/// The primary colour, hovered or pressed.
pub fn accent_dark() -> Color {
    mix(accent(), Color::BLACK, 0.18)
}

/// A wash of the primary colour, for highlighted backgrounds.
pub fn accent_tint() -> Color {
    mix(accent(), palette().surface, if is_dark() { 0.8 } else { 0.9 })
}

/// The secondary colour: the primary's complement (opposite hue), with
/// its lightness adjusted so it stands out from the background at least
/// as well as the primary. Used for incoming traffic, next to outgoing
/// in the primary colour.
pub fn secondary() -> Color {
    let primary = accent();
    let (hue, saturation, lightness) = to_hsl(primary);
    // A grey (the Graphite accent) has no opposite; use the brand's.
    let (hue, saturation) = if saturation < 0.15 {
        let (brand_hue, brand_saturation, _) = to_hsl(palette().brand);
        (brand_hue, brand_saturation)
    } else {
        (hue, saturation)
    };
    let hue = (hue + 180.0) % 360.0;
    let target = luminance(primary);
    // Darker than the primary on a light background, lighter on a dark one.
    let (step, too_close): (f32, fn(f32, f32) -> bool) =
        if is_dark() { (0.01, |l, t| l < t) } else { (-0.01, |l, t| l > t) };
    let mut lightness = lightness;
    let mut color = from_hsl(hue, saturation, lightness);
    while too_close(luminance(color), target) && (0.05..=0.95).contains(&lightness) {
        lightness += step;
        color = from_hsl(hue, saturation, lightness);
    }
    color
}

/// `a` moved `amount` (0..1) of the way towards `b`.
fn mix(a: Color, b: Color, amount: f32) -> Color {
    Color::from_rgb(a.r + (b.r - a.r) * amount, a.g + (b.g - a.g) * amount, a.b + (b.b - a.b) * amount)
}

/// WCAG relative luminance.
fn luminance(c: Color) -> f32 {
    let linear = |v: f32| if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) };
    0.2126 * linear(c.r) + 0.7152 * linear(c.g) + 0.0722 * linear(c.b)
}

/// (hue in degrees, saturation, lightness)
fn to_hsl(c: Color) -> (f32, f32, f32) {
    let max = c.r.max(c.g).max(c.b);
    let min = c.r.min(c.g).min(c.b);
    let lightness = (max + min) / 2.0;
    let delta = max - min;
    if delta == 0.0 {
        return (0.0, 0.0, lightness);
    }
    let saturation = delta / (1.0 - (2.0 * lightness - 1.0).abs());
    let hue = if max == c.r {
        60.0 * ((c.g - c.b) / delta).rem_euclid(6.0)
    } else if max == c.g {
        60.0 * ((c.b - c.r) / delta + 2.0)
    } else {
        60.0 * ((c.r - c.g) / delta + 4.0)
    };
    (hue, saturation, lightness)
}

fn from_hsl(hue: f32, saturation: f32, lightness: f32) -> Color {
    let chroma = (1.0 - (2.0 * lightness - 1.0).abs()) * saturation;
    let x = chroma * (1.0 - ((hue / 60.0).rem_euclid(2.0) - 1.0).abs());
    let (r, g, b) = match hue as u32 / 60 {
        0 => (chroma, x, 0.0),
        1 => (x, chroma, 0.0),
        2 => (0.0, chroma, x),
        3 => (0.0, x, chroma),
        4 => (x, 0.0, chroma),
        _ => (chroma, 0.0, x),
    };
    let m = lightness - chroma / 2.0;
    Color::from_rgb(r + m, g + m, b + m)
}

// -- text ---------------------------------------------------------------------

pub fn label<'a>(content: impl text::IntoFragment<'a>, size: f32, color: Color) -> text::Text<'a> {
    text(content).size(size).color(color)
}

/// Chivo Mono, for a value that is entirely a number.
pub fn mono<'a>(content: impl text::IntoFragment<'a>, size: f32) -> text::Text<'a> {
    text(content).size(size).font(MONO).color(palette().text)
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
    container::Style { background: Some(palette().bg.into()), text_color: Some(palette().text), ..Default::default() }
}

pub fn header(_: &Theme) -> container::Style {
    container::Style { background: Some(palette().surface.into()), ..Default::default() }
}

pub fn card(border: Color, radius: f32) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(palette().surface.into()),
        border: Border { color: border, width: 1.0, radius: radius.into() },
        shadow: Shadow { color: Color { a: 0.06, ..palette().shadow }, offset: Vector::new(0.0, 1.0), blur_radius: 2.0 },
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
        background: Some(palette().toast.into()),
        text_color: Some(palette().toast_text),
        border: Border { radius: 10.0.into(), ..Default::default() },
        shadow: Shadow { color: Color { a: 0.25, ..palette().shadow }, offset: Vector::new(0.0, 6.0), blur_radius: 16.0 },
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
        button::Status::Hovered | button::Status::Pressed => Some(palette().grid.into()),
        _ => None,
    };
    button::Style { background, text_color: palette().text, border: Border::default().rounded(8), ..Default::default() }
}

/// The clickable body of a profile card: rounded only at the top, where
/// it meets the card's corners, and inset so the border stays visible.
pub fn row_button(_: &Theme, status: button::Status) -> button::Style {
    let background = match status {
        button::Status::Hovered | button::Status::Pressed => Some(palette().row_hover.into()),
        _ => None,
    };
    let radius = iced::border::Radius { top_left: 9.0, top_right: 9.0, bottom_right: 0.0, bottom_left: 0.0 };
    button::Style { background, text_color: palette().text, border: Border { radius, ..Border::default() }, ..Default::default() }
}

/// Filled accent pill (BROWSE, ADD, DELETE).
pub fn pill_primary(_: &Theme, status: button::Status) -> button::Style {
    let color = match status {
        button::Status::Hovered | button::Status::Pressed => accent_dark(),
        button::Status::Disabled => palette().toggle_off,
        button::Status::Active => accent(),
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
        button::Status::Hovered | button::Status::Pressed => palette().grid,
        _ => palette().surface,
    };
    button::Style {
        background: Some(background.into()),
        text_color: palette().text,
        border: Border { color: palette().input_border, width: 1.0, radius: 22.0.into() },
        ..Default::default()
    }
}

/// The "add profile" button in the title bar: a small rounded square.
pub fn add_button(_: &Theme, status: button::Status) -> button::Style {
    let color = match status {
        button::Status::Hovered | button::Status::Pressed => accent_dark(),
        _ => accent(),
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
    button::Style { text_color: palette().text, ..Default::default() }
}

// -- inputs --------------------------------------------------------------------

pub fn input(_: &Theme, status: text_input::Status) -> text_input::Style {
    let border = match status {
        text_input::Status::Focused { .. } => accent(),
        _ => palette().input_border,
    };
    text_input::Style {
        background: Background::Color(palette().surface),
        border: Border { color: border, width: 1.0, radius: 8.0.into() },
        icon: palette().muted,
        placeholder: palette().muted,
        value: palette().text,
        selection: accent_tint(),
    }
}

pub fn check(_: &Theme, status: checkbox::Status) -> checkbox::Style {
    let checked = match status {
        checkbox::Status::Active { is_checked }
        | checkbox::Status::Hovered { is_checked }
        | checkbox::Status::Disabled { is_checked } => is_checked,
    };
    checkbox::Style {
        background: Background::Color(if checked { accent() } else { palette().surface }),
        icon_color: Color::WHITE,
        border: Border { color: if checked { accent() } else { palette().input_border }, width: 1.0, radius: 4.0.into() },
        text_color: Some(palette().text),
    }
}

pub fn tint(color: Color) -> impl Fn(&Theme, svg::Status) -> svg::Style {
    move |_, _| svg::Style { color: Some(color) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accent and appearance are global; tests that change them take
    /// turns.
    static GLOBALS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn hex(c: Color) -> String {
        let [r, g, b, _] = c.into_rgba8();
        format!("#{r:02X}{g:02X}{b:02X}")
    }

    fn contrast(a: Color, b: Color) -> f32 {
        let (hi, lo) = (luminance(a).max(luminance(b)), luminance(a).min(luminance(b)));
        (hi + 0.05) / (lo + 0.05)
    }

    #[test]
    fn hsl_round_trips() {
        for c in [LIGHT.brand, Color::from_rgb8(0x00, 0x7A, 0xFF), Color::from_rgb8(0x62, 0xBA, 0x46), Color::WHITE] {
            let (h, s, l) = to_hsl(c);
            assert_eq!(hex(from_hsl(h, s, l)), hex(c));
        }
    }

    #[test]
    fn accents_and_complements() {
        let _turn = GLOBALS.lock().unwrap();
        // The brand coral carries white text.
        assert!(contrast(LIGHT.brand, Color::WHITE) >= 4.5);

        // Approximate macOS accents: blue, purple, pink, red, orange,
        // yellow, green, graphite; plus Multicolor (the brand).
        let accents = [
            None,
            Some(Color::from_rgb8(0x00, 0x7A, 0xFF)),
            Some(Color::from_rgb8(0xA5, 0x50, 0xA7)),
            Some(Color::from_rgb8(0xF7, 0x4F, 0x9E)),
            Some(Color::from_rgb8(0xE0, 0x38, 0x3E)),
            Some(Color::from_rgb8(0xF7, 0x82, 0x1B)),
            Some(Color::from_rgb8(0xFF, 0xC6, 0x00)),
            Some(Color::from_rgb8(0x62, 0xBA, 0x46)),
            Some(Color::from_rgb8(0x8C, 0x8C, 0x8C)),
        ];
        for accent_color in accents {
            set_accent(accent_color);
            let (primary, second) = (accent(), secondary());
            println!("primary {} secondary {} (contrast on white {:.1})", hex(primary), hex(second), contrast(second, Color::WHITE));
            assert!(luminance(second) <= luminance(primary) + 0.001);
            let hue_gap = (to_hsl(primary).0 - to_hsl(second).0).abs();
            if to_hsl(primary).1 >= 0.15 {
                assert!((hue_gap - 180.0).abs() < 2.0, "hue gap {hue_gap}");
            }
        }
        set_accent(None);
        assert_eq!(hex(accent()), "#D43F48");
    }

    #[test]
    fn dark_mode_switches_palette_and_secondary() {
        let _turn = GLOBALS.lock().unwrap();
        set_dark(true);
        set_accent(None);
        assert_eq!(hex(palette().bg), hex(DARK.bg));
        assert_eq!(hex(accent()), "#F0565C");
        let (primary, second) = (accent(), secondary());
        println!("dark: primary {} secondary {}", hex(primary), hex(second));
        // On a dark background the complement is made no darker than the primary.
        assert!(luminance(second) + 0.001 >= luminance(primary));
        // Text stays readable on the dark surfaces.
        assert!(contrast(DARK.text, DARK.surface) >= 7.0);
        assert!(contrast(DARK.muted, DARK.surface) >= 4.5);
        assert!(contrast(LIGHT.muted, LIGHT.surface) >= 4.5);
        set_dark(false);
        assert_eq!(hex(palette().bg), hex(LIGHT.bg));
    }
}
