//! The mock's inline SVG icons. They are drawn in black and tinted when
//! shown, so one handle serves every colour.

use iced::Color;
use iced::widget::svg::{self, Svg};

use crate::theme;

const ROUND: &str = r#"fill="none" stroke="black" stroke-linecap="round" stroke-linejoin="round""#;

fn icon(stroke_width: &str, body: &str) -> svg::Handle {
    let source = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" {ROUND} stroke-width="{stroke_width}">{body}</svg>"#
    );
    svg::Handle::from_memory(source.into_bytes())
}

fn show(handle: svg::Handle, size: f32, color: Color) -> Svg<'static> {
    Svg::new(handle).width(size).height(size).style(theme::tint(color))
}

const DOCUMENT: &str = r#"<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="14 3 14 9 20 9"/>"#;

pub fn upload_file(size: f32, color: Color) -> Svg<'static> {
    let body = format!(r#"{DOCUMENT}<line x1="12" y1="18" x2="12" y2="12"/><polyline points="9 14.5 12 11.5 15 14.5"/>"#);
    show(icon("1.6", &body), size, color)
}

pub fn checked_file(size: f32, color: Color) -> Svg<'static> {
    let body = format!(r#"{DOCUMENT}<polyline points="9 15 11 17 15 13"/>"#);
    show(icon("1.8", &body), size, color)
}

pub fn back(size: f32, color: Color) -> Svg<'static> {
    show(icon("2", r#"<polyline points="15 18 9 12 15 6"/>"#), size, color)
}

pub fn plus(size: f32, color: Color) -> Svg<'static> {
    show(icon("2.4", r#"<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>"#), size, color)
}

pub fn shield(size: f32, color: Color) -> Svg<'static> {
    show(icon("1.6", r#"<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/>"#), size, color)
}

pub fn download(size: f32, color: Color) -> Svg<'static> {
    show(icon("2", r#"<path d="M12 3v12"/><polyline points="7 10 12 15 17 10"/><path d="M5 21h14"/>"#), size, color)
}

pub fn trash(size: f32, color: Color) -> Svg<'static> {
    show(
        icon("2", r#"<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>"#),
        size,
        color,
    )
}

pub fn document(size: f32, color: Color) -> Svg<'static> {
    let body = format!(r#"{DOCUMENT}<line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/>"#);
    show(icon("2", &body), size, color)
}

pub fn copy(size: f32, color: Color) -> Svg<'static> {
    show(
        icon("1.8", r#"<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/>"#),
        size,
        color,
    )
}
