//! The screens from the mock, plus the pieces they share.

pub mod config;
pub mod connection;
pub mod import;
pub mod profiles;

use iced::widget::{Column, button, column, container, row, scrollable, space, text};
use iced::{Alignment, Color, Element, Length, Padding};

use crate::app::Message;
use crate::{icons, theme};

/// Distance from the window edges to content: titles, cards, buttons.
pub const MARGIN: f32 = 16.0;
/// Side of the square back button.
const BACK_SIZE: f32 = 36.0;

/// The 60 px white title bar, with an optional back button and trailing
/// action.
pub fn header<'a>(
    title: &'a str,
    back: Option<Message>,
    action: Option<Element<'a, Message>>,
) -> Element<'a, Message> {
    let mut content = row![].spacing(8).align_y(Alignment::Center).padding(bar_padding(0.0));
    if let Some(message) = back {
        content = content.push(back_button(message));
    }
    content = content.push(text(title).size(18).font(theme::SANS_SEMIBOLD).color(theme::TEXT).width(Length::Fill));
    if let Some(action) = action {
        content = content.push(action);
    }
    bar(container(content).height(60).align_y(Alignment::Center))
}

/// The white title bar, ruled off below.
pub fn bar<'a>(content: container::Container<'a, Message>) -> Element<'a, Message> {
    column![content.width(Length::Fill).style(theme::header), theme::rule(theme::BORDER)].into()
}

/// Title-bar padding that puts the first and last items on MARGIN.
pub fn bar_padding(vertical: f32) -> Padding {
    Padding { top: vertical, right: MARGIN, bottom: vertical, left: MARGIN }
}

/// The back chevron, centred in a small rounded square.
pub fn back_button<'a>(message: Message) -> Element<'a, Message> {
    button(container(icons::back(22.0, theme::TEXT)).center(BACK_SIZE))
        .padding(0)
        .on_press(message)
        .style(theme::icon_button)
        .into()
}


/// A vertical scroll area with a slim scrollbar.
pub fn scroll<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    scrollable(content)
        .direction(scrollable::Direction::Vertical(scrollable::Scrollbar::new().width(4).scroller_width(4).margin(2)))
        .height(Length::Fill)
        .into()
}

/// A header above a scrolling body; the shape of every screen.
pub fn page<'a>(header: Element<'a, Message>, body: Column<'a, Message>, padding: Padding) -> Element<'a, Message> {
    column![header, scroll(body.padding(padding).width(Length::Fill))]
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// The pill switch drawn in the mock. Purely visual; the surrounding
/// button does the work.
pub fn toggle<'a>(on: bool, color: Color, width: f32, height: f32) -> Element<'a, Message> {
    let knob = height - 6.0;
    let dot = container(space()).width(knob).height(knob).style(theme::filled(Color::WHITE, knob / 2.0));
    let track = container(dot)
        .padding(3)
        .width(width)
        .height(height)
        .align_y(Alignment::Center)
        .style(theme::filled(color, height / 2.0));
    if on { track.align_right(width).into() } else { track.align_left(width).into() }
}

/// A small caption/value pair, e.g. "Server IP / 203.0.113.10".
pub fn field<'a>(caption: &'a str, value: String) -> Element<'a, Message> {
    column![theme::label(caption, 12.0, theme::MUTED), theme::value(value, 13.5, theme::TEXT)]
        .spacing(2)
        .width(Length::Fill)
        .into()
}

/// A white card with a section title.
pub fn card<'a>(content: Column<'a, Message>) -> Element<'a, Message> {
    container(content.spacing(12)).padding(16).width(Length::Fill).style(theme::card(theme::BORDER, 12.0)).into()
}

pub fn error_box(message: &str) -> Element<'_, Message> {
    container(theme::label(message, 13.0, theme::ERROR))
        .padding([12, 14])
        .width(Length::Fill)
        .style(theme::filled(theme::ERROR_TINT, 8.0))
        .into()
}

pub fn drop_overlay<'a>() -> Element<'a, Message> {
    let inner = column![
        icons::download(48.0, theme::TEXT),
        text("Drop to import profiles").size(17).font(theme::SANS_SEMIBOLD).color(theme::TEXT),
        theme::label("WireGuard .conf files", 13.0, theme::MUTED),
    ]
    .spacing(12)
    .align_x(Alignment::Center);
    container(
        container(inner)
            .center(Length::Fill)
            .style(theme::dashed_zone(theme::ACCENT, Color { a: 0.94, ..Color::WHITE })),
    )
    .padding(10)
    .into()
}

pub fn toast(message: &str) -> Element<'_, Message> {
    let bubble = container(text(message).size(13.5).color(Color::WHITE)).padding([14, 16]).width(Length::Fill).style(theme::toast);
    container(bubble)
        .padding(Padding { top: 0.0, right: MARGIN, bottom: 24.0, left: MARGIN })
        .height(Length::Fill)
        .align_bottom(Length::Fill)
        .into()
}
