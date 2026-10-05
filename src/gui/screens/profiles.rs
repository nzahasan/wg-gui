//! Screen 1 · Profiles: connected profile on top, the rest below.

use iced::widget::{Column, button, column, container, row, space, stack, text};
use iced::{Alignment, Element, Length, Padding};

use crate::app::{App, Message, Status};
use crate::storage::Profile;
use crate::{format, icons, theme};

use super::{MARGIN, bar, bar_padding, error_box, page, toggle};

pub fn view(app: &App) -> Element<'_, Message> {
    let add = button(container(icons::plus(18.0, iced::Color::WHITE)).center(34))
        .padding(0)
        .on_press(Message::GoImport)
        .style(theme::add_button);
    let header = bar(
        container(
            row![
                text("Profiles").size(18).font(theme::SANS_SEMIBOLD).color(theme::TEXT).width(Length::Fill),
                add,
            ]
            .spacing(10)
            .align_y(Alignment::Center)
            .padding(bar_padding(0.0)),
        )
        .height(60)
        .align_y(Alignment::Center),
    );

    let mut body = Column::new().spacing(10);
    if !app.is_root {
        body = body.push(error_box("Not running as root. Start with: sudo wg-gui"));
    }
    if let Some(e) = &app.store_error {
        body = body.push(error_box(e));
    }

    let (connected, others): (Vec<&Profile>, Vec<&Profile>) =
        app.profiles.iter().partition(|p| app.is_active(&p.name));

    if !connected.is_empty() {
        body = body.push(theme::section("CONNECTED", theme::OK));
        for profile in connected {
            body = body.push(profile_row(app, profile, true));
        }
        body = body.push(container(iced::widget::space()).height(8));
    }
    if !others.is_empty() {
        body = body.push(theme::section("DISCONNECTED", theme::MUTED));
        for profile in others {
            body = body.push(profile_row(app, profile, false));
        }
    }
    if app.profiles.is_empty() {
        body = body.push(
            column![
                icons::shield(40.0, theme::MUTED),
                text("No profiles yet").size(16).font(theme::SANS_SEMIBOLD).color(theme::TEXT),
                container(
                    theme::label("Drag and drop WireGuard .conf files anywhere in this window, or press + to import one.", 14.0, theme::MUTED)
                        .align_x(Alignment::Center)
                )
                .max_width(280),
            ]
            .spacing(10)
            .align_x(Alignment::Center)
            .width(Length::Fill)
            .padding(Padding { top: 80.0, ..Padding::ZERO }),
        );
    }
    // The empty state already explains importing; the tip is for later.
    if !app.profiles.is_empty() {
        body = body.push(
            column![
                icons::download(16.0, theme::MUTED),
                theme::label("Tip: drop one or more .conf files on this window to import them.", 12.5, theme::MUTED)
                    .align_x(Alignment::Center),
            ]
            .spacing(6)
            .align_x(Alignment::Center)
            .width(Length::Fill)
            .padding(Padding { top: 14.0, ..Padding::ZERO }),
        );
    }

    page(header, body, Padding { top: 20.0, right: MARGIN, bottom: 28.0, left: MARGIN })
}

fn profile_row<'a>(app: &'a App, profile: &'a Profile, connected: bool) -> Element<'a, Message> {
    // Host in Plex Sans, the port (a number) in Chivo Mono.
    let meta: Element<'a, Message> = match &profile.summary {
        Ok(s) => row![
            text(format!("{} · UDP ", s.host)).size(12.5).color(theme::MUTED),
            theme::mono(s.port.to_string(), 12.5).color(theme::MUTED),
        ]
        .into(),
        Err(e) => theme::label(format!("Invalid config: {e}"), 12.5, theme::ERROR).into(),
    };

    let mut lines = column![text(&profile.name).size(15).font(theme::SANS_SEMIBOLD).color(theme::TEXT)].spacing(3);
    if connected {
        let active = app.active.as_ref().expect("connected implies active");
        let status: Element<'a, Message> = match active.status {
            Status::Connected => row![
                text("Connected · ").size(12.5).font(theme::SANS_MEDIUM).color(theme::OK),
                text(format::duration(active.seconds())).size(12.5).font(theme::MONO_MEDIUM).color(theme::OK),
            ]
            .into(),
            Status::Connecting => text("Connecting…").size(12.5).font(theme::SANS_MEDIUM).color(theme::OK).into(),
            Status::Disconnecting => text("Disconnecting…").size(12.5).font(theme::SANS_MEDIUM).color(theme::MUTED).into(),
        };
        lines = lines.push(status);
    }
    lines = lines.push(meta);

    let (track, border) = if connected {
        let up = app.active.as_ref().is_some_and(|a| a.status == Status::Connected);
        (if up { theme::ACCENT } else { theme::WARN_TOGGLE }, theme::OK_BORDER)
    } else if app.highlight.as_deref() == Some(profile.name.as_str()) {
        (theme::TOGGLE_OFF, theme::ACCENT)
    } else {
        (theme::TOGGLE_OFF, theme::BORDER)
    };

    // The card body opens the connection (or connects); the toggle sits on
    // top of it as its own button, so a click on it never reaches the body.
    let body = button(
        row![lines.width(Length::Fill), space().width(TOGGLE_WIDTH)]
            .spacing(14)
            .align_y(Alignment::Center)
            .padding(Padding { top: 14.0, right: CARD_INSET, bottom: 10.0, left: CARD_INSET }),
    )
    .padding(0)
    .width(Length::Fill)
    .on_press(Message::ProfilePressed(profile.name.clone()))
    .style(theme::row_button);

    let switch_message = if connected {
        app.active.as_ref().filter(|a| a.status != Status::Disconnecting).map(|_| Message::Disconnect)
    } else {
        Some(Message::ProfilePressed(profile.name.clone()))
    };
    let switch = button(toggle(connected, track, TOGGLE_WIDTH, 24.0))
        .padding([6, 0])
        .on_press_maybe(switch_message)
        .style(theme::bare);
    let switch_layer = container(switch)
        .align_right(Length::Fill)
        .center_y(Length::Fill)
        .padding(Padding { right: CARD_INSET, ..Padding::ZERO });

    let mut actions = row![action(icons::document(16.0, theme::TEXT), "View config", theme::TEXT, Message::ViewConfig(profile.name.clone()))]
        .spacing(4)
        .align_y(Alignment::Center);
    if !connected {
        actions = actions.push(action(icons::trash(16.0, theme::ACCENT), "Delete", theme::ACCENT, Message::Delete(profile.name.clone())));
    }

    // The 1 px padding keeps the hover wash inside the border.
    container(column![
        stack![body, switch_layer],
        theme::rule(theme::GRID),
        // Action buttons have 10 px of their own padding; together they
        // put the icons in line with the profile name.
        container(actions).padding(Padding { top: 6.0, right: CARD_INSET - 10.0, bottom: 6.0, left: CARD_INSET - 10.0 }),
    ])
    .padding(1)
    .width(Length::Fill)
    .style(theme::card(border, 10.0))
    .into()
}

const TOGGLE_WIDTH: f32 = 44.0;
/// Inner margin of a profile card (inside its 1 px padding).
const CARD_INSET: f32 = 16.0;

/// A small text button with an icon, in the row's action bar.
fn action<'a>(icon: iced::widget::Svg<'a>, label: &'a str, color: iced::Color, message: Message) -> Element<'a, Message> {
    button(
        container(row![icon, text(label).size(13).font(theme::SANS_MEDIUM)].spacing(6).align_y(Alignment::Center))
            .center_y(32)
            .padding([0, 10]),
    )
    .padding(0)
    .on_press(message)
    .style(move |theme, status| iced::widget::button::Style { text_color: color, ..theme::icon_button(theme, status) })
    .into()
}
