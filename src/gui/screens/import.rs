//! Screen 2 · Import profile: a drop zone with BROWSE, then a review card
//! for a single file.

use iced::widget::{Column, button, checkbox, column, container, row, space, text, text_input};
use iced::{Alignment, Element, Length, Padding};

use crate::app::{App, Message};
use crate::{icons, theme};

use super::{MARGIN, error_box, header, page};

pub fn view(app: &App) -> Element<'_, Message> {
    let header = header("Import Profile", Some(Message::GoProfiles), None);
    let mut body = Column::new().spacing(16);

    if app.pending.is_none() {
        let (border, fill) = if app.drag_over { (theme::accent(), theme::accent_tint()) } else { (theme::palette().input_border, theme::palette().surface) };
        let zone = column![
            icons::upload_file(48.0, theme::palette().muted),
            text("Drag and drop to upload .conf profile").size(16).font(theme::SANS_SEMIBOLD).color(theme::palette().text),
            container(
                theme::label("Drop one file to review it before adding, or several files to add them all at once.", 13.0, theme::palette().muted)
                    .align_x(Alignment::Center),
            )
            .max_width(300),
            container(pill("BROWSE", Message::Browse, theme::pill_primary)).padding(Padding { top: 6.0, ..Padding::ZERO }),
        ]
        .spacing(14)
        .align_x(Alignment::Center);
        body = body.push(container(zone).padding(24).center_x(Length::Fill).height(300).align_y(Alignment::Center).style(theme::dashed_zone(border, fill)));
        body = body.push(theme::label(
            "Supported: WireGuard configuration files (.conf) with one [Peer].",
            12.5,
            theme::palette().muted,
        ));
    }

    if let Some(error) = &app.import_error {
        body = body.push(error_box(error));
    }

    if let Some(pending) = &app.pending {
        let file_card = container(
            row![
                icons::checked_file(28.0, theme::palette().ok),
                column![
                    text(&pending.file_name).size(13.5).font(theme::SANS_SEMIBOLD).color(theme::palette().text),
                    theme::label("Profile successfully read", 12.5, theme::palette().ok),
                ]
                .spacing(2),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        )
        .padding(16)
        .width(Length::Fill)
        .style(theme::card(theme::palette().border, 12.0));

        let name_input = text_input("Profile name", &pending.name)
            .on_input(Message::PendingName)
            .on_submit(Message::AddPending)
            .padding([13, 14])
            .size(15)
            .style(theme::input);

        let tiles = row![
            tile("Server hostname", pending.summary.host.clone()),
            tile("Protocol / port", format!("UDP {}", pending.summary.port)),
        ]
        .spacing(12);

        let connect_after = checkbox(app.connect_after)
            .label("Connect after import")
            .on_toggle(Message::ToggleConnectAfter)
            .size(20)
            .spacing(12)
            .text_size(14)
            .style(theme::check);

        let actions = row![
            space().width(Length::Fill),
            pill("CANCEL", Message::CancelPending, theme::pill_secondary),
            pill("ADD", Message::AddPending, theme::pill_primary),
        ]
        .spacing(12);

        body = body
            .push(theme::section("IMPORTED PROFILE", theme::palette().muted))
            .push(file_card)
            .push(text("Profile Name").size(13).font(theme::SANS_SEMIBOLD).color(theme::palette().text))
            .push(name_input)
            .push(tiles)
            .push(container(connect_after).height(44).align_y(Alignment::Center))
            .push(container(actions).padding(Padding { top: 8.0, ..Padding::ZERO }));
    }

    page(header, body, Padding { top: 24.0, right: MARGIN, bottom: 24.0, left: MARGIN })
}

fn tile<'a>(caption: &'a str, value: String) -> Element<'a, Message> {
    container(column![theme::label(caption, 12.0, theme::palette().muted), theme::value(value, 13.0, theme::palette().text)].spacing(4))
        .padding(12)
        .width(Length::Fill)
        .style(theme::card(theme::palette().border, 8.0))
        .into()
}

pub fn pill<'a>(
    label: &'a str,
    message: Message,
    style: fn(&iced::Theme, button::Status) -> button::Style,
) -> Element<'a, Message> {
    button(container(text(label).size(13).font(theme::SANS_SEMIBOLD)).center_y(44).padding([0, 26]))
        .padding(0)
        .on_press(message)
        .style(style)
        .into()
}
