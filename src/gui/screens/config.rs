//! Profile Config ("View config" on a profile): the .conf file, read-only,
//! with its keys hidden. Profiles are not edited in the app; re-import a
//! changed file instead.

use iced::widget::{column, container, row, text};
use iced::{Alignment, Element, Length};

use crate::app::{App, Message};
use crate::theme;

use super::{MARGIN, back_button, bar, bar_padding, scroll};

pub fn view<'a>(app: &'a App, name: &'a str) -> Element<'a, Message> {
    let header = bar(
        container(
            row![
                back_button(Message::GoProfiles),
                column![
                    text("Profile Config").size(18).font(theme::SANS_SEMIBOLD).color(theme::TEXT),
                    text(name).size(12.5).color(theme::MUTED),
                ]
                .spacing(2)
                .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        )
        .padding(bar_padding(10.0)),
    );

    let file_name = app.profile(name).map(|p| p.path.file_name().unwrap_or_default().to_string_lossy().into_owned());
    let body = column![
        row![
            text(file_name.unwrap_or_default()).size(13).font(theme::SANS_MEDIUM).color(theme::TEXT).width(Length::Fill),
            theme::label("Read-only", 12.0, theme::MUTED),
        ]
        .align_y(Alignment::Center),
        container(text(&app.config_text).size(12.5).font(theme::MONO).color(theme::BG).line_height(1.6))
            .padding(16)
            .width(Length::Fill)
            .style(theme::filled(theme::TEXT, 10.0)),
    ]
    .spacing(12)
    .padding(MARGIN);

    column![header, scroll(body)].height(Length::Fill).into()
}
