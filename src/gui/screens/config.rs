//! Profile Config ("View config" on a profile): the .conf file, read-only,
//! with its keys hidden. Profiles are not edited in the app; re-import a
//! changed file instead.

use iced::widget::{Column, column, container, row, text};
use iced::{Alignment, Color, Element, Length};

use crate::app::{App, Message};
use crate::theme;

use super::{MARGIN, back_button, bar, bar_padding, scroll};

pub fn view<'a>(app: &'a App, name: &'a str) -> Element<'a, Message> {
    let header = bar(
        container(
            row![
                back_button(Message::GoProfiles),
                column![
                    text("Profile Config").size(18).font(theme::SANS_SEMIBOLD).color(theme::palette().text),
                    text(name).size(12.5).color(theme::palette().muted),
                ]
                .spacing(2)
                .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        )
        .padding(bar_padding(10.0)),
    );

    let profile = app.profile(name);
    let file_name = profile.map(|p| p.path.file_name().unwrap_or_default().to_string_lossy().into_owned());
    let mut body = Column::new().spacing(12).padding(MARGIN).push(
        row![
            text(file_name.unwrap_or_default()).size(13).font(theme::SANS_MEDIUM).color(theme::palette().text).width(Length::Fill),
            theme::label("Read-only", 12.0, theme::palette().muted),
        ]
        .align_y(Alignment::Center),
    );
    // Where the copy came from, as recorded in the index.
    let origin: Vec<String> = profile
        .into_iter()
        .flat_map(|p| {
            [p.added.as_ref().map(|added| format!("Added {added}")), p.comment.clone()]
        })
        .flatten()
        .collect();
    if !origin.is_empty() {
        body = body.push(theme::label(origin.join("\n"), 12.0, theme::palette().muted));
    }
    // Black in both appearances, like a terminal.
    let body = body.push(
        container(text(&app.config_text).size(12.5).font(theme::MONO).color(theme::LIGHT.bg).line_height(1.6))
            .padding(16)
            .width(Length::Fill)
            .style(theme::filled(Color::BLACK, 10.0)),
    );

    column![header, scroll(body)].height(Length::Fill).into()
}
