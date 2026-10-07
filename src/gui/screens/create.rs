//! Create profile: a form for typing a profile in by hand, with a
//! generated key pair.

use iced::widget::{Column, button, checkbox, column, container, row, space, text, text_input, tooltip};
use iced::{Alignment, Element, Length, Padding};

use crate::app::{App, DraftField, Message};
use crate::{icons, theme};

use super::import::pill;
use super::{MARGIN, error_box, header, page};

pub fn view(app: &App) -> Element<'_, Message> {
    let header = header("Create Profile", Some(Message::GoImport), None);
    let draft = &app.draft;

    let public_key = draft.public_key();
    let copy_public = copy_button("Copy public key", public_key.as_ref().map(|_| Message::CopyPublicKey));
    let public_key = container(theme::mono(public_key.unwrap_or_else(|| "—".to_string()), 12.5))
        .padding([13, 14])
        .width(Length::Fill)
        .style(theme::card(theme::palette().border, 8.0));

    let generate = button(text("GENERATE").size(12).font(theme::SANS_SEMIBOLD))
        .padding([6, 12])
        .on_press(Message::GenerateKey)
        .style(theme::pill_secondary);
    let copy_private =
        copy_button("Copy private key", (!draft.private_key.trim().is_empty()).then_some(Message::CopyPrivateKey));
    // The public key follows from the private key, so it comes second.
    let private_caption =
        row![caption("Private Key"), space().width(Length::Fill), generate, copy_private].spacing(6).align_y(Alignment::Center);
    let public_caption =
        row![caption("Public Key"), space().width(Length::Fill), copy_public].spacing(6).align_y(Alignment::Center);

    let connect_after = checkbox(app.connect_after)
        .label("Connect after saving")
        .on_toggle(Message::ToggleConnectAfter)
        .size(20)
        .spacing(12)
        .text_size(14)
        .style(theme::check);

    let actions = row![
        space().width(Length::Fill),
        pill("CANCEL", Message::GoImport, theme::pill_secondary),
        pill("SAVE", Message::SaveDraft, theme::pill_primary),
    ]
    .spacing(12);

    let mut body = Column::new()
        .spacing(16)
        .push(field("Profile Name", input("e.g. Office VPN", &draft.name, DraftField::Name)))
        .push(section("INTERFACE"))
        .push(column![private_caption, input("Private key", &draft.private_key, DraftField::PrivateKey)].spacing(8))
        .push(column![public_caption, public_key].spacing(8))
        .push(field("Address", input("10.0.0.2/32", &draft.address, DraftField::Address)))
        .push(field("DNS (optional)", input("1.1.1.1", &draft.dns, DraftField::Dns)))
        .push(field("MTU (optional)", input("1420", &draft.mtu, DraftField::Mtu)))
        .push(section("PEER"))
        .push(field("Public Key", input("Server public key", &draft.peer_public_key, DraftField::PeerPublicKey)))
        .push(field("Endpoint", input("vpn.example.com:51820", &draft.endpoint, DraftField::Endpoint)))
        .push(field("Allowed IPs", input("0.0.0.0/0, ::/0", &draft.allowed_ips, DraftField::AllowedIps)))
        .push(field("Preshared Key (optional)", input("Preshared key", &draft.preshared_key, DraftField::PresharedKey)))
        .push(field("Persistent Keepalive (optional)", input("25", &draft.keepalive, DraftField::Keepalive)))
        .push(container(connect_after).height(44).align_y(Alignment::Center));

    if let Some(error) = &app.import_error {
        body = body.push(error_box(error));
    }
    body = body.push(container(actions).padding(Padding { top: 8.0, ..Padding::ZERO }));

    page(header, body, Padding { top: 24.0, right: MARGIN, bottom: 24.0, left: MARGIN })
}

fn input<'a>(placeholder: &'a str, value: &'a str, field: DraftField) -> Element<'a, Message> {
    text_input(placeholder, value)
        .on_input(move |value| Message::DraftChanged(field, value))
        .on_submit(Message::SaveDraft)
        .padding([13, 14])
        .size(15)
        .style(theme::input)
        .into()
}

/// A section title, set apart from the field above it.
fn section(title: &str) -> Element<'_, Message> {
    container(text(title).size(14).font(theme::SANS_SEMIBOLD).color(theme::palette().muted))
        .padding(Padding { top: 12.0, ..Padding::ZERO })
        .into()
}

fn caption(caption: &str) -> text::Text<'_> {
    text(caption).size(13).font(theme::SANS_SEMIBOLD).color(theme::palette().text)
}

fn field<'a>(caption: &'a str, content: Element<'a, Message>) -> Element<'a, Message> {
    column![self::caption(caption), content].spacing(8).into()
}

/// A small copy icon, named by a tooltip; greyed out without a message.
fn copy_button<'a>(tip: &'static str, message: Option<Message>) -> Element<'a, Message> {
    let color = if message.is_some() { theme::palette().text } else { theme::palette().muted };
    let button = button(container(icons::copy(16.0, color)).center(28))
        .padding(0)
        .on_press_maybe(message)
        .style(theme::icon_button);
    tooltip(button, container(text(tip).size(12)).padding([4, 8]).style(theme::tooltip), tooltip::Position::Top)
        .gap(4)
        .into()
}
