//! Screen 3 · Connection: status in the title bar, then live traffic and
//! what was configured.

use iced::widget::{Column, button, canvas, column, container, row, text};
use iced::{Alignment, Element, Length, Padding};

use std::net::IpAddr;

use wg_common::config::Cidr;

use crate::app::{App, Message, Status, join};
use crate::graph::{self, Graph};
use crate::{format, theme};

use super::{MARGIN, back_button, bar, bar_padding, card, field, header, page, toggle};

pub fn view(app: &App) -> Element<'_, Message> {
    let Some(active) = &app.active else {
        let body = column![theme::label("Not connected.", 14.0, theme::MUTED)];
        return page(header("Connection", Some(Message::GoProfiles), None), body, Padding::from(16));
    };
    let summary = app.profile(&active.profile).and_then(|p| p.summary.as_ref().ok());
    let endpoint = active
        .info
        .as_ref()
        .map(|i| i.endpoint_text.clone())
        .or_else(|| summary.map(|s| s.endpoint.clone()))
        .unwrap_or_default();

    // -- title bar with status -------------------------------------------------
    let (label, color, track) = match active.status {
        Status::Connected => ("CONNECTED", theme::OK, theme::ACCENT),
        Status::Connecting => ("CONNECTING…", theme::WARN, theme::WARN_TOGGLE),
        Status::Disconnecting => ("DISCONNECTING…", theme::MUTED, theme::TOGGLE_OFF),
    };
    let mut status_line = row![text(label).size(12).font(theme::SANS_BOLD).color(color)].spacing(8).align_y(Alignment::Center);
    if active.started.is_some() {
        status_line = status_line.push(theme::mono(format::duration(active.seconds()), 12.0).color(theme::MUTED));
    }
    let switch = button(container(toggle(true, track, 52.0, 28.0)).center_y(44))
        .padding(0)
        .on_press_maybe((active.status != Status::Disconnecting).then_some(Message::Disconnect))
        .style(theme::bare);
    let header = bar(
        container(
            row![
                back_button(Message::GoProfiles),
                column![
                    status_line,
                    text(&active.profile).size(18).font(theme::SANS_SEMIBOLD).color(theme::TEXT),
                    text(endpoint).size(12.5).color(theme::MUTED),
                ]
                .spacing(2)
                .width(Length::Fill),
                switch,
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        )
        .padding(bar_padding(12.0)),
    );

    // -- traffic -------------------------------------------------------------
    let history = &active.history;
    let rate = |series: &std::collections::VecDeque<f32>| format::rate(series.back().copied().unwrap_or(0.0));
    let legend = |caption: &'static str, direction: Direction, value: String| -> Element<'_, Message> {
        column![theme::label(caption, 12.5, theme::MUTED), directed(value, direction, 20.0)]
            .spacing(2)
            .width(Length::Fill)
            .into()
    };
    let stats = active.stats;
    let traffic = card(column![
        row![
            theme::section("TRAFFIC", theme::MUTED).width(Length::Fill),
            theme::value(format!("last {} s", graph::SAMPLES), 12.0, theme::MUTED),
        ],
        row![
            legend("Incoming", Direction::In, rate(&history.incoming)),
            legend("Outgoing", Direction::Out, rate(&history.outgoing)),
        ]
        .spacing(12),
        canvas(Graph { history, accent: theme::ACCENT }).width(Length::Fill).height(graph::HEIGHT),
        theme::rule(theme::GRID),
        row![
            small_stat("BYTES IN", directed(format::bytes(stats.rx_bytes), Direction::In, 14.0)),
            small_stat("BYTES OUT", directed(format::bytes(stats.tx_bytes), Direction::Out, 14.0)),
            small_stat("PACKETS", theme::value(format::count(stats.rx_packets + stats.tx_packets), 14.0, theme::TEXT)),
        ]
        .spacing(8),
    ]);

    let mut body = Column::new().spacing(14).push(traffic);

    // -- details, once the tunnel is up ---------------------------------------
    if let Some(info) = &active.info {
        let addresses: Vec<String> = info.addresses.iter().map(|a| format!("{}/{}", a.ip, a.prefix)).collect();
        body = body.push(card(column![
            theme::section("CONNECTION", theme::MUTED),
            row![field("Your VPN IP", join(&addresses)), field("Server IP", info.server.ip().to_string())].spacing(16),
            row![field("Protocol", format!("UDP {}", info.server.port())), field("Cipher", "ChaCha20-Poly1305".to_string())]
                .spacing(16),
            row![field("Interface", info.tun_name.clone()), field("MTU", info.mtu.to_string())].spacing(16),
        ]));

        let badge: Element<'_, Message> = if info.dns_changed {
            container(text("DNS set by profile").size(12).font(theme::SANS_MEDIUM).color(theme::OK))
                .padding([3, 8])
                .style(theme::filled(theme::OK_TINT, 10.0))
                .into()
        } else {
            iced::widget::space().into()
        };
        let mut dns = column![row![theme::section("DNS", theme::MUTED).width(Length::Fill), badge].align_y(Alignment::Center)]
            .spacing(0);
        if info.dns.is_empty() {
            dns = dns.push(dns_row("Servers", "System default (unchanged)".to_string()));
        } else {
            for (i, server) in info.dns.iter().enumerate() {
                let caption = match i {
                    0 => "Primary server",
                    1 => "Secondary server",
                    _ => "Server",
                };
                dns = dns.push(dns_row(caption, server.to_string()));
            }
            dns = dns.push(dns_row("Source", "From profile".to_string()));
            let outside = dns_outside_tunnel(&info.dns, &info.allowed_ips);
            if !outside.is_empty() {
                let servers = join(&outside.iter().map(ToString::to_string).collect::<Vec<_>>());
                let (verb, pronoun) = if outside.len() == 1 { ("is", "it") } else { ("are", "them") };
                dns = dns.push(
                    container(theme::label(
                        format!("{servers} {verb} outside the tunnel's routes, so lookups to {pronoun} use your normal connection, not the VPN."),
                        12.0,
                        theme::WARN,
                    ))
                    .padding(Padding { top: 6.0, ..Padding::ZERO }),
                );
            }
        }
        body = body.push(card(dns));

        let mut routes = column![
            row![
                theme::section("ROUTES", theme::MUTED).width(Length::Fill),
                theme::value(format!("{} routes", info.routes.len()), 12.0, theme::MUTED),
            ],
            route_line("DESTINATION", "GATEWAY", "IFACE", true),
        ]
        .spacing(0);
        for route in &info.routes {
            routes = routes.push(route_line(&route.destination, &route.gateway, &route.interface, false));
        }
        let note = route_note(&info.allowed_ips, &info.addresses, info.server.is_ipv4());
        routes = routes.push(container(theme::label(note, 12.0, theme::MUTED)).padding(Padding { top: 6.0, ..Padding::ZERO }));
        body = body.push(card(routes));
    }

    page(header, body, Padding { top: 16.0, right: MARGIN, bottom: 28.0, left: MARGIN })
}

#[derive(Clone, Copy)]
enum Direction {
    In,
    Out,
}

/// A traffic figure in its direction's colour, with an arrow after it.
fn directed<'a>(value: String, direction: Direction, size: f32) -> Element<'a, Message> {
    let (color, arrow) = match direction {
        Direction::In => (theme::INCOMING, "↓"),
        Direction::Out => (theme::ACCENT, "↑"),
    };
    row![theme::value(value, size, color), text(arrow).size(size).font(theme::SANS_SEMIBOLD).color(color)]
        .spacing(size * 0.3)
        .align_y(Alignment::Center)
        .into()
}

fn small_stat<'a>(caption: &'a str, value: Element<'a, Message>) -> Element<'a, Message> {
    column![theme::label(caption, 11.5, theme::MUTED), value]
        .spacing(2)
        .padding(Padding { top: 8.0, ..Padding::ZERO })
        .width(Length::Fill)
        .into()
}

fn dns_row<'a>(caption: &'a str, value: String) -> Element<'a, Message> {
    column![
        theme::rule(theme::GRID),
        row![theme::label(caption, 13.0, theme::MUTED).width(Length::Fill), theme::value(value, 13.0, theme::TEXT)]
            .spacing(12)
            .padding([8, 0]),
    ]
    .into()
}

fn route_line<'a>(destination: &str, gateway: &str, interface: &str, heading: bool) -> Element<'a, Message> {
    let cell = |value: &str, portion: u16, color: iced::Color| -> Element<'a, Message> {
        let content: Element<'a, Message> =
            if heading { theme::label(value.to_string(), 11.5, theme::MUTED).into() } else { theme::value(value, 12.5, color) };
        container(content).width(Length::FillPortion(portion)).into()
    };
    column![
        row![cell(destination, 15, theme::TEXT), cell(gateway, 11, theme::TEXT), cell(interface, 6, theme::MUTED)]
            .spacing(8)
            .padding([if heading { 6 } else { 7 }, 0]),
        theme::rule(if heading { theme::AXIS } else { theme::GRID }),
    ]
    .into()
}

/// What the route table means, including traffic that cannot get anywhere.
fn route_note(allowed_ips: &[Cidr], addresses: &[Cidr], endpoint_is_ipv4: bool) -> String {
    let full = |v4: bool| allowed_ips.iter().any(|c| c.prefix == 0 && c.ip.is_ipv4() == v4);
    let has_address = |v4: bool| addresses.iter().any(|a| a.ip.is_ipv4() == v4);
    let (ipv4_full, ipv6_full) = (full(true), full(false));

    let mut note = match (ipv4_full, ipv6_full) {
        (true, true) => "All traffic is routed through the tunnel.".to_string(),
        (true, false) => "All IPv4 traffic is routed through the tunnel; IPv6 only for the routes listed.".to_string(),
        (false, true) => "All IPv6 traffic is routed through the tunnel; IPv4 only for the routes listed.".to_string(),
        (false, false) => "Only the routes listed go through the tunnel; other traffic uses your normal connection.".to_string(),
    };
    // The endpoint keeps its own route through the local gateway only when
    // its address family is fully tunnelled.
    if if endpoint_is_ipv4 { ipv4_full } else { ipv6_full } {
        note.push_str(" The server address stays on your local gateway.");
    }
    // A family sent into the tunnel without an address of its own there
    // has no source address to use: that traffic is blocked.
    for (v4, family) in [(true, "IPv4"), (false, "IPv6")] {
        if allowed_ips.iter().any(|c| c.ip.is_ipv4() == v4) && !has_address(v4) {
            note.push_str(&format!(" {family} traffic on these routes is blocked: the profile has no {family} address."));
        }
    }
    note
}

/// DNS servers the tunnel does not carry; queries to them leave over the
/// normal connection.
fn dns_outside_tunnel(dns: &[IpAddr], allowed_ips: &[Cidr]) -> Vec<IpAddr> {
    dns.iter().copied().filter(|server| !allowed_ips.iter().any(|net| net.contains(*server))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidrs(list: &[&str]) -> Vec<Cidr> {
        list.iter()
            .map(|s| {
                let (ip, prefix) = s.split_once('/').unwrap();
                Cidr { ip: ip.parse().unwrap(), prefix: prefix.parse().unwrap() }
            })
            .collect()
    }

    #[test]
    fn note_matches_the_allowed_ips() {
        let v4_addr = cidrs(&["10.8.0.3/24"]);
        let both = cidrs(&["0.0.0.0/0", "::/0"]);
        let dual = cidrs(&["10.8.0.3/24", "fd00::3/64"]);
        assert_eq!(
            route_note(&both, &dual, true),
            "All traffic is routed through the tunnel. The server address stays on your local gateway."
        );
        // The reported profile: 10.200.202.108/24 + ::/0, IPv4-only address.
        let split = cidrs(&["10.200.202.108/24", "::/0"]);
        assert_eq!(
            route_note(&split, &v4_addr, true),
            "All IPv6 traffic is routed through the tunnel; IPv4 only for the routes listed. \
             IPv6 traffic on these routes is blocked: the profile has no IPv6 address."
        );
        assert_eq!(
            route_note(&cidrs(&["10.0.0.0/8"]), &v4_addr, true),
            "Only the routes listed go through the tunnel; other traffic uses your normal connection."
        );
    }

    #[test]
    fn finds_dns_servers_outside_the_tunnel() {
        let dns: Vec<IpAddr> = vec!["1.1.1.1".parse().unwrap(), "10.200.202.1".parse().unwrap()];
        let outside = dns_outside_tunnel(&dns, &cidrs(&["10.200.202.108/24", "::/0"]));
        assert_eq!(outside, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        assert!(dns_outside_tunnel(&dns, &cidrs(&["0.0.0.0/0"])).is_empty());
    }
}
