//! The 60-second traffic graph on the Connection screen.

use std::collections::VecDeque;

use iced::widget::canvas::{self, Frame, Geometry, LineCap, LineJoin, Path, Stroke, Text};
use iced::{Color, Pixels, Point, Rectangle, Renderer, Theme, alignment, mouse};

use crate::{format, theme};

/// Seconds of history kept and drawn.
pub const SAMPLES: usize = 60;
pub const HEIGHT: f32 = 150.0;
/// Smallest y-axis top, in KB/s; an idle tunnel still gets a sensible axis.
const MIN_SCALE: f32 = 1.0;

/// Rates in KB/s, oldest first. Lives only in memory.
#[derive(Debug, Clone)]
pub struct History {
    pub incoming: VecDeque<f32>,
    pub outgoing: VecDeque<f32>,
}

impl Default for History {
    fn default() -> Self {
        History { incoming: VecDeque::from(vec![0.0; SAMPLES]), outgoing: VecDeque::from(vec![0.0; SAMPLES]) }
    }
}

impl History {
    pub fn push(&mut self, incoming: f32, outgoing: f32) {
        for (series, value) in [(&mut self.incoming, incoming), (&mut self.outgoing, outgoing)] {
            series.pop_front();
            series.push_back(value);
        }
    }

    /// Top of the y axis: the peak plus some headroom, rounded up to a
    /// round number, so 2–3 KB/s of traffic fills the graph as visibly as
    /// 300 MB/s does.
    pub fn scale(&self) -> f32 {
        let peak = self.incoming.iter().chain(&self.outgoing).fold(0.0_f32, |a, &b| a.max(b));
        nice_ceiling((peak * 1.15).max(MIN_SCALE))
    }
}

pub struct Graph<'a> {
    pub history: &'a History,
    pub accent: Color,
}

impl<Message> canvas::Program<Message> for Graph<'_> {
    type State = ();

    fn draw(&self, _: &(), renderer: &Renderer, _: &Theme, bounds: Rectangle, _: mouse::Cursor) -> Vec<Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());
        let (w, h) = (bounds.width, bounds.height);
        let max = self.history.scale();

        for (y, color) in [(10.0, theme::GRID), (h / 2.0 + 5.0, theme::GRID), (h - 1.0, theme::AXIS)] {
            frame.stroke(
                &Path::line(Point::new(0.0, y), Point::new(w, y)),
                Stroke::default().with_color(color).with_width(1.0),
            );
        }

        for (series, color) in [(&self.history.incoming, theme::INCOMING), (&self.history.outgoing, self.accent)] {
            let points: Vec<Point> = series
                .iter()
                .enumerate()
                .map(|(i, &v)| Point::new(i as f32 * w / (SAMPLES - 1) as f32, h - 1.0 - v / max * (h - 12.0)))
                .collect();
            let area = Path::new(|p| {
                p.move_to(Point::new(0.0, h - 1.0));
                points.iter().for_each(|&pt| p.line_to(pt));
                p.line_to(Point::new(w, h - 1.0));
                p.close();
            });
            frame.fill(&area, Color { a: 0.10, ..color });
            let line = Path::new(|p| {
                p.move_to(points[0]);
                points[1..].iter().for_each(|&pt| p.line_to(pt));
            });
            frame.stroke(
                &line,
                Stroke::default()
                    .with_color(color)
                    .with_width(2.0)
                    .with_line_join(LineJoin::Round)
                    .with_line_cap(LineCap::Round),
            );
        }

        for (y, value) in [(0.0, max), (h / 2.0 - 5.0, max / 2.0)] {
            let label = format::rate(value);
            let width = label.len() as f32 * 6.7 + 4.0;
            frame.fill_rectangle(Point::new(w - width, y), iced::Size::new(width, 15.0), Color::WHITE);
            frame.fill_text(Text {
                content: label,
                position: Point::new(w, y),
                color: theme::MUTED,
                size: Pixels(11.0),
                font: theme::MONO,
                align_x: alignment::Horizontal::Right.into(),
                align_y: alignment::Vertical::Top,
                ..Text::default()
            });
        }

        vec![frame.into_geometry()]
    }
}

/// The smallest of 1, 2, 2.5, 5 × 10ⁿ that is at least `value`.
fn nice_ceiling(value: f32) -> f32 {
    let magnitude = 10f32.powf(value.log10().floor());
    [1.0, 2.0, 2.5, 5.0, 10.0]
        .into_iter()
        .map(|step| step * magnitude)
        .find(|&candidate| candidate >= value * 0.9999)
        .unwrap_or(10.0 * magnitude)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_peak(kb: f32) -> History {
        let mut history = History::default();
        history.push(kb, 0.0);
        history
    }

    #[test]
    fn scale_follows_the_traffic() {
        assert_eq!(History::default().scale(), 1.0);
        assert_eq!(with_peak(2.0).scale(), 2.5);
        assert_eq!(with_peak(3.0).scale(), 5.0);
        assert_eq!(with_peak(300.0).scale(), 500.0);
        assert_eq!(with_peak(1500.0).scale(), 2000.0);
        assert_eq!(nice_ceiling(250.0), 250.0);
    }
}
