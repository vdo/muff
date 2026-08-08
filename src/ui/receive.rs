use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::app::{AppState, MouseRegion, RECEIVE_ADDRESS_COUNT};
use crate::ui::{Regions, centered_rect, truncate_middle};

/// Label for a receive-list index (0 = primary address).
fn address_label(index: usize) -> String {
    if index == 0 {
        "Primary".to_string()
    } else {
        format!("Sub #{index}")
    }
}

/// Render the receive screen showing wallet addresses.
///
/// The screen is a single full-width address list; the QR code is only
/// shown on demand, inside the detail modal opened with Enter.
pub fn render_receive(frame: &mut Frame, area: Rect, state: &AppState, regions: &mut Regions) {
    render_addresses(frame, area, state, regions);
}

/// Selectable address list (primary + first subaddresses).
///
/// Addresses are truncated in the middle so they always fit the pane;
/// Enter opens a modal with the QR code and the full address.
fn render_addresses(frame: &mut Frame, area: Rect, state: &AppState, regions: &mut Regions) {
    let block = Block::default()
        .title(" Addresses (↑↓/Tab select, Enter QR & full address, [C] copy) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    if state.wallet_keys.is_none() {
        let widget = Paragraph::new("  No wallet loaded").block(block);
        frame.render_widget(widget, area);
        return;
    }

    // One row per address, starting at content line 1 inside the border.
    let inner_x = area.x + 1;
    let inner_width = area.width.saturating_sub(2);
    let inner_bottom = area.bottom().saturating_sub(1);
    for i in 0..RECEIVE_ADDRESS_COUNT {
        let y = area.y + 1 + i as u16;
        if y < inner_bottom && inner_width > 0 {
            regions.push((
                Rect::new(inner_x, y, inner_width, 1),
                MouseRegion::ReceiveRow(i),
            ));
        }
    }

    // Budget: marker (3) + label (9) + address, capped to the pane width.
    let addr_budget = (inner_width as usize).saturating_sub(13).max(12);

    let mut lines: Vec<Line> = Vec::new();
    for i in 0..RECEIVE_ADDRESS_COUNT {
        let addr = state.receive_address_string(i).unwrap_or_default();
        let selected = i == state.receive_selected;
        let marker = if selected { " ▶ " } else { "   " };
        let style = if selected {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        lines.push(Line::from(vec![
            Span::styled(marker, style),
            Span::styled(format!("{:<8}", address_label(i)), style),
            Span::styled(truncate_middle(&addr, addr_budget), style),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Use a fresh subaddress per sender for privacy.",
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(Span::styled(
        "  Enter shows the QR code and full address; [C] copies it.",
        Style::default().fg(Color::DarkGray),
    )));

    let widget = Paragraph::new(lines).block(block);
    frame.render_widget(widget, area);
}

/// Quiet zone width (in modules) around the QR code.
const QUIET: usize = 2;

/// Build the QR code for `data` as terminal lines of exactly
/// `width + 2*QUIET` columns: two module rows per terminal row via half
/// blocks, with a uniform white quiet zone on all four sides.
///
/// Every returned line has the same number of cells — the previous
/// renderer made the blank quiet rows twice as wide as the module rows,
/// producing a ragged, hard-to-scan code.
fn qr_lines(data: &[u8]) -> Option<(Vec<Line<'static>>, usize)> {
    let code = qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::L).ok()?;
    let width = code.width();
    let colors = code.into_colors();
    let total = width + QUIET * 2;

    let is_dark = |gx: usize, gy: usize| -> bool {
        gx >= QUIET
            && gy >= QUIET
            && gx < QUIET + width
            && gy < QUIET + width
            && colors[(gy - QUIET) * width + (gx - QUIET)] == qrcode::Color::Dark
    };

    // Black modules on white background, as scanners expect.
    let dark = Style::default().fg(Color::Black).bg(Color::White);
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut gy = 0;
    while gy < total {
        let mut spans = Vec::with_capacity(total);
        for gx in 0..total {
            let top = is_dark(gx, gy);
            let bottom = gy + 1 < total && is_dark(gx, gy + 1);
            let ch = match (top, bottom) {
                (true, true) => "█",
                (true, false) => "▀",
                (false, true) => "▄",
                (false, false) => " ",
            };
            spans.push(Span::styled(ch, dark));
        }
        lines.push(Line::from(spans));
        gy += 2;
    }
    Some((lines, total))
}

/// Modal showing the selected address as a QR code plus its full text
/// (opened with Enter). The QR is only rendered here, on demand — never
/// on the receive screen itself.
pub fn render_detail_modal(frame: &mut Frame, area: Rect, state: &AppState) {
    let label = address_label(state.receive_selected);
    let Some(address) = state.receive_address_string(state.receive_selected) else {
        return;
    };

    // `monero:<address>` is the standard URI scheme wallets understand.
    let uri = format!("monero:{address}");

    if let Some((qr, qr_cols)) = qr_lines(uri.as_bytes()) {
        let qr_rows = qr.len() as u16;
        let popup_width = ((qr_cols as u16) + 6).max(64).min(area.width);
        // The address is a single long word; it wraps to 2 lines at ~60
        // columns of text width.
        let text_width = popup_width.saturating_sub(4).max(1);
        let addr_rows = (address.len() as u16) / text_width + 1;
        // QR + blank + address + blank + key hints.
        let content_rows = qr_rows + 1 + addr_rows + 2;

        if popup_width >= qr_cols as u16 + 2 && area.height >= content_rows + 2 {
            let popup = centered_rect(area, popup_width, content_rows + 2);
            frame.render_widget(Clear, popup);

            let inner_width = popup_width.saturating_sub(2) as usize;
            let pad = " ".repeat(inner_width.saturating_sub(qr_cols) / 2);

            let mut lines: Vec<Line> = Vec::new();
            for qr_line in qr {
                let mut spans = vec![Span::raw(pad.clone())];
                spans.extend(qr_line.spans);
                lines.push(Line::from(spans));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("  {address}"),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Enter/Esc: close    [C]: copy",
                Style::default().fg(Color::Yellow),
            )));

            let widget = Paragraph::new(lines)
                .block(
                    Block::default()
                        .title(format!(" {label} address "))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan)),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(widget, popup);
            return;
        }
    }

    // Fallback for tiny terminals (or QR build failure): address only.
    let popup = centered_rect(area, 56, 11);
    frame.render_widget(Clear, popup);

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {address}"),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Verify the address character by character when",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  sharing it out of band.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "  (Enlarge the terminal to see the QR code.)",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Enter/Esc: close    [C]: copy",
            Style::default().fg(Color::Yellow),
        )),
    ];

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .title(format!(" {label} address "))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(widget, popup);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic `monero:<address>` payload renders as a rectangle:
    /// every terminal row has exactly `width + 2*QUIET` one-cell spans
    /// (the old renderer drew the quiet rows twice as wide).
    #[test]
    fn qr_lines_are_uniform_width() {
        let address: String = std::iter::repeat_n('A', 95).collect();
        let uri = format!("monero:{address}");
        let (lines, total) = qr_lines(uri.as_bytes()).expect("QR builds");

        assert_eq!(lines.len(), total.div_ceil(2));
        for line in &lines {
            assert_eq!(line.spans.len(), total);
            for span in &line.spans {
                assert_eq!(span.content.chars().count(), 1);
            }
        }

        // The quiet zone (first/last QUIET columns of every row) is blank.
        for line in &lines {
            for span in &line.spans[..QUIET] {
                assert_eq!(span.content, " ");
            }
            for span in &line.spans[total - QUIET..] {
                assert_eq!(span.content, " ");
            }
        }
    }
}
