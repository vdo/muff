use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};

use crate::app::{AppState, MouseRegion};
use crate::ui::{Regions, centered_rect};
use crate::wallet::{TransferDirection, TransferRecord, format_xmr};

/// Format a unix timestamp as `YYYY-MM-DD HH:MM` (UTC), or a dash for 0.
fn format_time(timestamp: u64) -> String {
    if timestamp == 0 {
        return "\u{2014}".to_string();
    }
    chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "\u{2014}".to_string())
}

/// Render the transaction history screen.
pub fn render_history(frame: &mut Frame, area: Rect, state: &AppState, regions: &mut Regions) {
    let block = Block::default()
        .title(" Transaction History ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    if state.transfers.is_empty() {
        let mut lines = vec![Line::from(Span::styled(
            "  No transactions found. Start syncing to discover transfers.",
            Style::default().fg(Color::DarkGray),
        ))];
        if let Some(notice) = &state.history_notice {
            lines.push(Line::from(Span::styled(
                format!("  {notice}"),
                Style::default().fg(Color::Yellow),
            )));
        }
        let widget = ratatui::widgets::Paragraph::new(lines).block(block);
        frame.render_widget(widget, area);
        return;
    }

    // Split: table on top, selected-transfer details at the bottom.
    let chunks = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(5)])
        .split(area);

    // Newest first: display index 0 is the most recent transfer.
    let display: Vec<&TransferRecord> = state.transfers.iter().rev().collect();
    // `history_selected` is already in display order (0 = newest).
    let selected_display = state.history_selected.min(display.len() - 1);

    // Register click targets: data row i sits at content line 2 + i inside
    // the table block (border + header row), clamped to the visible area.
    let table_area = chunks[0];
    let inner_x = table_area.x + 1;
    let inner_width = table_area.width.saturating_sub(2);
    let inner_bottom = table_area.bottom().saturating_sub(1);
    if inner_width > 0 {
        for i in 0..display.len() {
            let y = table_area.y + 2 + i as u16;
            if y >= inner_bottom {
                break;
            }
            regions.push((
                Rect::new(inner_x, y, inner_width, 1),
                MouseRegion::HistoryRow(i),
            ));
        }
    }

    let header_cells = [
        "Direction",
        "Height",
        "Date (UTC)",
        "Amount",
        "Fee",
        "TX Hash",
        "Status",
    ]
    .iter()
    .map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).style(Style::default()).height(1);

    let rows = display.iter().enumerate().map(|(i, t)| {
        let dir_style = match t.direction {
            TransferDirection::In => Style::default().fg(Color::Green),
            TransferDirection::Out => Style::default().fg(Color::Red),
        };

        let status = if t.failed {
            Span::styled("\u{2717} dropped", Style::default().fg(Color::Red))
        } else if t.confirmed {
            Span::styled("\u{2713}", Style::default().fg(Color::Green))
        } else {
            Span::styled("pending", Style::default().fg(Color::Yellow))
        };

        let hash_short = if t.tx_hash.len() > 16 {
            format!("{}\u{2026}", &t.tx_hash[..16])
        } else {
            t.tx_hash.clone()
        };

        let height_str = if t.height == 0 && !t.confirmed {
            "\u{2014}".to_string()
        } else {
            format!("{}", t.height)
        };

        let style = if i == selected_display {
            Style::default().bg(Color::DarkGray)
        } else {
            Style::default()
        };

        Row::new(vec![
            Cell::from(Span::styled(format!("{}", t.direction), dir_style)),
            Cell::from(height_str),
            Cell::from(format_time(t.timestamp)),
            Cell::from(Span::styled(format_xmr(t.amount), dir_style)),
            Cell::from(if t.fee > 0 {
                format_xmr(t.fee)
            } else {
                "\u{2014}".to_string()
            }),
            Cell::from(hash_short),
            Cell::from(status),
        ])
        .height(1)
        .style(style)
    });

    let widths = [
        Constraint::Length(9),
        Constraint::Length(10),
        Constraint::Length(17),
        Constraint::Length(22),
        Constraint::Length(22),
        Constraint::Length(18),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    let mut table_state = TableState::default().with_selected(selected_display);
    frame.render_stateful_widget(table, chunks[0], &mut table_state);

    // Detail pane for the selected transfer.
    let selected = display.get(selected_display);
    let detail_title = match &state.history_notice {
        Some(notice) => format!(" {notice} "),
        None => " Details (↑↓/Tab select, Enter full, [C] copy hash, [E] export CSV) ".to_string(),
    };
    let detail_block = Block::default()
        .title(detail_title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let detail_lines = match selected {
        Some(t) => vec![
            Line::from(vec![
                Span::styled("  TX: ", Style::default().fg(Color::DarkGray)),
                Span::styled(t.tx_hash.clone(), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    if t.failed {
                        "Dropped by the network \u{2014} funds were not spent"
                    } else if t.confirmed {
                        "Confirmed"
                    } else {
                        "Broadcast to the network \u{2014} in the pool, waiting to be mined"
                    },
                    Style::default().fg(if t.failed {
                        Color::Red
                    } else if t.confirmed {
                        Color::Green
                    } else {
                        Color::Yellow
                    }),
                ),
                Span::styled(
                    format!("   {}", t.note),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
        ],
        None => vec![],
    };
    let detail = ratatui::widgets::Paragraph::new(detail_lines).block(detail_block);
    frame.render_widget(detail, chunks[1]);
}

/// Modal with the full details of the selected transaction (opened with
/// Enter; Up/Down move between transactions while it stays open).
pub fn render_detail_modal(frame: &mut Frame, area: Rect, state: &AppState) {
    if state.transfers.is_empty() {
        return;
    }
    // Display order is reversed storage order (0 = newest).
    let len = state.transfers.len();
    let storage_idx = len - 1 - state.history_selected.min(len - 1);
    let Some(t) = state.transfers.get(storage_idx) else {
        return;
    };

    let dir_style = match t.direction {
        TransferDirection::In => Style::default().fg(Color::Green),
        TransferDirection::Out => Style::default().fg(Color::Red),
    };
    let dir_label = match t.direction {
        TransferDirection::In => "IN (received)",
        TransferDirection::Out => "OUT (sent)",
    };

    let (status_text, status_style) = if t.failed {
        (
            "Dropped by the network — funds were not spent".to_string(),
            Style::default().fg(Color::Red),
        )
    } else if t.confirmed {
        // Confirmations = chain tip - tx height + 1; `node_status.height`
        // is the block count, so that is simply height - tx_height.
        let confs = state
            .node_status
            .connected
            .then(|| state.node_status.height.saturating_sub(t.height))
            .filter(|c| *c > 0);
        (
            match confs {
                Some(c) => format!(
                    "Confirmed ({c} confirmation{})",
                    if c == 1 { "" } else { "s" }
                ),
                None => "Confirmed".to_string(),
            },
            Style::default().fg(Color::Green),
        )
    } else {
        (
            "Broadcast to the network \u{2014} waiting to be mined".to_string(),
            Style::default().fg(Color::Yellow),
        )
    };

    let row = |label: &str, value: String, style: Style| {
        Line::from(vec![
            Span::styled(
                format!("  {label:<10}"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(value, style),
        ])
    };

    let popup = centered_rect(area, 76, 15);
    frame.render_widget(Clear, popup);

    let mut lines = vec![
        Line::from(""),
        row("Direction", dir_label.to_string(), dir_style),
        row(
            "Amount",
            format_xmr(t.amount),
            dir_style.add_modifier(Modifier::BOLD),
        ),
    ];
    if t.fee > 0 {
        lines.push(row(
            "Fee",
            format_xmr(t.fee),
            Style::default().fg(Color::White),
        ));
    }
    lines.push(row("Status", status_text, status_style));
    lines.push(row(
        "Height",
        if t.height == 0 && !t.confirmed {
            "—".to_string()
        } else {
            t.height.to_string()
        },
        Style::default().fg(Color::White),
    ));
    lines.push(row(
        "Date (UTC)",
        format_time(t.timestamp),
        Style::default().fg(Color::White),
    ));
    lines.push(row(
        "TX hash",
        t.tx_hash.clone(),
        Style::default().fg(Color::Cyan),
    ));
    if !t.note.is_empty() {
        lines.push(row(
            "Note",
            t.note.clone(),
            Style::default().fg(Color::Gray),
        ));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  ↑/↓: prev/next    [C]: copy hash    Enter/Esc: close",
        Style::default().fg(Color::Yellow),
    )));

    let title = format!(" Transaction {} ", &t.tx_hash[..8.min(t.tx_hash.len())]);
    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(widget, popup);
}
