use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::AppState;
use crate::ui::truncate_middle;
use crate::wallet::{TransferDirection, format_xmr};

/// Render the main dashboard screen: balance + node status on top, recent
/// activity in the middle, captured log output at the bottom.
pub fn render_dashboard(frame: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Balance + Node status
            Constraint::Min(6),     // Recent activity
            Constraint::Length(8),  // Logs
        ])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[0]);

    render_balance(frame, top[0], state);
    render_node(frame, top[1], state);
    render_activity(frame, chunks[1], state);
    render_logs(frame, chunks[2], state);
}

/// Top-left pane: wallet balance.
fn render_balance(frame: &mut Frame, area: Rect, state: &AppState) {
    let balance_block = Block::default()
        .title(" Balance ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let total_str = format_xmr(state.balance.total);
    let unlocked_str = format_xmr(state.balance.unlocked);
    let locked_str = format_xmr(state.balance.locked);

    let mut balance_text = vec![
        Line::from(vec![
            Span::styled("  Total:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                total_str,
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Available:", Style::default().fg(Color::DarkGray)),
            Span::styled(unlocked_str, Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled("  Locked:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(locked_str, Style::default().fg(Color::Red)),
        ]),
    ];

    // The primary address sits under the balance in the spare rows.
    if let Some(ref keys) = state.wallet_keys {
        let addr = keys.address_string();
        let short = truncate_middle(&addr, 24);
        balance_text.push(Line::from(""));
        balance_text.push(Line::from(vec![
            Span::styled("  Address:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(short, Style::default().fg(Color::White)),
        ]));
    }

    let balance_widget = Paragraph::new(balance_text)
        .block(balance_block)
        .alignment(Alignment::Left);
    frame.render_widget(balance_widget, area);
}

/// Top-right pane: compact node status (merged in from the old Node tab).
fn render_node(frame: &mut Frame, area: Rect, state: &AppState) {
    let node_block = Block::default()
        .title(" Node ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let ns = &state.node_status;
    let inner_width = area.width.saturating_sub(2) as usize;
    // Labels + indent take 13 columns; values get the rest.
    let value_budget = inner_width.saturating_sub(13).max(8);

    let (status_text, status_color) = if ns.connected {
        ("● Connected", Color::Green)
    } else {
        ("● Disconnected", Color::Red)
    };

    let height_str = if ns.connected {
        if ns.target_height > ns.height {
            format!("{} / {}", ns.height, ns.target_height)
        } else {
            format!("{}", ns.height)
        }
    } else {
        "---".to_string()
    };

    let mut node_lines = vec![
        Line::from(vec![
            Span::styled("  Status:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                status_text,
                Style::default()
                    .fg(status_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Height:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(height_str, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Network:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                truncate_middle(&ns.net_type, value_budget),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Version:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                truncate_middle(&ns.version, value_budget),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Peers:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", ns.peer_count),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("  URL:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                truncate_middle(&state.config.daemon.url, value_budget),
                Style::default().fg(Color::White),
            ),
        ]),
    ];

    if let Some(ref err) = ns.error {
        node_lines.push(Line::from(vec![
            Span::styled("  Error:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                truncate_middle(err, value_budget),
                Style::default().fg(Color::Red),
            ),
        ]));
    }

    let node_widget = Paragraph::new(node_lines).block(node_block);
    frame.render_widget(node_widget, area);
}

/// Middle pane: recent wallet activity (unchanged behavior).
fn render_activity(frame: &mut Frame, area: Rect, state: &AppState) {
    let info_block = Block::default()
        .title(" Wallet — Recent Activity ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let mut info_lines = vec![];

    // Recent transfers (newest first), as many as the pane can hold.
    let capacity = area.height.saturating_sub(3) as usize;
    let recent: Vec<_> = state.transfers.iter().rev().take(capacity.max(1)).collect();
    if recent.is_empty() {
        info_lines.push(Line::from(Span::styled(
            "  No activity yet.",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for t in recent {
            let (dir_label, dir_color) = match t.direction {
                TransferDirection::In => ("+ IN ", Color::Green),
                TransferDirection::Out => ("- OUT", Color::Red),
            };
            let status = if t.failed {
                "\u{2717}"
            } else if t.confirmed {
                "\u{2713}"
            } else {
                "\u{23f3}"
            };
            let date = if t.timestamp > 0 {
                chrono::DateTime::from_timestamp(t.timestamp as i64, 0)
                    .map(|dt| dt.format("%m-%d %H:%M").to_string())
                    .unwrap_or_default()
            } else {
                "     ".to_string()
            };
            info_lines.push(Line::from(vec![
                Span::styled(format!("  {status} "), Style::default().fg(dir_color)),
                Span::styled(dir_label, Style::default().fg(dir_color)),
                Span::styled(format_xmr(t.amount), Style::default().fg(Color::White)),
                Span::styled(format!("  {date}"), Style::default().fg(Color::DarkGray)),
            ]));
        }
    }

    if let Some(ref err) = state.last_error {
        info_lines.push(Line::from(""));
        info_lines.push(Line::from(vec![
            Span::styled("  Notice: ", Style::default().fg(Color::DarkGray)),
            Span::styled(err.clone(), Style::default().fg(Color::Red)),
        ]));
    }

    let info_widget = Paragraph::new(info_lines).block(info_block);
    frame.render_widget(info_widget, area);
}

/// Bottom pane: the tail of the captured tracing output. This is the only
/// place logs are rendered — no other screen shows them, and nothing is
/// written to the terminal directly.
fn render_logs(frame: &mut Frame, area: Rect, state: &AppState) {
    let log_block = Block::default()
        .title(" Logs ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let capacity = area.height.saturating_sub(2) as usize;
    let lines = state.log_buffer.tail(capacity);

    let log_lines: Vec<Line> = if lines.is_empty() {
        vec![Line::from(Span::styled(
            "  No log output yet.",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        lines
            .into_iter()
            .map(|l| Line::from(Span::styled(l, Style::default().fg(Color::Gray))))
            .collect()
    };

    let log_widget = Paragraph::new(log_lines).block(log_block);
    frame.render_widget(log_widget, area);
}
