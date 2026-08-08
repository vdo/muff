use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::{AppState, MouseRegion};
use crate::ui::Regions;

/// Render an inline unicode progress bar like `[██████░░░░]`.
fn render_bar(fraction: f64, width: usize) -> String {
    let fraction = fraction.clamp(0.0, 1.0);
    let filled = (fraction * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);
    format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
}

/// Render the status header bar at the top of the screen.
pub fn render_header(frame: &mut Frame, area: Rect, state: &AppState) {
    let network_label = match state.config.wallet.network {
        crate::config::NetworkKind::Mainnet => "MAINNET",
        crate::config::NetworkKind::Stagenet => "STAGENET",
        crate::config::NetworkKind::Testnet => "TESTNET",
    };

    let connection_status = if state.node_status.connected {
        Span::styled("● Connected", Style::default().fg(Color::Green))
    } else {
        Span::styled("● Disconnected", Style::default().fg(Color::Red))
    };

    let height_info = if state.node_status.connected {
        format!("Height: {}", state.node_status.height)
    } else {
        "Height: ---".to_string()
    };

    let sync_spans = if let Some((current, target)) = state.scan_progress {
        let pct = if target > 0 {
            current as f64 / target as f64
        } else {
            0.0
        };
        let bar = render_bar(pct, 10);
        vec![
            Span::styled(
                format!("Syncing: {:.1}% ", pct * 100.0),
                Style::default().fg(Color::Magenta),
            ),
            Span::styled(bar, Style::default().fg(Color::Magenta)),
            Span::styled(
                format!(" {}/{}", current, target),
                Style::default().fg(Color::DarkGray),
            ),
        ]
    } else if state.node_status.synced {
        vec![Span::styled("Synced ✓", Style::default().fg(Color::Green))]
    } else {
        vec![Span::styled(
            "Syncing...",
            Style::default().fg(Color::Magenta),
        )]
    };

    let mut header_spans = vec![
        Span::styled(
            " MUFF ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" │ "),
        Span::styled(network_label, Style::default().fg(Color::Cyan)),
        Span::raw(" │ "),
        connection_status,
        Span::raw(" │ "),
        Span::styled(height_info, Style::default().fg(Color::White)),
        Span::raw(" │ "),
    ];
    header_spans.extend(sync_spans);

    let header_text = Line::from(header_spans);

    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(header, area);
}

/// Render the tab navigation bar.
///
/// Registers a clickable [`MouseRegion::Tab`] for each tab title so the bar
/// works with the mouse.
pub fn render_tabs(frame: &mut Frame, area: Rect, active_tab: usize, regions: &mut Regions) {
    let tabs = ["Dashboard", "Send", "Addresses", "History", "Config"];

    // Register click targets: each title is rendered as `│ Name `, so tab i
    // occupies `1 + name.len() + 2` columns starting at the running offset.
    let mut x = area.x;
    for (i, name) in tabs.iter().enumerate() {
        let width = 1 + name.len() as u16 + 2;
        let width = width.min(area.right().saturating_sub(x));
        if width == 0 {
            break;
        }
        regions.push((Rect::new(x, area.y, width, 1), MouseRegion::Tab(i)));
        x = x.saturating_add(width);
    }

    let titles: Vec<Line> = tabs
        .iter()
        .enumerate()
        .map(|(i, t)| {
            if i == active_tab {
                Line::from(Span::styled(
                    format!(" {} ", t),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ))
            } else {
                Line::from(Span::styled(
                    format!(" {} ", t),
                    Style::default().fg(Color::DarkGray),
                ))
            }
        })
        .collect();

    let tab_bar = Paragraph::new(Line::from(
        titles
            .into_iter()
            .flat_map(|t| {
                vec![
                    Span::styled("│", Style::default().fg(Color::DarkGray)),
                    t.spans.into_iter().next().unwrap_or_default(),
                ]
            })
            .collect::<Vec<_>>(),
    ))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(tab_bar, area);
}

/// Render the footer with keybindings help.
pub fn render_footer(frame: &mut Frame, area: Rect) {
    let help_text = Line::from(vec![
        Span::styled(" ←/→·1-5 ", Style::default().fg(Color::Yellow)),
        Span::styled("Tabs", Style::default().fg(Color::DarkGray)),
        Span::raw(" │ "),
        Span::styled(" Tab ", Style::default().fg(Color::Yellow)),
        Span::styled("Next element", Style::default().fg(Color::DarkGray)),
        Span::raw(" │ "),
        Span::styled(" ↑/↓ ", Style::default().fg(Color::Yellow)),
        Span::styled("Move", Style::default().fg(Color::DarkGray)),
        Span::raw(" │ "),
        Span::styled(" Enter ", Style::default().fg(Color::Yellow)),
        Span::styled("Open", Style::default().fg(Color::DarkGray)),
        Span::raw(" │ "),
        Span::styled(" ? ", Style::default().fg(Color::Yellow)),
        Span::styled("Help", Style::default().fg(Color::DarkGray)),
        Span::raw(" │ "),
        Span::styled(" q ", Style::default().fg(Color::Yellow)),
        Span::styled("Quit", Style::default().fg(Color::DarkGray)),
    ]);

    let footer = Paragraph::new(help_text).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(footer, area);
}

/// Split the main content area into header, tabs, content, and footer.
pub fn layout_main(area: Rect) -> (Rect, Rect, Rect, Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            // One text row plus the bottom separator. A third row leaves a
            // visually empty gap between navigation and the active screen.
            Constraint::Length(2), // Tabs
            Constraint::Min(0),    // Content
            Constraint::Length(3), // Footer
        ])
        .split(area);

    (chunks[0], chunks[1], chunks[2], chunks[3])
}
