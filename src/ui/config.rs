//! Config screen: wallet info, sensitive password-gated actions (seed and
//! private-key export, password change) and network maintenance (rescan
//! from height, daemon address edit).

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::app::{AppState, ChangePwStage, ConfigModal, MouseRegion, PasswordPurpose};
use crate::ui::{Regions, centered_rect};

/// The actionable option rows, in display order (name, dim hint).
/// `app.rs::activate_config_option` maps the index to the action.
const OPTIONS: [(&str, &str); 6] = [
    ("Reveal seed phrase", "requires wallet password"),
    ("Reveal private keys", "requires wallet password"),
    ("Change wallet password", "requires current password"),
    ("Rescan blockchain from height", "rescans outputs & history"),
    ("Change daemon address", "saved to config file"),
    ("Switch node", "pick from the failover pool"),
];

/// Render the config screen.
pub fn render_config(frame: &mut Frame, area: Rect, state: &AppState, regions: &mut Regions) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(6)])
        .split(area);

    render_info(frame, chunks[0], state);
    render_options(frame, chunks[1], state, regions);
}

/// Top pane: read-only wallet/network configuration summary.
fn render_info(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .title(" Wallet ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let network = match state.config.wallet.network {
        crate::config::NetworkKind::Mainnet => "Mainnet",
        crate::config::NetworkKind::Stagenet => "Stagenet",
        crate::config::NetworkKind::Testnet => "Testnet",
    };

    let row = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(
                format!("  {label:<12}"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(value, Style::default().fg(Color::White)),
        ])
    };

    let lines = vec![
        Line::from(""),
        row("Network", network.to_string()),
        row("Daemon", state.config.daemon.url.clone()),
        row(
            "Wallet file",
            state.config.wallet.path.display().to_string(),
        ),
        row(
            "Status",
            if state.wallet_keys.is_some() {
                "Unlocked".to_string()
            } else {
                "No wallet loaded".to_string()
            },
        ),
        Line::from(""),
    ];

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Bottom pane: selectable list of sensitive actions.
fn render_options(frame: &mut Frame, area: Rect, state: &AppState, regions: &mut Regions) {
    let block = Block::default()
        .title(" Security (↑↓/Tab select, Enter to activate) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    // One row per option, starting at content line 1 inside the border.
    let inner_x = area.x + 1;
    let inner_width = area.width.saturating_sub(2);
    let inner_bottom = area.bottom().saturating_sub(1);
    for (i, _) in OPTIONS.iter().enumerate() {
        let y = area.y + 1 + i as u16;
        if y < inner_bottom && inner_width > 0 {
            regions.push((
                Rect::new(inner_x, y, inner_width, 1),
                MouseRegion::ConfigRow(i),
            ));
        }
    }

    let mut lines: Vec<Line> = Vec::new();
    for (i, (name, hint)) in OPTIONS.iter().enumerate() {
        let selected = i == state.config_selected;
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
            Span::styled(*name, style),
            Span::styled(format!("   ({hint})"), Style::default().fg(Color::DarkGray)),
        ]));
    }

    lines.push(Line::from(""));
    if let Some(notice) = &state.config_notice {
        lines.push(Line::from(Span::styled(
            format!("  ✓ {notice}"),
            Style::default().fg(Color::Green),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  Secrets are shown on screen only, after password",
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(Span::styled(
            "  verification, and are cleared again on lock.",
            Style::default().fg(Color::DarkGray),
        )));
    }

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Render the active config-screen modal, if any.
/// No-op while `state.config_modal` is `Hidden`.
///
/// SECURITY: this is one of only two render sites of the seed phrase
/// (the other is the wizard's one-time backup screen).
pub fn render_config_modal(frame: &mut Frame, area: Rect, state: &AppState) {
    match &state.config_modal {
        ConfigModal::Hidden => {}
        ConfigModal::Password {
            password,
            error,
            next,
        } => {
            let purpose = match next {
                PasswordPurpose::Seed => "reveal the seed phrase",
                PasswordPurpose::Keys => "reveal the private keys",
            };
            render_password_prompt(frame, area, password, error, purpose)
        }
        ConfigModal::RevealedSeed(words) => render_revealed_seed(frame, area, words),
        ConfigModal::RevealedKeys { spend, view } => render_revealed_keys(frame, area, spend, view),
        ConfigModal::ChangePassword {
            stage,
            current,
            first,
            second,
            error,
        } => render_change_password(frame, area, *stage, current, first, second, error),
        ConfigModal::Rescan { input, error } => render_rescan(frame, area, state, input, error),
        ConfigModal::DaemonAddress { input, error } => {
            render_daemon_address(frame, area, state, input, error)
        }
        ConfigModal::NodePicker { selected } => render_node_picker(frame, area, state, *selected),
    }
}

/// The failover pool, with the active node marked and third-party nodes
/// labelled as such.
fn render_node_picker(frame: &mut Frame, area: Rect, state: &AppState, selected: usize) {
    let candidates = state.node_pool.candidates();
    let mut lines: Vec<Line> = vec![Line::from("")];

    if candidates.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No daemon endpoints configured.",
            Style::default().fg(Color::Red),
        )));
    }

    let active = state.node_pool.active_index();
    for (i, candidate) in candidates.iter().enumerate() {
        let marker = if i == active { "●" } else { " " };
        let style = if i == selected {
            Style::default().bg(Color::DarkGray).fg(Color::White)
        } else if i == active {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Gray)
        };
        // Third-party nodes get a colour of their own: picking one has
        // privacy consequences the other two sources do not.
        let source_style = match candidate.source {
            crate::rpc::NodeSource::Public => Style::default().fg(Color::Yellow),
            _ => Style::default().fg(Color::DarkGray),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {marker} "), style),
            Span::styled(candidate.url.clone(), style),
            Span::styled(format!("  [{}]", candidate.source.label()), source_style),
        ]));
    }

    lines.push(Line::from(""));
    if candidates
        .iter()
        .any(|c| c.source == crate::rpc::NodeSource::Public)
    {
        lines.push(Line::from(Span::styled(
            "  Public nodes see your IP and the transactions you ask about.",
            Style::default().fg(Color::Yellow),
        )));
    }
    lines.push(Line::from(Span::styled(
        "  ↑/↓: select    Enter: connect    Esc: cancel",
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(Span::styled(
        "  Switching here is temporary; the config file keeps its primary.",
        Style::default().fg(Color::DarkGray),
    )));

    // Size to the content: the pool is anywhere from one node to a dozen,
    // and a fixed height would either clip the list or float in whitespace.
    let width = candidates
        .iter()
        .map(|c| c.url.len() + c.source.label().len() + 12)
        .max()
        .unwrap_or(40)
        .clamp(52, 96) as u16;
    let popup = centered_rect(area, width, lines.len() as u16 + 2);
    frame.render_widget(Clear, popup);

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(" Switch node ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(widget, popup);
}

/// The masked password prompt shown before a secret is revealed.
fn render_password_prompt(
    frame: &mut Frame,
    area: Rect,
    password: &str,
    error: &Option<String>,
    purpose: &str,
) {
    let popup = centered_rect(area, 56, 11);
    frame.render_widget(Clear, popup);

    let masked = "•".repeat(password.chars().count());
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  Enter the wallet password to {purpose}."),
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Password: ", Style::default().fg(Color::White)),
            Span::styled(
                masked,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("█", Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
    ];
    if let Some(error) = error {
        lines.push(Line::from(Span::styled(
            format!("  ✗ {error}"),
            Style::default().fg(Color::Red),
        )));
    } else {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Enter: confirm    Esc: cancel",
        Style::default().fg(Color::DarkGray),
    )));

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(" Password required ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(widget, popup);
}

/// The revealed seed phrase (25 words for legacy seeds, 16 for polyseed),
/// numbered in a 3-column grid.
fn render_revealed_seed(frame: &mut Frame, area: Rect, words: &str) {
    let popup = centered_rect(area, 66, 17);
    frame.render_widget(Clear, popup);

    let words: Vec<&str> = words.split(' ').collect();
    let mut lines = vec![
        Line::from(Span::styled(
            "  Anyone with these words can steal your funds.",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    // Row-major numbering (1,2,3 / 4,5,6 / ...) matching the wizard's
    // backup screen, so comparing the two displays is straightforward.
    const COLS: usize = 3;
    const ROWS: usize = 9;
    for row in 0..ROWS {
        let mut spans = vec![Span::raw("  ")];
        for col in 0..COLS {
            let idx = row * COLS + col;
            if let Some(word) = words.get(idx) {
                spans.push(Span::styled(
                    format!("{:<4}", format!("{}.", idx + 1)),
                    Style::default().fg(Color::DarkGray),
                ));
                spans.push(Span::styled(
                    format!("{word:<16}"),
                    Style::default().fg(Color::White),
                ));
            }
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Word 25 is the checksum word (repeats one of words 1-24).",
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Esc/Enter: hide    [C]: copy to clipboard",
        Style::default().fg(Color::Yellow),
    )));

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(" Seed phrase — keep it secret ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red)),
    );
    frame.render_widget(widget, popup);
}

/// The revealed private spend/view keys (hex).
fn render_revealed_keys(frame: &mut Frame, area: Rect, spend: &str, view: &str) {
    let popup = centered_rect(area, 72, 13);
    frame.render_widget(Clear, popup);

    let lines = vec![
        Line::from(Span::styled(
            "  Anyone with these keys can steal (spend) or watch (view) your funds.",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Secret spend key:",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            format!("    {spend}"),
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Secret view key:",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            format!("    {view}"),
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Esc/Enter: hide    [C]: copy to clipboard",
            Style::default().fg(Color::Yellow),
        )),
    ];

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(" Private keys — keep them secret ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red)),
    );
    frame.render_widget(widget, popup);
}

/// The change-password flow (verify current → new → repeat).
fn render_change_password(
    frame: &mut Frame,
    area: Rect,
    stage: ChangePwStage,
    current: &str,
    first: &str,
    second: &str,
    error: &Option<String>,
) {
    let popup = centered_rect(area, 56, 11);
    frame.render_widget(Clear, popup);

    let (label, value) = match stage {
        ChangePwStage::Current => ("Current password", current),
        ChangePwStage::New => ("New password", first),
        ChangePwStage::Confirm => ("Repeat new password", second),
    };
    let masked = "\u{2022}".repeat(value.chars().count());
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            match stage {
                ChangePwStage::Current => "  Confirm the current password first.",
                ChangePwStage::New => "  Choose the new password (min. 4 characters).",
                ChangePwStage::Confirm => "  Repeat the new password.",
            },
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("  {label}: "), Style::default().fg(Color::White)),
            Span::styled(
                masked,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("\u{2588}", Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
    ];
    if let Some(error) = error {
        lines.push(Line::from(Span::styled(
            format!("  \u{2717} {error}"),
            Style::default().fg(Color::Red),
        )));
    } else {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Enter: confirm    Esc: cancel",
        Style::default().fg(Color::DarkGray),
    )));

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(" Change wallet password ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(widget, popup);
}

/// The rescan-from-height input.
fn render_rescan(
    frame: &mut Frame,
    area: Rect,
    state: &AppState,
    input: &str,
    error: &Option<String>,
) {
    let popup = centered_rect(area, 56, 12);
    frame.render_widget(Clear, popup);

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Rewind the scanner and rescan the chain for your outputs.",
            Style::default().fg(Color::Gray),
        )),
        Line::from(Span::styled(
            "  Use 1 for a full rescan.",
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  From height: ", Style::default().fg(Color::White)),
            Span::styled(
                input,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("\u{2588}", Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
    ];
    if let Some(error) = error {
        lines.push(Line::from(Span::styled(
            format!("  \u{2717} {error}"),
            Style::default().fg(Color::Red),
        )));
    } else if state.node_status.height > 0 {
        lines.push(Line::from(Span::styled(
            format!(
                "  Chain tip: {}",
                state.node_status.height.saturating_sub(1)
            ),
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Enter: start rescan    Esc: cancel",
        Style::default().fg(Color::DarkGray),
    )));

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(" Rescan blockchain ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(widget, popup);
}

/// The daemon-address input.
fn render_daemon_address(
    frame: &mut Frame,
    area: Rect,
    state: &AppState,
    input: &str,
    error: &Option<String>,
) {
    let popup = centered_rect(area, 64, 12);
    frame.render_widget(Clear, popup);

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Current: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                state.config.daemon.url.clone(),
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  New URL: ", Style::default().fg(Color::White)),
            Span::styled(
                input,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("\u{2588}", Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  e.g. http://127.0.0.1:18081 — saved to the config file.",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    if let Some(error) = error {
        lines.push(Line::from(Span::styled(
            format!("  \u{2717} {error}"),
            Style::default().fg(Color::Red),
        )));
    } else {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Enter: apply & reconnect    Esc: cancel",
        Style::default().fg(Color::DarkGray),
    )));

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(" Change daemon address ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(widget, popup);
}
