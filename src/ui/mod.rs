pub mod components;
pub mod config;
pub mod dashboard;
pub mod history;
pub mod receive;
pub mod send;

use ratatui::Frame;
use ratatui::layout::Rect;

use crate::app::{AppState, MouseRegion};

/// Clickable regions collected during a render pass.
pub type Regions = Vec<(Rect, MouseRegion)>;

/// Truncate a long string for display by replacing its middle with "...".
/// Keeps at least `max` characters total when truncating.
pub fn truncate_middle(text: &str, max: usize) -> String {
    let len = text.chars().count();
    if len <= max || max < 8 {
        return text.to_string();
    }
    let keep = max - 3; // "..."
    let head = keep / 2 + keep % 2;
    let tail = keep / 2;
    let start: String = text.chars().take(head).collect();
    let end: String = text
        .chars()
        .rev()
        .take(tail)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{start}...{end}")
}

/// A centered popup rectangle of the given size, clamped to `area`.
pub fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width.saturating_sub(width)) / 2,
        area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    )
}

/// Main render function that dispatches to the active tab's renderer.
///
/// Takes `&mut AppState` so the renderers can register clickable mouse
/// regions for the frame they just drew (`state.mouse_regions`).
pub fn render(frame: &mut Frame, state: &mut AppState) {
    // While locked, only the lock screen is visible — nothing else renders
    // and nothing is clickable.
    if state.locked {
        state.mouse_regions = Vec::new();
        render_lock_screen(frame, state);
        return;
    }

    let area = frame.area();
    let (header_area, tabs_area, content_area, footer_area) = components::header::layout_main(area);

    let mut regions: Regions = Vec::new();

    // Render persistent UI elements
    components::header::render_header(frame, header_area, state);
    components::header::render_tabs(frame, tabs_area, state.active_tab, &mut regions);
    components::header::render_footer(frame, footer_area);

    // Render active tab content
    match state.active_tab {
        0 => dashboard::render_dashboard(frame, content_area, state),
        1 => send::render_send(frame, content_area, state, &mut regions),
        2 => receive::render_receive(frame, content_area, state, &mut regions),
        3 => history::render_history(frame, content_area, state, &mut regions),
        4 => config::render_config(frame, content_area, state, &mut regions),
        _ => dashboard::render_dashboard(frame, content_area, state),
    }

    // Modals sit above the tab content; while one is open the regions below
    // are inert (the key handler swallows input and clicks are ignored).
    if state.receive_detail {
        receive::render_detail_modal(frame, content_area, state);
    }
    if state.history_detail {
        history::render_detail_modal(frame, content_area, state);
    }
    config::render_config_modal(frame, content_area, state);
    send::render_book_modal(frame, content_area, state);

    // Help overlay on top of everything.
    if state.help_visible {
        render_help_overlay(frame, content_area);
    }

    state.mouse_regions = regions;
}

/// Render the idle-lock screen: masked password prompt, nothing else.
fn render_lock_screen(frame: &mut Frame, state: &AppState) {
    use ratatui::layout::{Constraint, Layout};
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Paragraph};

    let area = frame.area();
    let [_, mid, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(11),
        Constraint::Fill(1),
    ])
    .areas(area);
    let [_, center, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(56),
        Constraint::Fill(1),
    ])
    .areas(mid);

    let block = Block::default()
        .title(" Wallet Locked ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let masked = "•".repeat(state.unlock_password.chars().count());
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Locked due to inactivity.",
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
    if let Some(err) = &state.last_error {
        lines.push(Line::from(Span::styled(
            format!("  {err}"),
            Style::default().fg(Color::Red),
        )));
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        "  Enter: unlock    q / Ctrl-C: quit",
        Style::default().fg(Color::DarkGray),
    )));

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, center);
}

/// Render a centered help popup listing all keybindings.
fn render_help_overlay(frame: &mut Frame, area: Rect) {
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

    // Centered box: 60% wide, fixed height (sized to the content below).
    let width = (area.width * 60 / 100).clamp(56, 78).min(area.width);
    let height = 42u16.min(area.height);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let popup = Rect::new(x, y, width, height);

    frame.render_widget(Clear, popup);

    let lines = vec![
        Line::from(Span::styled(
            "  Global",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("    Left/Right (h/l)  switch screen"),
        Line::from("    1..5              jump to screen"),
        Line::from("    Tab / Shift-Tab   move to next / previous element"),
        Line::from("    r                 refresh balance & node status"),
        Line::from("    ?                 this help (any key or click closes)"),
        Line::from("    q / Ctrl-C        quit"),
        Line::from(""),
        Line::from(Span::styled(
            "  Moving between elements",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("    Tab / Shift-Tab   next / previous element (fields, rows)"),
        Line::from("    j/k, Up/Down      move within lists"),
        Line::from("    mouse             click tabs, fields, rows; wheel scrolls"),
        Line::from(""),
        Line::from(Span::styled(
            "  Send",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("    Tab, Up/Down      switch address / amount / address book"),
        Line::from("    [D] address  [A] amount  [B] book  [M] max (fee deducted)"),
        Line::from("    [P]                 cycle fee priority (low/normal/…)"),
        Line::from("    Enter             build transaction (in book: use entry)"),
        Line::from("    [N] / [X]         (in book) add / delete saved recipient"),
        Line::from("    [Y] / [N]         confirm or cancel broadcast"),
        Line::from("    Esc               back to dashboard"),
        Line::from(""),
        Line::from(Span::styled(
            "  Receive",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("    j/k, Up/Down, Tab select address"),
        Line::from("    Enter             show QR code & full address (again to close)"),
        Line::from("    [C]               copy selected address"),
        Line::from(""),
        Line::from(Span::styled(
            "  History",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("    j/k, Up/Down, Tab select transaction"),
        Line::from("    Enter             full transaction details"),
        Line::from("    PgUp/PgDn         scroll a page"),
        Line::from("    Home/End          first / last"),
        Line::from("    [C]               copy transaction hash"),
        Line::from(""),
        Line::from(Span::styled(
            "  Config",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("    Up/Down, Tab      select option"),
        Line::from("    Enter             activate (secrets ask the password)"),
        Line::from("                      seed & keys, password change, rescan,"),
        Line::from("                      daemon address"),
    ];

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Help — keybindings ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(widget, popup);
}
