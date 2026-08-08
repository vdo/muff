//! Smoke tests for the TUI: every screen must render without panicking,
//! the merged dashboard shows balance/node/activity/logs, and the receive
//! QR code only appears after pressing Enter on an address.

use muff::app::{AppState, TAB_COUNT};
use muff::config::Config;
use muff::ui;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::Color;

fn render(state: &mut AppState, width: u16, height: u16) -> Buffer {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| ui::render(frame, state)).unwrap();
    terminal.backend().buffer().clone()
}

fn buffer_text(buf: &Buffer) -> String {
    buf.content().iter().map(|cell| cell.symbol()).collect()
}

#[test]
fn all_tabs_render_without_panic() {
    let mut state = AppState::new(Config::default());
    for tab in 0..TAB_COUNT {
        state.active_tab = tab;
        let _ = render(&mut state, 120, 40);
    }
}

#[test]
fn dashboard_has_balance_node_activity_and_logs() {
    let mut state = AppState::new(Config::default());
    state.active_tab = 0;
    let buf = render(&mut state, 120, 40);
    let text = buffer_text(&buf);

    assert!(text.contains("Balance"), "balance pane missing: {text}");
    assert!(text.contains("Node"), "node pane missing: {text}");
    assert!(
        text.contains("Wallet — Recent Activity"),
        "activity pane missing: {text}"
    );
    assert!(text.contains("Logs"), "log pane missing: {text}");
    // The middle sync gauge is gone.
    assert!(!text.contains("Sync Status"), "sync gauge still present");
}

#[test]
fn log_lines_appear_on_the_dashboard_only() {
    let mut state = AppState::new(Config::default());
    state.log_buffer.push_line("hello-log-line".to_string());
    for tab in 0..TAB_COUNT {
        state.active_tab = tab;
        let text = buffer_text(&render(&mut state, 120, 40));
        if tab == 0 {
            assert!(text.contains("hello-log-line"), "dashboard hides logs");
        } else {
            assert!(
                !text.contains("hello-log-line"),
                "logs leaked onto tab {tab}"
            );
        }
    }
}

#[test]
fn qr_only_rendered_after_enter_on_an_address() {
    let mut state = AppState::new(Config::default());
    state.wallet_keys = Some(muff::wallet::derive_keys(
        &[7u8; 32],
        monero::Network::Stagenet,
    ));
    state.active_tab = 2;

    // The QR uses a white background; nothing else on the screen does.
    let has_white_bg = |buf: &Buffer| buf.content().iter().any(|cell| cell.bg == Color::White);

    let buf = render(&mut state, 120, 40);
    assert!(!has_white_bg(&buf), "QR visible before Enter was pressed");

    // Simulate pressing Enter on the selected address.
    state.receive_detail = true;
    let buf = render(&mut state, 120, 40);
    assert!(has_white_bg(&buf), "QR missing after Enter was pressed");
}
