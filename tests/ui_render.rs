//! Smoke tests for the TUI: every screen must render without panicking,
//! the merged dashboard shows balance/node/activity/logs, and the receive
//! QR code only appears after pressing Enter on an address.

use muff::app::{AppState, TAB_COUNT};
use muff::config::Config;
use muff::event::AppEvent;
use muff::ui;
use muff::wallet::{OwnedOutput, ScanEvent};
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

fn owned_output(minor: u32, amount: u64, key: &str) -> OwnedOutput {
    OwnedOutput {
        tx_hash: format!("tx-{key}"),
        output_index: 0,
        key_hex: key.to_string(),
        height: 10,
        amount,
        spent: false,
        subaddress_major: 0,
        subaddress_minor: minor,
        timestamp: 1_700_000_000,
        unlock_height: 20,
    }
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

#[test]
fn addresses_show_balances_and_selected_send_source() {
    let mut state = AppState::new(Config::default());
    state.wallet_keys = Some(muff::wallet::derive_keys(
        &[8u8; 32],
        monero::Network::Stagenet,
    ));
    state.node_status.height = 100;
    state.send_from_minor = 2;
    state.receive_selected = 2;
    state.active_tab = 2;
    state.handle_event(AppEvent::Scan(ScanEvent::OutputFound(owned_output(
        2,
        1_234_000_000_000,
        "sub-two",
    ))));
    let mut restored_account_output = owned_output(3, 500_000_000_000, "account-one");
    restored_account_output.subaddress_major = 1;
    state.handle_event(AppEvent::Scan(ScanEvent::OutputFound(
        restored_account_output,
    )));

    let text = buffer_text(&render(&mut state, 120, 40));
    assert!(text.contains("Addresses"));
    assert!(text.contains("Sub #2"));
    assert!(text.contains("1.234000000000 XMR"));
    assert!(text.contains("Acct 1/3"));
    assert!(text.contains("0.500000000000 XMR"));
    assert!(text.contains("New address"));
    assert!(text.contains("Send from selected"));
}

#[test]
fn dashboard_separates_current_and_total_wallet_balance() {
    let mut state = AppState::new(Config::default());
    state.wallet_keys = Some(muff::wallet::derive_keys(
        &[9u8; 32],
        monero::Network::Stagenet,
    ));
    state.node_status.height = 100;
    state.send_from_minor = 2;
    state.handle_event(AppEvent::Scan(ScanEvent::OutputFound(owned_output(
        0,
        2_000_000_000_000,
        "primary",
    ))));
    state.handle_event(AppEvent::Scan(ScanEvent::OutputFound(owned_output(
        2,
        1_000_000_000_000,
        "sub-two",
    ))));

    let text = buffer_text(&render(&mut state, 120, 40));
    assert!(text.contains("Current · Sub #2"));
    assert!(text.contains("1.000000000000 XMR"));
    assert!(text.contains("Total wallet"));
    assert!(text.contains("3.000000000000 XMR"));
}
