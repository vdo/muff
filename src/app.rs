use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::event::AppEvent;
use crate::logbuf::LogBuffer;
use crate::rpc::{DaemonClient, NodeStatus};
use crate::wallet::{
    BalanceInfo, DEFAULT_RECEIVE_ADDRESS_COUNT, MIN_NEW_PASSWORD_CHARS, OwnedOutput, ScanEvent,
    Scanner, SendEvent, SendPriority, SendRequest, TransferDirection, TransferRecord, WalletDb,
    WalletKeys, format_xmr,
};

/// Which input field is focused on the send screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendField {
    Address,
    Amount,
    /// The address-book list pane.
    Book,
}

/// Number of tabs in the main UI (Dashboard, Send, Addresses, History,
/// Config). Node status is embedded in the dashboard.
pub const TAB_COUNT: usize = 5;

/// Consecutive failed status polls before rotating to the next node.
///
/// The poller runs every 5s, so this is ~15s of silence — long enough that a
/// brief hiccup does not bounce the wallet between endpoints, short enough
/// that a real outage does not strand a syncing wallet.
const FAILOVER_AFTER_POLLS: u32 = 3;

/// Whether a failed status poll should trigger rotation to the next node.
///
/// Split out from `AppState::consider_failover` so the policy is testable
/// without a live daemon client: the caller has already established that the
/// active node is down and bumped `failures`.
fn should_fail_over(failures: u32, can_fail_over: bool, send_in_flight: bool) -> bool {
    // Nowhere to go, or not yet convinced the node is really down.
    if !can_fail_over || failures < FAILOVER_AFTER_POLLS {
        return false;
    }
    // Retargeting drops the RPC client out from under whatever is using it.
    // Mid-send that would abort a transaction the user is watching, so let
    // the send finish (or fail on its own terms) first.
    !send_in_flight
}

/// Which sensitive action the config-screen password gate protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordPurpose {
    /// Reveal the seed phrase (25 words for legacy seeds, 16 for polyseed).
    Seed,
    /// Reveal the private spend/view keys.
    Keys,
}

/// Stage of the change-password flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangePwStage {
    /// Verifying the current password.
    Current,
    /// Entering the new password.
    New,
    /// Repeating the new password.
    Confirm,
}

/// State of the config-screen modals (secret reveals, password change,
/// rescan-from-height, daemon address edit).
///
/// SECURITY: revealed secrets and typed passwords are held in `Zeroizing`
/// buffers and the whole state is reset to `Hidden` on lock, so secrets
/// are never kept in memory longer than they are on screen. `Debug` is
/// derived manually to avoid leaking secrets into logs.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum ConfigModal {
    /// Nothing is shown.
    #[default]
    Hidden,
    /// The password prompt gating a secret reveal.
    Password {
        /// Masked password being typed (zeroized on drop/clear).
        password: Zeroizing<String>,
        /// Error from the last verification attempt.
        error: Option<String>,
        /// What to reveal on success.
        next: PasswordPurpose,
    },
    /// The seed phrase is on screen (space-separated words; 25 for legacy
    /// seeds, 16 for polyseed).
    RevealedSeed(Zeroizing<String>),
    /// The private keys are on screen (hex-encoded spend/view secrets).
    RevealedKeys {
        spend: Zeroizing<String>,
        view: Zeroizing<String>,
    },
    /// Change-password flow.
    ChangePassword {
        stage: ChangePwStage,
        current: Zeroizing<String>,
        first: Zeroizing<String>,
        second: Zeroizing<String>,
        error: Option<String>,
    },
    /// Rescan-from-height input.
    Rescan {
        input: String,
        error: Option<String>,
    },
    /// Daemon-address input.
    DaemonAddress {
        input: String,
        error: Option<String>,
    },
    /// Pick a daemon from the failover pool.
    NodePicker { selected: usize },
}

impl std::fmt::Debug for ConfigModal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print passwords, seeds, or keys.
        match self {
            ConfigModal::Hidden => f.write_str("Hidden"),
            ConfigModal::Password { .. } => f.write_str("Password(<redacted>)"),
            ConfigModal::RevealedSeed(_) => f.write_str("RevealedSeed(<redacted>)"),
            ConfigModal::RevealedKeys { .. } => f.write_str("RevealedKeys(<redacted>)"),
            ConfigModal::ChangePassword { .. } => f.write_str("ChangePassword(<redacted>)"),
            ConfigModal::Rescan { .. } => f.write_str("Rescan"),
            ConfigModal::DaemonAddress { .. } => f.write_str("DaemonAddress"),
            ConfigModal::NodePicker { .. } => f.write_str("NodePicker"),
        }
    }
}

/// Which field is focused in the address-book "add entry" modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookField {
    Label,
    Address,
}

/// State of the address-book "add entry" modal on the send screen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum BookModal {
    /// Nothing is shown.
    #[default]
    Hidden,
    /// The two-field add form is open.
    Adding {
        label: String,
        address: String,
        focus: BookField,
        error: Option<String>,
    },
}

/// A clickable/scrollable region of the UI, hit-tested against mouse events.
/// Regions are re-registered on every render by the `ui` module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseRegion {
    /// A tab in the tab bar.
    Tab(usize),
    /// One of the send-form input panes.
    SendField(SendField),
    /// The "`[Y]` Sign & broadcast" button on the confirm screen.
    ConfirmYes,
    /// The "`[N]` Cancel" button on the confirm screen.
    ConfirmNo,
    /// An address entry on the Addresses screen.
    ReceiveRow(usize),
    /// Allocate another account-0 subaddress.
    NewReceiveAddress,
    /// Make the highlighted address the only source for future sends.
    SelectReceiveSource,
    /// A transaction row (display order: 0 = newest) in the history table.
    HistoryRow(usize),
    /// An actionable option row on the config screen.
    ConfigRow(usize),
    /// An entry row in the send-screen address book.
    AddressBookRow(usize),
}

/// Copy text to the system clipboard, logging failures.
pub fn copy_to_clipboard(text: &str) {
    match arboard::Clipboard::new() {
        Ok(mut clipboard) => {
            if clipboard.set_text(text).is_ok() {
                tracing::info!("Copied to clipboard");
            } else {
                tracing::warn!("Failed to write to clipboard");
            }
        }
        Err(e) => {
            tracing::warn!("Failed to access clipboard: {e}");
        }
    }
}

/// Lifecycle stage of the send flow.
#[derive(Debug, Clone, PartialEq)]
pub enum SendStage {
    /// Editing the form.
    Entering,
    /// The engine is working (input selection, decoys, construction).
    Preparing(String),
    /// Waiting for the user to confirm the built transaction.
    Confirming {
        address: String,
        amount: u64,
        fee: u64,
        inputs: usize,
    },
    /// Transaction is signed and being published.
    Publishing,
    /// Transaction published successfully.
    Done { tx_hash: String, fee: u64 },
    /// Relay result was uncertain; the exact transaction is queued locally.
    StoredForRetry { tx_hash: String, fee: u64 },
    /// Sending failed (or was cancelled).
    Failed(String),
}

/// Central application state.
pub struct AppState {
    // Configuration
    pub config: Config,

    // Connection
    pub daemon: DaemonClient,
    pub node_status: NodeStatus,
    /// Ordered daemon endpoints to fall back through.
    pub node_pool: crate::rpc::NodePool,
    /// Consecutive failed status polls on the active node. Reset on every
    /// successful poll; failover triggers at [`FAILOVER_AFTER_POLLS`].
    node_failures: u32,

    // Wallet
    pub wallet_keys: Option<WalletKeys>,
    pub balance: BalanceInfo,
    pub owned_outputs: Vec<OwnedOutput>,
    pub transfers: Vec<TransferRecord>,
    pub scan_progress: Option<(u64, u64)>,

    // UI State
    pub active_tab: usize,
    pub running: bool,
    pub last_error: Option<String>,
    /// Whether the help overlay is visible.
    pub help_visible: bool,
    /// Clickable regions registered during the last render, used to
    /// hit-test mouse clicks. Rebuilt on every frame by `ui::render`.
    pub mouse_regions: Vec<(ratatui::layout::Rect, MouseRegion)>,
    /// Selected row in the history table.
    pub history_selected: usize,
    /// Whether the transaction detail modal is open on the history screen
    /// (toggled with Enter; follows `history_selected`).
    pub history_detail: bool,
    /// Result of the last CSV export, shown in the History footer.
    pub history_notice: Option<String>,
    /// Highlighted row on the Addresses screen (0 = primary).
    pub receive_selected: usize,
    /// Full subaddress index whose outputs may fund outgoing transactions.
    pub send_from_major: u32,
    pub send_from_minor: u32,
    /// Whether the full-address detail modal is open on the Addresses screen
    /// (toggled with Enter).
    pub receive_detail: bool,
    /// Selected option row on the config screen.
    pub config_selected: usize,
    /// Config-screen modal state (secret reveals, password change, rescan,
    /// daemon edit).
    pub config_modal: ConfigModal,
    /// Transient success notice shown on the config screen.
    pub config_notice: Option<String>,
    /// Captured tracing output, rendered on the dashboard log pane.
    pub log_buffer: LogBuffer,
    /// Path of the loaded config file (for persisting edits).
    config_path: Option<std::path::PathBuf>,
    /// Set by 'r': the main loop performs an immediate node-status refresh.
    pub force_status_refresh: bool,

    // Send form state
    pub send_field: SendField,
    pub send_address: String,
    pub send_amount: String,
    /// Sweep-all armed by `[M]` (or an amount equal to the unlocked balance):
    /// the fee is subtracted from the payment during construction.
    pub send_sweep: bool,
    /// Whether the privacy warning must be acknowledged before sweep-all is
    /// handed to the transaction engine.
    pub sweep_warning: bool,
    /// Fee priority tier, cycled with `[P]` on the send screen.
    pub send_fee_priority: SendPriority,
    pub send_stage: SendStage,
    pub send_confirm_tx: Option<oneshot::Sender<bool>>,
    /// Saved recipients (address book), shown on the send screen.
    pub address_book: Vec<crate::wallet::AddressBookEntry>,
    /// Selected address-book row.
    pub book_selected: usize,
    /// Address-book "add entry" modal.
    pub book_modal: BookModal,

    /// Encrypted wallet database, shared with the scanner and the send
    /// engine. `None` while the wallet is locked (dropped from memory).
    wallet_db: Option<Arc<WalletDb>>,
    /// Wallet password, kept only while unlocked so `WalletDb::save` can
    /// re-encrypt; zeroized on lock.
    wallet_password: Option<Zeroizing<String>>,
    /// Cancellation flag for the running scanner; set on idle lock.
    scan_cancel: Option<Arc<AtomicBool>>,
    /// Whether the wallet is currently locked (idle auto-lock).
    pub locked: bool,
    /// Password being typed on the lock screen (zeroized on clear).
    pub unlock_password: Zeroizing<String>,
    /// Last user activity, for idle auto-lock timing.
    last_activity: Instant,

    /// Wallet creation/restore height (scanner start when state is fresh).
    scan_start_height: u64,
    /// Whether the background scanner has been started.
    scanner_started: bool,

    /// Channel for spawning background tasks from event handling.
    event_tx: Option<mpsc::UnboundedSender<AppEvent>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let daemon = DaemonClient::new(&config);
        let node_pool = crate::rpc::NodePool::new(&config);
        Self {
            config,
            daemon,
            node_status: NodeStatus::default(),
            node_pool,
            node_failures: 0,
            wallet_keys: None,
            balance: BalanceInfo::default(),
            owned_outputs: Vec::new(),
            transfers: Vec::new(),
            scan_progress: None,
            active_tab: 0,
            running: true,
            last_error: None,
            help_visible: false,
            mouse_regions: Vec::new(),
            history_selected: 0,
            history_detail: false,
            history_notice: None,
            receive_selected: 0,
            send_from_major: 0,
            send_from_minor: 0,
            receive_detail: false,
            config_selected: 0,
            config_modal: ConfigModal::Hidden,
            config_notice: None,
            log_buffer: LogBuffer::new(),
            config_path: None,
            force_status_refresh: false,
            send_field: SendField::Address,
            send_address: String::new(),
            send_amount: String::new(),
            send_sweep: false,
            sweep_warning: false,
            send_fee_priority: SendPriority::default(),
            send_stage: SendStage::Entering,
            send_confirm_tx: None,
            address_book: Vec::new(),
            book_selected: 0,
            book_modal: BookModal::Hidden,
            wallet_db: None,
            wallet_password: None,
            scan_cancel: None,
            locked: false,
            unlock_password: Zeroizing::new(String::new()),
            last_activity: Instant::now(),
            scan_start_height: 0,
            scanner_started: false,
            event_tx: None,
        }
    }

    /// Store the event channel used to spawn background work.
    pub fn set_event_tx(&mut self, tx: mpsc::UnboundedSender<AppEvent>) {
        self.event_tx = Some(tx);
    }

    /// Record where the loaded config lives so edits can be persisted.
    pub fn set_config_path(&mut self, path: std::path::PathBuf) {
        self.config_path = Some(path);
    }

    /// Attach the shared log buffer that tracing writes into (rendered on
    /// the dashboard log pane).
    pub fn set_log_buffer(&mut self, log_buffer: LogBuffer) {
        self.log_buffer = log_buffer;
    }

    /// Record the wallet's creation/restore height (scanner start point).
    pub fn set_scan_start_height(&mut self, height: u64) {
        self.scan_start_height = height;
    }

    /// Attach the opened wallet database (and its password) to the app.
    pub fn set_wallet_db(&mut self, db: Arc<WalletDb>, password: &str) {
        self.wallet_db = Some(db);
        self.wallet_password = Some(Zeroizing::new(password.to_string()));
    }

    /// The shared wallet database, if unlocked.
    pub fn wallet_db(&self) -> Option<Arc<WalletDb>> {
        self.wallet_db.clone()
    }

    /// Populate in-memory balances/history from the wallet database.
    pub fn load_persisted_state(&mut self) {
        let Some(db) = &self.wallet_db else {
            return;
        };
        let Ok((outputs, history)) = db.ui_snapshot() else {
            return;
        };
        self.owned_outputs = outputs
            .iter()
            .filter_map(|o| {
                let output = crate::wallet::send::stored_to_wallet_output(o).ok()?;
                Some(OwnedOutput {
                    tx_hash: hex::encode(output.transaction()),
                    output_index: output.index_in_transaction() as usize,
                    key_hex: o.key_hex.clone(),
                    height: o.height,
                    amount: o.amount,
                    spent: o.spent,
                    subaddress_major: output.subaddress().map(|i| i.account()).unwrap_or(0),
                    subaddress_minor: output.subaddress().map(|i| i.address()).unwrap_or(0),
                    timestamp: o.timestamp,
                    unlock_height: crate::wallet::send::unlock_height(&output, o.height),
                })
            })
            .collect();
        // Older wallets may already contain payments to subaddresses beyond
        // the original five-row UI. Keep every observed account-0 address
        // visible and persist the migration once.
        let observed_count = self
            .owned_outputs
            .iter()
            .filter(|output| output.subaddress_major == 0)
            .map(|output| output.subaddress_minor.saturating_add(1))
            .max()
            .unwrap_or(DEFAULT_RECEIVE_ADDRESS_COUNT);
        match db.ensure_receive_address_count(observed_count) {
            Ok(true) => {
                if let Err(e) = db.save() {
                    tracing::warn!("failed to persist expanded address list: {e:#}");
                }
            }
            Ok(false) => {}
            Err(e) => tracing::warn!("failed to read address allocation state: {e:#}"),
        }
        (self.send_from_major, self.send_from_minor) =
            db.selected_send_subaddress().unwrap_or((0, 0));
        self.receive_selected = self
            .receive_selected
            .min(self.receive_address_count().saturating_sub(1));
        self.transfers = history;
        // Keep the history selection in range after a reload.
        if self.transfers.is_empty() {
            self.history_selected = 0;
        } else {
            self.history_selected = self.history_selected.min(self.transfers.len() - 1);
        }
        self.address_book = db.address_book_entries().unwrap_or_default();
        if self.address_book.is_empty() {
            self.book_selected = 0;
        } else {
            self.book_selected = self.book_selected.min(self.address_book.len() - 1);
        }
        self.recalculate_balance();
    }

    /// Handle an incoming application event and update state accordingly.
    pub fn handle_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Key(key) => {
                if self.locked {
                    self.handle_locked_key(key);
                } else {
                    self.last_activity = Instant::now();
                    self.handle_key(key);
                }
            }
            AppEvent::Mouse(mouse) => {
                if !self.locked {
                    self.last_activity = Instant::now();
                    self.handle_mouse(mouse);
                }
            }
            AppEvent::Paste(text) => {
                if self.locked {
                    self.unlock_password.push_str(text.trim());
                } else {
                    self.last_activity = Instant::now();
                    self.handle_paste(&text);
                }
            }
            AppEvent::Tick => {
                let timeout = self.config.security.idle_timeout_secs;
                if self.maybe_idle_lock(timeout) {
                    tracing::info!("wallet locked after {timeout}s of inactivity");
                }
            }
            AppEvent::NodeStatus(status) => {
                let was_disconnected = !self.node_status.connected;
                self.node_status = status;
                self.consider_failover();
                // Unlock-height transitions change both the selected-address
                // and whole-wallet available balances even without a newly
                // discovered output.
                self.recalculate_balance();
                // If the daemon just became reachable and the scanner isn't
                // running yet, establish the RPC connection and start it.
                if self.node_status.connected && !self.scanner_started && self.wallet_keys.is_some()
                {
                    self.scanner_started = true;
                    if let Some(tx) = self.event_tx.clone() {
                        let daemon = self.daemon.clone();
                        tokio::spawn(async move {
                            if (was_disconnected || !daemon.is_connected().await)
                                && let Err(e) = daemon.connect().await
                            {
                                tracing::warn!("reconnect failed: {e}");
                            }
                            let _ = tx.send(AppEvent::StartScanner);
                        });
                    }
                }
            }
            AppEvent::StartScanner => {
                if self.locked {
                    return;
                }
                if let Some(tx) = self.event_tx.clone() {
                    self.start_scanner(tx, self.scan_start_height);
                }
            }
            AppEvent::Scan(scan_event) => match scan_event {
                ScanEvent::Started { from_height: _ } => {
                    self.scan_progress = Some((0, 1));
                }
                ScanEvent::Progress { current, target } => {
                    self.scan_progress = Some((current, target));
                    // Progress means the last scan error (if any) recovered.
                    self.last_error = None;
                }
                ScanEvent::OutputFound(output) => {
                    // Deduplicate: check if we already have this output
                    let key = output.unique_key();
                    let already_known = self.owned_outputs.iter().any(|o| o.unique_key() == key);
                    if !already_known {
                        self.owned_outputs.push(output.clone());
                        self.recalculate_balance();

                        // Also add as a transfer record
                        self.transfers.push(TransferRecord {
                            tx_hash: output.tx_hash,
                            height: output.height,
                            timestamp: output.timestamp,
                            amount: output.amount,
                            fee: 0,
                            direction: TransferDirection::In,
                            confirmed: true,
                            failed: false,
                            note: format!(
                                "Subaddress {}/{}",
                                output.subaddress_major, output.subaddress_minor
                            ),
                        });
                    }
                }
                ScanEvent::OutputSpent { key_hex } => {
                    let mut changed = false;
                    for output in self.owned_outputs.iter_mut() {
                        if output.key_hex == key_hex && !output.spent {
                            output.spent = true;
                            changed = true;
                        }
                    }
                    if changed {
                        self.recalculate_balance();
                    }
                }
                ScanEvent::OutputUnspent { key_hex } => {
                    // A dropped transaction released this output.
                    let mut changed = false;
                    for output in self.owned_outputs.iter_mut() {
                        if output.key_hex == key_hex && output.spent {
                            output.spent = false;
                            changed = true;
                        }
                    }
                    if changed {
                        self.recalculate_balance();
                    }
                }
                ScanEvent::TransferFailed { tx_hash, reason } => {
                    for record in self.transfers.iter_mut() {
                        if record.tx_hash == tx_hash {
                            record.failed = true;
                            record.confirmed = false;
                        }
                    }
                    self.last_error = Some(format!(
                        "Transaction {}… {reason}; funds unlocked",
                        &tx_hash[..8.min(tx_hash.len())],
                    ));
                    if matches!(
                        &self.send_stage,
                        SendStage::StoredForRetry { tx_hash: pending, .. } if *pending == tx_hash
                    ) {
                        self.send_stage = SendStage::Failed(format!(
                            "Transaction {}… {reason}; funds unlocked",
                            &tx_hash[..8.min(tx_hash.len())]
                        ));
                    }
                    self.load_persisted_state();
                }
                ScanEvent::TransferRelayed { tx_hash } => {
                    if let SendStage::StoredForRetry {
                        tx_hash: pending,
                        fee,
                    } = &self.send_stage
                        && *pending == tx_hash
                    {
                        self.send_stage = SendStage::Done {
                            tx_hash: tx_hash.clone(),
                            fee: *fee,
                        };
                    }
                    self.load_persisted_state();
                }
                ScanEvent::Reorg { fork_height } => {
                    // State was rolled back and is being rescanned.
                    self.last_error = Some(format!(
                        "Chain reorg detected; rescanning from block {fork_height}"
                    ));
                    self.load_persisted_state();
                }
                ScanEvent::TransferConfirmed { tx_hash, height } => {
                    for record in self.transfers.iter_mut() {
                        if record.tx_hash == tx_hash && !record.confirmed {
                            record.confirmed = true;
                            record.failed = false;
                            record.height = height;
                        }
                    }
                }
                ScanEvent::Completed { height: _ } => {
                    self.scan_progress = None;
                    // The database persists scan progress itself; refresh the
                    // UI from it (catches spent marks made by the send engine
                    // and key-image checks).
                    self.load_persisted_state();
                }
                ScanEvent::Error(e) => {
                    // Keep the last known scan progress: the bar stays put
                    // while the error message explains why it is not moving.
                    self.last_error = Some(e);
                }
            },
            AppEvent::Send(send_event) => match send_event {
                SendEvent::Stage(msg) => {
                    self.send_stage = SendStage::Preparing(msg);
                }
                SendEvent::AwaitingConfirmation {
                    address,
                    amount,
                    fee,
                    inputs,
                } => {
                    self.send_stage = SendStage::Confirming {
                        address,
                        amount,
                        fee,
                        inputs,
                    };
                    // Bring the confirmation screen into view immediately —
                    // the user must review it before anything is broadcast.
                    self.active_tab = 1;
                }
                SendEvent::Published {
                    tx_hash,
                    fee,
                    warning,
                } => {
                    self.send_stage = SendStage::Done { tx_hash, fee };
                    self.send_confirm_tx = None;
                    // Reload state: the engine marked inputs spent and added
                    // the outgoing transfer record.
                    self.load_persisted_state();
                    if let Some(warning) = warning {
                        self.last_error = Some(warning);
                    }
                }
                SendEvent::StoredForRetry { tx_hash, fee } => {
                    self.send_stage = SendStage::StoredForRetry { tx_hash, fee };
                    self.send_confirm_tx = None;
                    // Inputs remain reserved in the durable pre-relay record;
                    // showing the refreshed balance prevents a replacement
                    // spend while the exact bytes await retry.
                    self.load_persisted_state();
                }
                SendEvent::Failed(msg) => {
                    self.send_stage = SendStage::Failed(msg);
                    self.send_confirm_tx = None;
                }
            },
            AppEvent::Quit => {
                self.running = false;
            }
        }
    }

    /// Recalculate balance from owned outputs.
    ///
    /// Uses the wallet-scanned height (`owned_outputs` heights) with the node
    /// height as a fallback — an output is unlocked at its `unlock_height`
    /// (10-block standard lock; 60 blocks for miner outputs).
    fn recalculate_balance(&mut self) {
        self.balance = self.balance_matching(|_| true);
    }

    fn balance_for_subaddress(&self, major: u32, minor: u32) -> BalanceInfo {
        self.balance_matching(|output| {
            output.subaddress_major == major && output.subaddress_minor == minor
        })
    }

    /// Calculate total/unlocked/locked values over a chosen output scope.
    /// Keeping this shared prevents the dashboard, Addresses tab, and send
    /// validation from disagreeing about lock-height semantics.
    fn balance_matching(&self, include: impl Fn(&OwnedOutput) -> bool) -> BalanceInfo {
        let mut total = 0u64;
        let mut unlocked = 0u64;
        let mut locked = 0u64;

        // `chain_height` is the block count, so the latest block number
        // (chain tip) is one less; an output is unlocked when
        // `unlock_height <= tip`.
        let chain_height = self.node_status.height.max(
            self.owned_outputs
                .iter()
                .map(|o| o.height)
                .max()
                .unwrap_or(0),
        );

        for output in &self.owned_outputs {
            if output.spent || !include(output) {
                continue;
            }
            total += output.amount;
            if chain_height > output.unlock_height {
                unlocked += output.amount;
            } else {
                locked += output.amount;
            }
        }

        BalanceInfo {
            total,
            unlocked,
            locked,
        }
    }

    /// Whether a send is in a stage that must not be interrupted by locking
    /// (the engine holds a confirmation channel the user must answer).
    fn send_in_flight(&self) -> bool {
        matches!(
            self.send_stage,
            SendStage::Preparing(_) | SendStage::Confirming { .. } | SendStage::Publishing
        )
    }

    /// Lock the wallet when it has been idle longer than `idle_secs`.
    /// `0` disables the auto-lock. Returns true when the wallet was locked.
    pub fn maybe_idle_lock(&mut self, idle_secs: u64) -> bool {
        if idle_secs == 0 || self.locked || self.wallet_db.is_none() {
            return false;
        }
        if self.send_in_flight() {
            // Never lock mid-send; keep the idle clock from expiring so the
            // wallet locks promptly once the send finishes.
            self.last_activity = Instant::now();
            return false;
        }
        if self.last_activity.elapsed() < std::time::Duration::from_secs(idle_secs) {
            return false;
        }
        self.lock();
        true
    }

    /// Lock immediately: stop the scanner and drop all decrypted material
    /// (keys, password, database) from memory, then show the lock screen.
    pub fn lock(&mut self) {
        if self.locked || self.wallet_db.is_none() {
            return;
        }
        if let Some(cancel) = &self.scan_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        self.scan_cancel = None;
        // Drop decrypted state; WalletKeys/Zeroizing zeroize on drop.
        self.wallet_db = None;
        self.wallet_keys = None;
        self.wallet_password = None;
        self.balance = BalanceInfo::default();
        self.owned_outputs.clear();
        self.transfers.clear();
        self.scan_progress = None;
        self.history_selected = 0;
        self.history_detail = false;
        self.receive_selected = 0;
        self.send_from_major = 0;
        self.send_from_minor = 0;
        self.receive_detail = false;
        self.config_selected = 0;
        // SECURITY: drop any on-screen secrets / typed passwords.
        self.config_modal = ConfigModal::Hidden;
        self.config_notice = None;
        self.send_field = SendField::Address;
        self.send_address = String::new();
        self.send_amount = String::new();
        self.send_sweep = false;
        self.sweep_warning = false;
        self.send_stage = SendStage::Entering;
        self.send_confirm_tx = None;
        self.address_book.clear();
        self.book_selected = 0;
        self.book_modal = BookModal::Hidden;
        self.unlock_password = Zeroizing::new(String::new());
        self.help_visible = false;
        self.locked = true;
        self.scanner_started = false;
    }

    /// Handle keys on the lock screen: masked password entry + unlock.
    fn handle_locked_key(&mut self, key: crossterm::event::KeyEvent) {
        match (key.modifiers, key.code) {
            (KeyModifiers::CONTROL, KeyCode::Char('c')) => {
                self.running = false;
            }
            (KeyModifiers::NONE, KeyCode::Char('q')) => {
                self.running = false;
            }
            (_, KeyCode::Enter) => self.try_unlock(),
            (_, KeyCode::Backspace) => {
                self.unlock_password.pop();
            }
            (m, KeyCode::Char(c)) if m.is_empty() || m == KeyModifiers::SHIFT => {
                self.unlock_password.push(c);
                self.last_error = None;
            }
            _ => {}
        }
    }

    /// Attempt to unlock: reopen the encrypted database, re-derive keys,
    /// restore UI state and restart the scanner.
    fn try_unlock(&mut self) {
        if self.unlock_password.is_empty() {
            self.last_error = Some("Enter the wallet password".to_string());
            return;
        }
        let password = Zeroizing::new(self.unlock_password.to_string());
        self.unlock_password = Zeroizing::new(String::new());

        let path = self.config.wallet.path.clone();
        let db = match WalletDb::open(&path, password.as_bytes()) {
            Ok(db) => Arc::new(db),
            Err(e) => {
                tracing::warn!("unlock failed: {e:#}");
                self.last_error = Some("Incorrect password".to_string());
                return;
            }
        };
        let keys = match db.seed() {
            Ok(seed) => crate::wallet::derive_keys(&seed, self.config.wallet.network.into()),
            Err(e) => {
                self.last_error = Some(format!("Failed to read wallet database: {e:#}"));
                return;
            }
        };

        self.wallet_db = Some(db);
        self.wallet_password = Some(password);
        self.wallet_keys = Some(keys);
        self.locked = false;
        self.last_error = None;
        self.last_activity = Instant::now();
        self.load_persisted_state();

        // Restart the scanner from the persisted position.
        self.scanner_started = false;
        if let Some(tx) = self.event_tx.clone() {
            self.start_scanner(tx, self.scan_start_height);
        }
        tracing::info!("wallet unlocked");
    }

    fn handle_key(&mut self, key: crossterm::event::KeyEvent) {
        // Ctrl-C always quits, even while a modal is open.
        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
            self.running = false;
            return;
        }

        // Help overlay swallows all keys; any key closes it.
        if self.help_visible {
            self.help_visible = false;
            return;
        }

        // Sweep-all can correlate every input it consolidates. Require a
        // dedicated acknowledgement before any transaction construction.
        if self.sweep_warning {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    self.sweep_warning = false;
                    self.start_send_with_sweep_ack(true);
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.sweep_warning = false;
                }
                _ => {}
            }
            return;
        }

        // The config-screen modals swallow everything (a password may
        // contain any character, including 'q' or digits).
        if self.config_modal != ConfigModal::Hidden {
            self.handle_config_modal_key(key);
            return;
        }

        // The address-book "add entry" modal swallows keys too.
        if self.book_modal != BookModal::Hidden {
            self.handle_book_modal_key(key);
            return;
        }

        // The full-address detail modal swallows keys until dismissed.
        if self.receive_detail {
            match key.code {
                KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q') => {
                    self.receive_detail = false;
                }
                KeyCode::Char('C') => {
                    if let Some(addr) = self.receive_address_string(self.receive_selected) {
                        copy_to_clipboard(&addr);
                    }
                }
                _ => {}
            }
            return;
        }

        // The transaction detail modal swallows keys until dismissed;
        // Up/Down keep navigating (the modal follows the selection).
        if self.history_detail {
            let len = self.transfers.len();
            match key.code {
                KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q') => {
                    self.history_detail = false;
                }
                KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                    self.history_selected = self.history_selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                    if len > 0 {
                        self.history_selected = (self.history_selected + 1).min(len - 1);
                    }
                }
                KeyCode::Char('C') => {
                    if len > 0 {
                        let storage_idx = len - 1 - self.history_selected.min(len - 1);
                        if let Some(record) = self.transfers.get(storage_idx) {
                            let hash = record.tx_hash.clone();
                            copy_to_clipboard(&hash);
                        }
                    }
                }
                _ => {}
            }
            return;
        }

        // On the send tab, route keys to the send handler first; it consumes
        // almost everything while a form field or confirmation is active so
        // typing an address never triggers global shortcuts (e.g. 'q').
        if self.active_tab == 1 {
            self.handle_send_keys(key);
            return;
        }

        // Global keys
        match (key.modifiers, key.code) {
            (_, KeyCode::Char('q')) => {
                self.running = false;
                return;
            }
            (_, KeyCode::Char('?')) => {
                self.help_visible = true;
                return;
            }
            (_, KeyCode::Char('r')) => {
                // Reload wallet state and request an immediate node refresh.
                self.load_persisted_state();
                self.force_status_refresh = true;
                self.last_error = None;
                self.history_notice = None;
                return;
            }
            // Left/Right (and h/l) move between screens; Tab moves focus
            // between the elements *within* the active screen (handled by the
            // per-tab key handlers below).
            (_, KeyCode::Left) | (_, KeyCode::Char('h')) => {
                self.active_tab = (self.active_tab + TAB_COUNT - 1) % TAB_COUNT;
                return;
            }
            (_, KeyCode::Right) | (_, KeyCode::Char('l')) => {
                self.active_tab = (self.active_tab + 1) % TAB_COUNT;
                return;
            }
            (_, KeyCode::Char(d @ '1'..='5')) => {
                self.active_tab = (d as usize - '1' as usize) % TAB_COUNT;
                return;
            }
            _ => {}
        }

        // Tab-specific keys. Tab/BackTab move focus across the elements of
        // the active screen (list selection on Addresses/History/Config).
        match self.active_tab {
            2 => self.handle_receive_keys(key),
            3 => self.handle_history_keys(key),
            4 => self.handle_config_keys(key),
            _ => {}
        }
    }

    /// History tab: scroll with Up/Down (or j/k), PgUp/PgDn for pages,
    /// Home/End to jump, 'c' to copy the selected transaction hash.
    /// `history_selected` is in display order: 0 = newest (top row).
    fn handle_history_keys(&mut self, key: crossterm::event::KeyEvent) {
        // Export is handled before the empty guard so pressing [E] with no
        // transfers reports why nothing happened rather than doing nothing.
        if key.code == KeyCode::Char('E') {
            self.export_history_csv();
            return;
        }
        let len = self.transfers.len();
        if len == 0 {
            return;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.history_selected = self.history_selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.history_selected = (self.history_selected + 1).min(len - 1);
            }
            // h/l now switch screens (global); PgUp/PgDn keep page scrolling.
            KeyCode::PageUp => {
                self.history_selected = self.history_selected.saturating_sub(10);
            }
            KeyCode::PageDown => {
                self.history_selected = (self.history_selected + 10).min(len - 1);
            }
            KeyCode::Home => self.history_selected = 0,
            KeyCode::End => self.history_selected = len - 1,
            // Enter opens the full-detail modal for the selected transaction.
            KeyCode::Enter => {
                self.history_detail = true;
            }
            // [C] = Shift+C copies the selected transaction hash.
            KeyCode::Char('C') => {
                // Display order is reversed storage order.
                let storage_idx = len - 1 - self.history_selected.min(len - 1);
                if let Some(record) = self.transfers.get(storage_idx) {
                    let hash = record.tx_hash.clone();
                    copy_to_clipboard(&hash);
                }
            }
            // [E] = Shift+E exports the whole history to CSV.
            KeyCode::Char('E') => self.export_history_csv(),
            _ => {}
        }
    }

    /// Write the full transaction history to a timestamped CSV next to the
    /// wallet file, and report where it landed.
    ///
    /// The wallet directory is the one place guaranteed to exist and be
    /// writable, and it keeps an export that names amounts and transaction
    /// ids out of a shared location like the home directory or /tmp.
    fn export_history_csv(&mut self) {
        if self.transfers.is_empty() {
            self.history_notice = Some("Nothing to export yet.".to_string());
            return;
        }

        let dir = self
            .config
            .wallet
            .path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let path = dir.join(crate::wallet::default_filename(chrono::Utc::now()));

        let csv = crate::wallet::history_to_csv(&self.transfers);
        self.history_notice = match std::fs::write(&path, csv) {
            Ok(()) => {
                let count = self.transfers.len();
                tracing::info!("exported {count} transfers to {}", path.display());
                Some(format!("Exported {count} transfers to {}", path.display()))
            }
            Err(e) => {
                tracing::warn!("history export failed: {e:#}");
                Some(format!("Export failed: {e}"))
            }
        };
    }

    fn handle_send_keys(&mut self, key: crossterm::event::KeyEvent) {
        // Ctrl-C always quits.
        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
            self.running = false;
            return;
        }

        // Left/Right are global screen navigation (arrows are never typed
        // into the text fields). '?' is safe to globalize too (not a base58
        // address character).
        match key.code {
            KeyCode::Left => {
                self.active_tab = (self.active_tab + TAB_COUNT - 1) % TAB_COUNT;
                return;
            }
            KeyCode::Right => {
                self.active_tab = (self.active_tab + 1) % TAB_COUNT;
                return;
            }
            KeyCode::Char('?') => {
                self.help_visible = true;
                return;
            }
            _ => {}
        }

        match self.send_stage.clone() {
            SendStage::Entering => match key.code {
                // Tab/Shift-Tab cycle focus through the fields and the
                // address-book pane. hjkl stay available as text input (they
                // are valid base58 address characters); use the Shift+letter
                // jumps below to focus a field directly.
                KeyCode::Tab => {
                    self.send_field = match self.send_field {
                        SendField::Address => SendField::Amount,
                        SendField::Amount => SendField::Book,
                        SendField::Book => SendField::Address,
                    };
                }
                KeyCode::BackTab => {
                    self.send_field = match self.send_field {
                        SendField::Address => SendField::Book,
                        SendField::Amount => SendField::Address,
                        SendField::Book => SendField::Amount,
                    };
                }
                // Up/Down move the book selection while the book is focused,
                // otherwise they switch fields.
                KeyCode::Down => match self.send_field {
                    SendField::Address => self.send_field = SendField::Amount,
                    SendField::Amount => self.send_field = SendField::Book,
                    SendField::Book => {
                        if !self.address_book.is_empty() {
                            self.book_selected = (self.book_selected + 1) % self.address_book.len();
                        }
                    }
                },
                KeyCode::Up => match self.send_field {
                    SendField::Address => self.send_field = SendField::Book,
                    SendField::Amount => self.send_field = SendField::Address,
                    SendField::Book => {
                        if !self.address_book.is_empty() {
                            self.book_selected = if self.book_selected == 0 {
                                self.address_book.len() - 1
                            } else {
                                self.book_selected - 1
                            };
                        }
                    }
                },
                // Shift+letter actions, shown as [X] hints in the pane
                // titles. Pasted text bypasses key handling entirely
                // (bracketed paste), so uppercase letters in pasted
                // addresses are unaffected.
                KeyCode::Char('D') => self.send_field = SendField::Address,
                KeyCode::Char('A') => self.send_field = SendField::Amount,
                KeyCode::Char('B') => self.send_field = SendField::Book,
                KeyCode::Char('M') => {
                    // Sweep only the source selected on the Addresses tab.
                    // The engine subtracts the fee from that address's
                    // unlocked balance.
                    let source_balance = self.current_address_balance();
                    if source_balance.unlocked > 0 {
                        self.send_amount = format_xmr(source_balance.unlocked)
                            .trim_end_matches(" XMR")
                            .to_string();
                        self.send_sweep = true;
                        self.send_field = SendField::Amount;
                    }
                }
                KeyCode::Char('P') => {
                    // Cycle the fee priority tier (Low/Normal/Elevated/
                    // Priority), shown in the form and the confirm screen.
                    self.send_fee_priority = self.send_fee_priority.next();
                }
                KeyCode::Enter => match self.send_field {
                    SendField::Book => self.book_use_selected(),
                    _ => self.start_send(),
                },
                KeyCode::Char(c) => match self.send_field {
                    SendField::Address => self.send_address.push(c),
                    SendField::Amount => {
                        if c.is_ascii_digit() || c == '.' {
                            self.send_amount.push(c);
                            // Hand-editing after [M] disarms the sweep.
                            self.send_sweep = false;
                        }
                    }
                    SendField::Book => match c {
                        'n' | 'N' => {
                            self.book_modal = BookModal::Adding {
                                label: String::new(),
                                address: self.send_address.trim().to_string(),
                                focus: BookField::Label,
                                error: None,
                            };
                        }
                        'x' | 'X' => self.book_remove_selected(),
                        _ => {}
                    },
                },
                KeyCode::Backspace => match self.send_field {
                    SendField::Address => {
                        self.send_address.pop();
                    }
                    SendField::Amount => {
                        self.send_amount.pop();
                        self.send_sweep = false;
                    }
                    SendField::Book => {}
                },
                KeyCode::Esc => {
                    self.send_address.clear();
                    self.send_amount.clear();
                    self.send_sweep = false;
                    self.active_tab = 0;
                }
                _ => {}
            },
            SendStage::Confirming { .. } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    if let Some(tx) = self.send_confirm_tx.take() {
                        let _ = tx.send(true);
                        self.send_stage = SendStage::Publishing;
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    if let Some(tx) = self.send_confirm_tx.take() {
                        let _ = tx.send(false);
                    }
                    self.send_stage = SendStage::Failed("Cancelled by user".to_string());
                }
                _ => {}
            },
            SendStage::Done { .. } | SendStage::StoredForRetry { .. } | SendStage::Failed(_) => {
                match key.code {
                    KeyCode::Enter | KeyCode::Esc => {
                        self.send_stage = SendStage::Entering;
                        self.send_address.clear();
                        self.send_amount.clear();
                        self.send_sweep = false;
                        self.active_tab = 0;
                    }
                    _ => {}
                }
            }
            SendStage::Preparing(_) | SendStage::Publishing => {
                // Read-only stages; allow navigating back to the dashboard
                // (the engine keeps running in the background).
                if key.code == KeyCode::Esc {
                    self.active_tab = 0;
                }
            }
        }
    }

    /// Validate the form and spawn the send engine.
    fn start_send(&mut self) {
        self.start_send_with_sweep_ack(false);
    }

    fn start_send_with_sweep_ack(&mut self, sweep_acknowledged: bool) {
        if self.wallet_keys.is_none() {
            self.send_stage = SendStage::Failed("No wallet loaded".to_string());
            return;
        }
        let Some(event_tx) = self.event_tx.clone() else {
            self.send_stage = SendStage::Failed("Internal error: no event channel".to_string());
            return;
        };
        let Some(db) = self.wallet_db.clone() else {
            self.send_stage = SendStage::Failed("Wallet is locked".to_string());
            return;
        };
        let Some(cancel) = self.scan_cancel.clone() else {
            self.send_stage = SendStage::Failed("Scanner not running".to_string());
            return;
        };

        let address = self.send_address.trim().to_string();
        if address.is_empty() {
            self.send_stage = SendStage::Failed("Recipient address is empty".to_string());
            return;
        }
        // Fail fast with a clear message before involving the engine.
        let wallet_network: monero::Network = self.config.wallet.network.into();
        let parsed = match monero::Address::from_str(&address) {
            Ok(parsed) => parsed,
            Err(e) => {
                self.send_stage = SendStage::Failed(format!("Invalid address: {e}"));
                return;
            }
        };
        if parsed.network != wallet_network {
            self.send_stage = SendStage::Failed(format!(
                "Address is for {:?} but this wallet is on {:?}",
                parsed.network, wallet_network
            ));
            return;
        }
        let Some(amount) = crate::wallet::keys::parse_xmr(&self.send_amount) else {
            self.send_stage =
                SendStage::Failed("Invalid amount (up to 12 decimal places)".to_string());
            return;
        };
        if amount == 0 {
            self.send_stage = SendStage::Failed("Amount must be greater than zero".to_string());
            return;
        }
        let source_balance = self.current_address_balance();
        if source_balance.unlocked < amount {
            self.send_stage = SendStage::Failed(format!(
                "Insufficient unlocked balance in {} ({})",
                self.current_address_label(),
                crate::wallet::format_xmr(source_balance.unlocked)
            ));
            return;
        }

        // Sweep-all: armed explicitly with [M], or implicitly when the typed
        // amount equals the whole unlocked balance (such a send can never
        // succeed with the fee on top, so the fee is subtracted from the
        // payment instead).
        let sweep_all =
            self.send_sweep || (source_balance.unlocked > 0 && amount == source_balance.unlocked);
        if sweep_all && !sweep_acknowledged {
            self.sweep_warning = true;
            return;
        }

        let (confirm_tx, confirm_rx) = oneshot::channel::<bool>();
        self.send_confirm_tx = Some(confirm_tx);
        self.send_stage = SendStage::Preparing("Starting".to_string());

        let daemon = self.daemon.clone();
        let keys = self.wallet_keys.clone().expect("checked above");
        let req = SendRequest {
            address,
            amount,
            sweep_all,
            priority: self.send_fee_priority.to_fee_priority(),
            source: (self.send_from_major, self.send_from_minor),
        };

        tokio::spawn(async move {
            crate::wallet::send::execute_send(daemon, keys, db, req, confirm_rx, event_tx, cancel)
                .await;
        });
    }

    /// Fill the send form's address field from the selected address-book
    /// entry and jump back to the address field for review.
    fn book_use_selected(&mut self) {
        if let Some(entry) = self.address_book.get(self.book_selected) {
            self.send_address = entry.address.clone();
            self.send_field = SendField::Address;
        }
    }

    /// Delete the selected address-book entry from the wallet database.
    fn book_remove_selected(&mut self) {
        let Some(db) = self.wallet_db.clone() else {
            return;
        };
        let Some(entry) = self.address_book.get(self.book_selected) else {
            return;
        };
        let id = entry.id;
        let label = entry.label.clone();
        match db.address_book_remove(id).and_then(|_| db.save()) {
            Ok(_) => {
                self.address_book.retain(|e| e.id != id);
                if self.book_selected >= self.address_book.len() {
                    self.book_selected = self.address_book.len().saturating_sub(1);
                }
                tracing::info!("address book: removed '{label}'");
            }
            Err(e) => {
                self.last_error = Some(format!("Failed to remove address book entry: {e:#}"));
            }
        }
    }

    /// Handle keys while the address-book "add entry" modal is open.
    fn handle_book_modal_key(&mut self, key: crossterm::event::KeyEvent) {
        let BookModal::Adding {
            mut label,
            mut address,
            focus,
            ..
        } = self.book_modal.clone()
        else {
            return;
        };
        let set = |label: String, address: String, focus: BookField| BookModal::Adding {
            label,
            address,
            focus,
            error: None,
        };
        match key.code {
            KeyCode::Esc => self.book_modal = BookModal::Hidden,
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Down | KeyCode::Up => {
                let next = match focus {
                    BookField::Label => BookField::Address,
                    BookField::Address => BookField::Label,
                };
                self.book_modal = set(label, address, next);
            }
            KeyCode::Enter => match focus {
                BookField::Label => {
                    self.book_modal = set(label, address, BookField::Address);
                }
                BookField::Address => self.book_add_submit(),
            },
            KeyCode::Backspace => {
                match focus {
                    BookField::Label => {
                        label.pop();
                    }
                    BookField::Address => {
                        address.pop();
                    }
                }
                self.book_modal = set(label, address, focus);
            }
            KeyCode::Char(c)
                if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
            {
                match focus {
                    BookField::Label => label.push(c),
                    // Addresses are single-line base58; ignore whitespace.
                    BookField::Address if !c.is_whitespace() => address.push(c),
                    BookField::Address => {}
                }
                self.book_modal = set(label, address, focus);
            }
            _ => {}
        }
    }

    /// Show an error inside the address-book "add entry" modal, keeping the
    /// typed values.
    fn book_add_fail(&mut self, msg: &str) {
        if let BookModal::Adding { label, address, .. } = self.book_modal.clone() {
            self.book_modal = BookModal::Adding {
                label,
                address,
                focus: BookField::Address,
                error: Some(msg.to_string()),
            };
        }
    }

    /// Validate and save the address-book "add entry" form.
    fn book_add_submit(&mut self) {
        let BookModal::Adding { label, address, .. } = self.book_modal.clone() else {
            return;
        };
        let label = label.trim().to_string();
        let address = address.trim().to_string();
        if label.is_empty() {
            self.book_add_fail("Label is empty");
            return;
        }
        let wallet_network: monero::Network = self.config.wallet.network.into();
        match monero::Address::from_str(&address) {
            Ok(parsed) if parsed.network == wallet_network => {}
            Ok(parsed) => {
                self.book_add_fail(&format!(
                    "Address is for {:?} but this wallet is on {:?}",
                    parsed.network, wallet_network
                ));
                return;
            }
            Err(e) => {
                self.book_add_fail(&format!("Invalid address: {e}"));
                return;
            }
        }
        let Some(db) = self.wallet_db.clone() else {
            self.book_add_fail("Wallet is locked");
            return;
        };
        match db
            .address_book_add(&label, &address)
            .and_then(|_| db.save())
        {
            Ok(_) => {
                self.book_modal = BookModal::Hidden;
                self.load_persisted_state();
            }
            Err(e) => {
                self.book_add_fail(&format!("Save failed: {e:#}"));
            }
        }
    }

    fn handle_receive_keys(&mut self, key: crossterm::event::KeyEvent) {
        let count = self.receive_address_count();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.receive_selected = if self.receive_selected == 0 {
                    count.saturating_sub(1)
                } else {
                    self.receive_selected - 1
                };
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.receive_selected = (self.receive_selected + 1) % count.max(1);
            }
            // Enter opens the detail modal with the full (untruncated)
            // address.
            KeyCode::Enter => {
                if self.wallet_keys.is_some() {
                    self.receive_detail = true;
                }
            }
            // [C] = Shift+C copies the selected address.
            KeyCode::Char('C') => {
                if let Some(addr) = self.receive_address_string(self.receive_selected) {
                    copy_to_clipboard(&addr);
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') => self.allocate_receive_address(),
            KeyCode::Char('s') | KeyCode::Char('S') => self.select_receive_source(),
            _ => {}
        }
    }

    /// Persist one additional account-0 subaddress and highlight it. The
    /// running scanner observes the allocation metadata before its next block
    /// chunk, so an address is never displayed outside its scan frontier.
    fn allocate_receive_address(&mut self) {
        let Some(db) = self.wallet_db.clone() else {
            self.last_error = Some("Wallet is locked".to_string());
            return;
        };
        match db.allocate_receive_address().and_then(|minor| {
            db.save()?;
            Ok(minor)
        }) {
            Ok(minor) => {
                self.receive_selected = minor as usize;
                self.last_error = None;
                tracing::info!("allocated subaddress 0/{minor}");
            }
            Err(e) => {
                self.last_error = Some(format!("Failed to create address: {e:#}"));
            }
        }
    }

    /// Restrict subsequent sends to the highlighted address. Persisting this
    /// choice makes dashboard and send balances stable across restarts.
    fn select_receive_source(&mut self) {
        if self.send_in_flight() {
            self.last_error = Some(
                "Cannot change the send source while a transaction is in progress".to_string(),
            );
            return;
        }
        let Some(db) = self.wallet_db.clone() else {
            self.last_error = Some("Wallet is locked".to_string());
            return;
        };
        let (major, minor) = self.receive_subaddress_index(self.receive_selected);
        match db
            .set_selected_send_subaddress(major, minor)
            .and_then(|()| db.save())
        {
            Ok(()) => {
                self.send_from_major = major;
                self.send_from_minor = minor;
                self.send_sweep = false;
                self.send_amount.clear();
                self.last_error = None;
                tracing::info!("outgoing source set to subaddress {major}/{minor}");
            }
            Err(e) => {
                self.last_error = Some(format!("Failed to select send address: {e:#}"));
            }
        }
    }

    /// Config screen: Up/Down (or Tab) move between the option rows,
    /// Enter activates the selected option.
    fn handle_config_keys(&mut self, key: crossterm::event::KeyEvent) {
        /// Number of actionable option rows on the config screen.
        const CONFIG_OPTIONS: usize = 6;
        match key.code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.config_selected = self.config_selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.config_selected = (self.config_selected + 1).min(CONFIG_OPTIONS - 1);
            }
            KeyCode::Enter => self.activate_config_option(),
            _ => {}
        }
    }

    /// Activate the selected config-screen option.
    fn activate_config_option(&mut self) {
        self.config_notice = None;
        match self.config_selected {
            // 0 = "Reveal seed phrase" / 1 = "Reveal private keys": ask for
            // the wallet password first.
            0 => {
                self.config_modal = ConfigModal::Password {
                    password: Zeroizing::new(String::new()),
                    error: None,
                    next: PasswordPurpose::Seed,
                };
            }
            1 => {
                self.config_modal = ConfigModal::Password {
                    password: Zeroizing::new(String::new()),
                    error: None,
                    next: PasswordPurpose::Keys,
                };
            }
            // 2 = "Change wallet password".
            2 => {
                self.config_modal = ConfigModal::ChangePassword {
                    stage: ChangePwStage::Current,
                    current: Zeroizing::new(String::new()),
                    first: Zeroizing::new(String::new()),
                    second: Zeroizing::new(String::new()),
                    error: None,
                };
            }
            // 3 = "Rescan blockchain from height".
            3 => {
                self.config_modal = ConfigModal::Rescan {
                    input: String::new(),
                    error: None,
                };
            }
            // 4 = "Change daemon address".
            4 => {
                self.config_modal = ConfigModal::DaemonAddress {
                    input: String::new(),
                    error: None,
                };
            }
            // 5 = "Switch node".
            5 => {
                self.config_modal = ConfigModal::NodePicker {
                    selected: self.node_pool.active_index(),
                };
            }
            _ => {}
        }
    }

    /// Switch to the pool entry at `index` without touching the configured
    /// primary — this is a "use that one for now", not a config change.
    fn select_pool_node(&mut self, index: usize) {
        let Some(candidate) = self.node_pool.candidates().get(index).cloned() else {
            return;
        };
        self.config_modal = ConfigModal::Hidden;
        self.node_pool.select(&candidate.url);
        self.node_failures = 0;
        self.config_notice = Some(format!("Connecting to {}…", candidate.url));

        if let Some(cancel) = &self.scan_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        self.scanner_started = false;
        self.node_status.connected = false;

        let daemon = self.daemon.clone();
        tokio::spawn(async move {
            daemon.set_url(&candidate.url).await;
            if let Err(e) = daemon.connect().await {
                tracing::warn!("connect to {} failed: {e:#}", candidate.url);
            }
        });
    }

    /// Handle keys while a config-screen modal is open.
    fn handle_config_modal_key(&mut self, key: crossterm::event::KeyEvent) {
        match self.config_modal.clone() {
            ConfigModal::Password {
                mut password, next, ..
            } => match key.code {
                KeyCode::Esc => {
                    self.config_modal = ConfigModal::Hidden;
                }
                KeyCode::Enter => self.config_password_submit(),
                KeyCode::Backspace => {
                    password.pop();
                    self.config_modal = ConfigModal::Password {
                        password,
                        error: None,
                        next,
                    };
                }
                KeyCode::Char(c)
                    if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
                {
                    password.push(c);
                    self.config_modal = ConfigModal::Password {
                        password,
                        error: None,
                        next,
                    };
                }
                _ => {}
            },
            ConfigModal::RevealedSeed(words) => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.config_modal = ConfigModal::Hidden;
                }
                KeyCode::Char('C') => copy_to_clipboard(&words),
                _ => {}
            },
            ConfigModal::RevealedKeys { spend, view } => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.config_modal = ConfigModal::Hidden;
                }
                KeyCode::Char('C') => {
                    copy_to_clipboard(&format!(
                        "spend: {}\nview: {}",
                        spend.as_str(),
                        view.as_str()
                    ));
                }
                _ => {}
            },
            ConfigModal::Hidden => {}
            _ => self.handle_config_modal_key_rest(key),
        }
    }

    /// Handle keys for the change-password, rescan and daemon modals (kept
    /// out of `handle_config_modal_key` for readability).
    fn handle_config_modal_key_rest(&mut self, key: crossterm::event::KeyEvent) {
        match self.config_modal.clone() {
            ConfigModal::ChangePassword {
                stage,
                mut current,
                mut first,
                mut second,
                ..
            } => {
                let set = |stage: ChangePwStage,
                           current: Zeroizing<String>,
                           first: Zeroizing<String>,
                           second: Zeroizing<String>| {
                    ConfigModal::ChangePassword {
                        stage,
                        current,
                        first,
                        second,
                        error: None,
                    }
                };
                match key.code {
                    KeyCode::Esc => self.config_modal = ConfigModal::Hidden,
                    KeyCode::Enter => self.change_password_advance(),
                    KeyCode::Backspace => {
                        match stage {
                            ChangePwStage::Current => {
                                current.pop();
                            }
                            ChangePwStage::New => {
                                first.pop();
                            }
                            ChangePwStage::Confirm => {
                                second.pop();
                            }
                        }
                        self.config_modal = set(stage, current, first, second);
                    }
                    KeyCode::Char(c)
                        if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
                    {
                        match stage {
                            ChangePwStage::Current => current.push(c),
                            ChangePwStage::New => first.push(c),
                            ChangePwStage::Confirm => second.push(c),
                        }
                        self.config_modal = set(stage, current, first, second);
                    }
                    _ => {}
                }
            }
            ConfigModal::Rescan { mut input, .. } => match key.code {
                KeyCode::Esc => self.config_modal = ConfigModal::Hidden,
                KeyCode::Enter => self.rescan_submit(),
                KeyCode::Backspace => {
                    input.pop();
                    self.config_modal = ConfigModal::Rescan { input, error: None };
                }
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    input.push(c);
                    self.config_modal = ConfigModal::Rescan { input, error: None };
                }
                _ => {}
            },
            ConfigModal::DaemonAddress { mut input, .. } => match key.code {
                KeyCode::Esc => self.config_modal = ConfigModal::Hidden,
                KeyCode::Enter => self.daemon_submit(),
                KeyCode::Backspace => {
                    input.pop();
                    self.config_modal = ConfigModal::DaemonAddress { input, error: None };
                }
                KeyCode::Char(c)
                    if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                        && !c.is_whitespace() =>
                {
                    input.push(c);
                    self.config_modal = ConfigModal::DaemonAddress { input, error: None };
                }
                _ => {}
            },
            ConfigModal::NodePicker { selected } => {
                let len = self.node_pool.candidates().len();
                match key.code {
                    KeyCode::Esc => self.config_modal = ConfigModal::Hidden,
                    KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                        self.config_modal = ConfigModal::NodePicker {
                            selected: selected.saturating_sub(1),
                        };
                    }
                    KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                        self.config_modal = ConfigModal::NodePicker {
                            selected: (selected + 1).min(len.saturating_sub(1)),
                        };
                    }
                    KeyCode::Enter => self.select_pool_node(selected),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Verify the typed password against the encrypted wallet file (the same
    /// check the lock screen performs) and, on success, reveal the gated
    /// secret. Verification deliberately re-opens the file rather than
    /// comparing against the in-memory password, so it also works if the
    /// in-memory state ever changes.
    fn config_password_submit(&mut self) {
        let ConfigModal::Password { password, next, .. } = &self.config_modal else {
            return;
        };
        let next = *next;
        if password.is_empty() {
            self.config_modal = ConfigModal::Password {
                password: Zeroizing::new(String::new()),
                error: Some("Enter the wallet password".to_string()),
                next,
            };
            return;
        }
        let password = Zeroizing::new(password.as_str().to_string());
        let path = self.config.wallet.path.clone();
        match WalletDb::open(&path, password.as_bytes()).and_then(|db| {
            // Polyseed wallets: re-display the original 16-word phrase (the
            // 150-bit secret is not recoverable from the derived key, so the
            // phrase itself is stored). Legacy wallets: derive the 25-word
            // mnemonic from the stored seed.
            if let Some(phrase) = db.polyseed_phrase()? {
                return Ok(phrase);
            }
            let seed = db.seed()?;
            Ok(crate::wallet::seed_to_mnemonic(&seed).join(" "))
        }) {
            Ok(words) => match next {
                PasswordPurpose::Seed => {
                    self.config_modal = ConfigModal::RevealedSeed(Zeroizing::new(words));
                }
                PasswordPurpose::Keys => {
                    let Some(keys) = &self.wallet_keys else {
                        self.config_modal = ConfigModal::Hidden;
                        self.last_error = Some("No wallet loaded".to_string());
                        return;
                    };
                    self.config_modal = ConfigModal::RevealedKeys {
                        spend: Zeroizing::new(hex::encode(keys.keypair.spend.as_bytes())),
                        view: Zeroizing::new(hex::encode(keys.keypair.view.as_bytes())),
                    };
                }
            },
            Err(e) => {
                tracing::warn!("config secret reveal: password verification failed: {e:#}");
                self.config_modal = ConfigModal::Password {
                    password: Zeroizing::new(String::new()),
                    error: Some("Incorrect password".to_string()),
                    next,
                };
            }
        }
    }

    /// Advance the change-password flow one stage (Current → New → Confirm
    /// → apply), validating at each step.
    fn change_password_advance(&mut self) {
        let ConfigModal::ChangePassword {
            stage,
            current,
            first,
            second,
            ..
        } = &self.config_modal
        else {
            return;
        };
        let stage = *stage;
        let rebuild = |stage: ChangePwStage, error: Option<String>| ConfigModal::ChangePassword {
            stage,
            current: Zeroizing::new(current.as_str().to_string()),
            first: Zeroizing::new(first.as_str().to_string()),
            second: Zeroizing::new(second.as_str().to_string()),
            error,
        };
        match stage {
            // Verify the current password against the encrypted file.
            ChangePwStage::Current => {
                if current.is_empty() {
                    self.config_modal = rebuild(stage, Some("Enter the current password".into()));
                    return;
                }
                let path = self.config.wallet.path.clone();
                match WalletDb::open(&path, current.as_bytes()) {
                    Ok(_) => {
                        self.config_modal = ConfigModal::ChangePassword {
                            stage: ChangePwStage::New,
                            current: Zeroizing::new(current.as_str().to_string()),
                            first: Zeroizing::new(String::new()),
                            second: Zeroizing::new(String::new()),
                            error: None,
                        };
                    }
                    Err(e) => {
                        tracing::warn!("change password: verification failed: {e:#}");
                        // Clear the field so the retry doesn't append to the
                        // wrong password (mirrors the seed-reveal prompt).
                        self.config_modal = ConfigModal::ChangePassword {
                            stage,
                            current: Zeroizing::new(String::new()),
                            first: Zeroizing::new(String::new()),
                            second: Zeroizing::new(String::new()),
                            error: Some("Incorrect password".into()),
                        };
                    }
                }
            }
            ChangePwStage::New => {
                if first.chars().count() < MIN_NEW_PASSWORD_CHARS {
                    self.config_modal = rebuild(
                        stage,
                        Some(format!(
                            "Use at least {MIN_NEW_PASSWORD_CHARS} characters for the new password"
                        )),
                    );
                    return;
                }
                self.config_modal = ConfigModal::ChangePassword {
                    stage: ChangePwStage::Confirm,
                    current: Zeroizing::new(current.as_str().to_string()),
                    first: Zeroizing::new(first.as_str().to_string()),
                    second: Zeroizing::new(String::new()),
                    error: None,
                };
            }
            ChangePwStage::Confirm => {
                if first != second {
                    self.config_modal = ConfigModal::ChangePassword {
                        stage: ChangePwStage::New,
                        current: Zeroizing::new(current.as_str().to_string()),
                        first: Zeroizing::new(String::new()),
                        second: Zeroizing::new(String::new()),
                        error: Some("Passwords did not match; start over".into()),
                    };
                    return;
                }
                let Some(db) = self.wallet_db.clone() else {
                    self.config_modal = rebuild(stage, Some("Wallet is locked".into()));
                    return;
                };
                match db.set_password(second.as_bytes()) {
                    Ok(()) => {
                        self.wallet_password = Some(Zeroizing::new(second.as_str().to_string()));
                        self.config_modal = ConfigModal::Hidden;
                        self.config_notice = Some("Wallet password changed".to_string());
                    }
                    Err(e) => {
                        tracing::error!("change password failed: {e:#}");
                        self.config_modal =
                            rebuild(stage, Some("Failed to save the wallet file".into()));
                    }
                }
            }
        }
    }

    /// Apply the rescan-from-height request: roll the database back, stop
    /// the scanner and let the auto-start bring it up from the new height.
    fn rescan_submit(&mut self) {
        let ConfigModal::Rescan { input, .. } = &self.config_modal else {
            return;
        };
        let height: u64 = match input.trim().parse() {
            Ok(h) if h >= 1 => h,
            _ => {
                self.config_modal = ConfigModal::Rescan {
                    input: input.clone(),
                    error: Some("Enter a block height (1 = full rescan)".to_string()),
                };
                return;
            }
        };
        if self.node_status.height > 0 && height > self.node_status.height {
            self.config_modal = ConfigModal::Rescan {
                input: input.clone(),
                error: Some("Height is beyond the chain tip".to_string()),
            };
            return;
        }
        let Some(db) = self.wallet_db.clone() else {
            self.config_modal = ConfigModal::Rescan {
                input: input.clone(),
                error: Some("Wallet is locked".to_string()),
            };
            return;
        };
        // Roll back everything above height-1 and leave the scan cursor at
        // `height`; the restarted scanner takes it from there.
        if let Err(e) = db
            .rollback(height.saturating_sub(1))
            .and_then(|_| db.save())
        {
            tracing::error!("rescan rollback failed: {e:#}");
            self.config_modal = ConfigModal::Rescan {
                input: input.clone(),
                error: Some("Failed to reset scan state".to_string()),
            };
            return;
        }
        if let Some(cancel) = &self.scan_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        self.scanner_started = false;
        self.scan_progress = None;
        self.load_persisted_state();
        self.config_modal = ConfigModal::Hidden;
        self.config_notice = Some(format!("Rescanning from block {height}"));
    }

    /// Apply the daemon-address change: persist it to the config file,
    /// retarget every client clone and reconnect; the scanner restarts on
    /// the new daemon via the auto-start.
    fn daemon_submit(&mut self) {
        let ConfigModal::DaemonAddress { input, .. } = &self.config_modal else {
            return;
        };
        let url = input.trim();
        if url.is_empty() {
            self.config_modal = ConfigModal::DaemonAddress {
                input: input.clone(),
                error: Some("Enter the daemon RPC URL".to_string()),
            };
            return;
        }
        let normalized = crate::rpc::normalize_url(url);
        self.config.daemon.url = normalized.clone();
        // An explicit choice overrides failover: re-seed the pool from the
        // new config so the primary really is primary again.
        self.node_pool = crate::rpc::NodePool::new(&self.config);
        self.node_pool.select(&normalized);
        self.node_failures = 0;
        self.config_notice = match &self.config_path {
            Some(path) => match self.config.save(path) {
                Ok(()) => Some(format!("Daemon set to {normalized} — reconnecting…")),
                Err(e) => {
                    tracing::warn!("failed to persist config: {e:#}");
                    Some(format!(
                        "Daemon set to {normalized} (config file not saved: {e})"
                    ))
                }
            },
            None => Some(format!("Daemon set to {normalized} (this session only)")),
        };
        self.config_modal = ConfigModal::Hidden;

        // Retarget every clone of the client (status poller, scanner, send
        // engine) and reconnect in the background.
        let daemon = self.daemon.clone();
        let new_url = normalized;
        tokio::spawn(async move {
            daemon.set_url(&new_url).await;
            if let Err(e) = daemon.connect().await {
                tracing::warn!("connect to new daemon failed: {e:#}");
            }
        });
        // Stop the scanner; the NodeStatus auto-start brings it back up on
        // the new daemon once connected.
        if let Some(cancel) = &self.scan_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        self.scanner_started = false;
        self.node_status.connected = false;
    }

    /// Handle a mouse event: hit-test clicks against the regions registered
    /// during the last render, and map the scroll wheel to list navigation.
    fn handle_mouse(&mut self, mouse: MouseEvent) {
        // Any click or scroll closes the help overlay first.
        if self.help_visible {
            if matches!(
                mouse.kind,
                MouseEventKind::Down(_) | MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
            ) {
                self.help_visible = false;
            }
            return;
        }
        if self.sweep_warning {
            // The warning intentionally requires an explicit keyboard
            // acknowledgement; clicks cannot activate controls behind it.
            return;
        }

        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                self.last_error = None;
                let pos = (mouse.column, mouse.row).into();
                // Later regions render on top; hit-test in reverse.
                let hit = self
                    .mouse_regions
                    .iter()
                    .rev()
                    .find(|(rect, _)| rect.contains(pos))
                    .map(|(_, region)| *region);
                match hit {
                    Some(MouseRegion::Tab(i)) => {
                        self.active_tab = i.min(TAB_COUNT - 1);
                    }
                    Some(MouseRegion::SendField(field)) => {
                        if self.active_tab == 1 && self.send_stage == SendStage::Entering {
                            self.send_field = field;
                        }
                    }
                    Some(MouseRegion::ConfirmYes) => {
                        if let SendStage::Confirming { .. } = self.send_stage {
                            if let Some(tx) = self.send_confirm_tx.take() {
                                let _ = tx.send(true);
                            }
                            self.send_stage = SendStage::Publishing;
                        }
                    }
                    Some(MouseRegion::ConfirmNo) => {
                        if let SendStage::Confirming { .. } = self.send_stage {
                            if let Some(tx) = self.send_confirm_tx.take() {
                                let _ = tx.send(false);
                            }
                            self.send_stage = SendStage::Failed("Cancelled by user".to_string());
                        }
                    }
                    Some(MouseRegion::ReceiveRow(i)) => {
                        if self.active_tab == 2 {
                            self.receive_selected =
                                i.min(self.receive_address_count().saturating_sub(1));
                        }
                    }
                    Some(MouseRegion::NewReceiveAddress) => {
                        if self.active_tab == 2 {
                            self.allocate_receive_address();
                        }
                    }
                    Some(MouseRegion::SelectReceiveSource) => {
                        if self.active_tab == 2 {
                            self.select_receive_source();
                        }
                    }
                    Some(MouseRegion::HistoryRow(i)) => {
                        if self.active_tab == 3 && !self.transfers.is_empty() {
                            self.history_selected = i.min(self.transfers.len() - 1);
                        }
                    }
                    Some(MouseRegion::ConfigRow(i)) => {
                        if self.active_tab == 4 && self.config_modal == ConfigModal::Hidden {
                            self.config_selected = i;
                            self.activate_config_option();
                        }
                    }
                    Some(MouseRegion::AddressBookRow(i)) => {
                        if self.active_tab == 1
                            && self.send_stage == SendStage::Entering
                            && i < self.address_book.len()
                        {
                            self.book_selected = i;
                            self.book_use_selected();
                        }
                    }
                    None => {}
                }
            }
            MouseEventKind::ScrollUp => match self.active_tab {
                2 => {
                    let count = self.receive_address_count();
                    self.receive_selected = if self.receive_selected == 0 {
                        count.saturating_sub(1)
                    } else {
                        self.receive_selected - 1
                    };
                }
                3 => {
                    self.history_selected = self.history_selected.saturating_sub(1);
                }
                _ => {}
            },
            MouseEventKind::ScrollDown => match self.active_tab {
                2 => {
                    self.receive_selected =
                        (self.receive_selected + 1) % self.receive_address_count().max(1);
                }
                3 if !self.transfers.is_empty() => {
                    self.history_selected =
                        (self.history_selected + 1).min(self.transfers.len() - 1);
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// Handle a bracketed-paste payload: pasted text goes straight into the
    /// focused input field, bypassing per-key handling (so e.g. uppercase
    /// letters in an address never trigger Shift+letter shortcuts).
    fn handle_paste(&mut self, text: &str) {
        if self.sweep_warning {
            return;
        }
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        // Modal inputs take priority.
        if let ConfigModal::DaemonAddress { mut input, .. } = self.config_modal.clone() {
            let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            input.push_str(&cleaned);
            self.config_modal = ConfigModal::DaemonAddress { input, error: None };
            return;
        }
        if let BookModal::Adding {
            mut label,
            mut address,
            focus,
            ..
        } = self.book_modal.clone()
        {
            match focus {
                BookField::Label => label.push_str(text),
                BookField::Address => {
                    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
                    address.push_str(&cleaned);
                }
            }
            self.book_modal = BookModal::Adding {
                label,
                address,
                focus,
                error: None,
            };
            return;
        }
        if self.active_tab == 1 && self.send_stage == SendStage::Entering {
            match self.send_field {
                SendField::Address => {
                    // Addresses are single-line base58; drop whitespace.
                    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
                    self.send_address.push_str(&cleaned);
                }
                SendField::Amount => {
                    let cleaned: String = text
                        .chars()
                        .filter(|c| c.is_ascii_digit() || *c == '.')
                        .collect();
                    self.send_amount.push_str(&cleaned);
                    self.send_sweep = false;
                }
                SendField::Book => {}
            }
        }
    }

    fn allocated_receive_address_count(&self) -> usize {
        self.wallet_db
            .as_ref()
            .and_then(|db| db.receive_address_count().ok())
            .unwrap_or(DEFAULT_RECEIVE_ADDRESS_COUNT) as usize
    }

    /// Stable allocated account-0 rows followed by any addresses discovered
    /// in restored nonzero accounts. Without the latter, selecting a strict
    /// send source could make those already-detected funds unreachable.
    pub fn receive_address_indices(&self) -> Vec<(u32, u32)> {
        let allocated = self.allocated_receive_address_count();
        let mut indices: Vec<(u32, u32)> = (0..allocated)
            .map(|minor| (0, u32::try_from(minor).unwrap_or(u32::MAX)))
            .collect();
        let mut observed: std::collections::BTreeSet<(u32, u32)> = self
            .owned_outputs
            .iter()
            .map(|output| (output.subaddress_major, output.subaddress_minor))
            .filter(|(major, minor)| *major != 0 || (*minor as usize) >= allocated)
            .collect();
        if self.send_from_major != 0 {
            // Keep a persisted nonzero-account source selectable even if a
            // reorg removed its last observed output from the local database.
            observed.insert((self.send_from_major, self.send_from_minor));
        }
        indices.extend(observed);
        indices
    }

    pub fn receive_address_count(&self) -> usize {
        self.receive_address_indices().len()
    }

    /// Actual subaddress index represented by an Addresses-screen row.
    pub fn receive_subaddress_index(&self, index: usize) -> (u32, u32) {
        self.receive_address_indices()
            .get(index)
            .copied()
            .unwrap_or((0, 0))
    }

    pub fn receive_subaddress_minor(&self, index: usize) -> u32 {
        self.receive_subaddress_index(index).1
    }

    pub fn receive_address_label(&self, index: usize) -> String {
        let (major, minor) = self.receive_subaddress_index(index);
        match (major, minor) {
            (0, 0) => "Primary".to_string(),
            (0, minor) => format!("Sub #{minor}"),
            _ => format!("Acct {major}/{minor}"),
        }
    }

    /// The address string for an Addresses-screen selection index.
    pub fn receive_address_string(&self, index: usize) -> Option<String> {
        if index >= self.receive_address_count() {
            return None;
        }
        let (major, minor) = self.receive_subaddress_index(index);
        self.subaddress_string(major, minor)
    }

    fn subaddress_string(&self, major: u32, minor: u32) -> Option<String> {
        let keys = self.wallet_keys.as_ref()?;
        if (major, minor) == (0, 0) {
            return Some(keys.address_string());
        }
        let sub = monero::cryptonote::subaddress::Index { major, minor };
        Some(keys.get_subaddress(sub).to_string())
    }

    /// Unspent balance belonging to one account-0 address. Pending outgoing
    /// inputs are already marked spent, so they cannot be counted twice.
    pub fn receive_address_balance(&self, index: usize) -> BalanceInfo {
        let (major, minor) = self.receive_subaddress_index(index);
        self.balance_for_subaddress(major, minor)
    }

    pub fn current_address_label(&self) -> String {
        match (self.send_from_major, self.send_from_minor) {
            (0, 0) => "Primary".to_string(),
            (0, minor) => format!("Sub #{minor}"),
            (major, minor) => format!("Acct {major}/{minor}"),
        }
    }

    pub fn current_address_string(&self) -> Option<String> {
        self.subaddress_string(self.send_from_major, self.send_from_minor)
    }

    pub fn current_change_address_label(&self) -> String {
        if self.send_from_major == 0 {
            "Primary".to_string()
        } else {
            format!("Acct {}/0", self.send_from_major)
        }
    }

    pub fn current_address_balance(&self) -> BalanceInfo {
        self.balance_for_subaddress(self.send_from_major, self.send_from_minor)
    }

    /// Refresh node status asynchronously.
    pub async fn refresh_node_status(&mut self) {
        let status = self.daemon.get_status().await;
        self.node_status = status;
        // Recalculate balance when we get new chain height
        self.recalculate_balance();
    }

    /// Track consecutive status-poll failures and rotate to the next node
    /// once the active one looks genuinely down.
    ///
    /// Waiting for several failures rather than reacting to the first keeps a
    /// momentary blip from bouncing the wallet between nodes; at the poller's
    /// 5s cadence this is roughly 15 seconds of silence before moving.
    fn consider_failover(&mut self) {
        if self.node_status.connected {
            self.node_failures = 0;
            return;
        }

        self.node_failures = self.node_failures.saturating_add(1);

        if !should_fail_over(
            self.node_failures,
            self.node_pool.can_fail_over(),
            self.send_in_flight(),
        ) {
            return;
        }

        let Some(next) = self.node_pool.advance().cloned() else {
            return;
        };
        self.node_failures = 0;

        // Surfaced to the user through the dashboard log pane; the Node
        // panel's "Using: fallback" line carries the ongoing state.
        tracing::warn!(
            "primary node unreachable — failing over to {} [{}]",
            next.url,
            next.source.label()
        );

        // Stop the scanner; the NodeStatus auto-start brings it back up on
        // the new node once the connection is established.
        if let Some(cancel) = &self.scan_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        self.scanner_started = false;

        let daemon = self.daemon.clone();
        tokio::spawn(async move {
            daemon.set_url(&next.url).await;
            if let Err(e) = daemon.connect().await {
                tracing::warn!("failover connect to {} failed: {e:#}", next.url);
            }
        });
    }

    /// Attempt to connect to the daemon.
    pub async fn try_connect(&mut self) {
        match self.daemon.connect().await {
            Ok(()) => {
                tracing::info!("Connected to daemon at {}", self.config.daemon.url);
                self.last_error = None;
            }
            Err(e) => {
                tracing::warn!("Failed to connect to daemon: {e}");
                self.last_error = Some(format!("Connection failed: {e}"));
            }
        }
    }

    /// Start the background scanner if wallet is loaded.
    pub fn start_scanner(&mut self, event_tx: mpsc::UnboundedSender<AppEvent>, from_height: u64) {
        let Some(ref keys) = self.wallet_keys else {
            return;
        };
        let Some(db) = self.wallet_db.clone() else {
            tracing::error!("start_scanner called without an open wallet database");
            return;
        };
        self.scanner_started = true;
        let daemon = self.daemon.clone();
        let keys = keys.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        self.scan_cancel = Some(cancel.clone());

        tokio::spawn(async move {
            let result = (|| -> color_eyre::Result<(monero_wallet::Scanner, _)> {
                // The running Scanner expands this baseline from the
                // database before it consumes any block.
                let wallet_scanner = crate::wallet::build_wallet_scanner(&keys)?;
                let spend = crate::wallet::send::spend_scalar(&keys.keypair.spend)?;
                Ok((wallet_scanner, spend))
            })();

            match result {
                Ok((wallet_scanner, spend)) => {
                    let scanner =
                        Scanner::new(daemon, event_tx.clone(), wallet_scanner, spend, db, cancel);
                    scanner.run(from_height).await;
                }
                Err(e) => {
                    let _ = event_tx.send(AppEvent::Scan(ScanEvent::Error(format!(
                        "Failed to initialize scanner: {e:#}"
                    ))));
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_off_until_the_node_looks_really_down() {
        for failures in 1..FAILOVER_AFTER_POLLS {
            assert!(
                !should_fail_over(failures, true, false),
                "rotated after only {failures} failed poll(s)"
            );
        }
        assert!(should_fail_over(FAILOVER_AFTER_POLLS, true, false));
    }

    #[test]
    fn never_rotates_with_nowhere_to_go() {
        assert!(!should_fail_over(FAILOVER_AFTER_POLLS + 10, false, false));
    }

    /// Switching nodes mid-send would drop the RPC client under a
    /// transaction the user is watching.
    #[test]
    fn waits_for_an_in_flight_send() {
        assert!(!should_fail_over(FAILOVER_AFTER_POLLS, true, true));
        // ...and goes ahead once the send is done.
        assert!(should_fail_over(FAILOVER_AFTER_POLLS, true, false));
    }

    #[test]
    fn a_long_outage_keeps_rotating() {
        assert!(should_fail_over(u32::MAX, true, false));
    }
}
