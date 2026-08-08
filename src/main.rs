use clap::Parser;
use color_eyre::Result;
use crossterm::{
    event::{DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use muff::app::AppState;
use muff::config::{self, Config};
use muff::event::{AppEvent, EventHandler};
use muff::rpc::DaemonClient;
use muff::ui;
use muff::wallet::{self, WalletDb, WalletFileFormat, detect_format};
use muff::wizard;

/// Muff — A Monero wallet TUI for Cuprate nodes
#[derive(Parser, Debug)]
#[command(name = "muff", version, about)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Daemon RPC URL (overrides config)
    #[arg(short, long)]
    daemon_url: Option<String>,

    /// Network: mainnet, stagenet, testnet
    #[arg(short, long)]
    network: Option<String>,

    /// Wallet file path (overrides config)
    #[arg(short, long)]
    wallet: Option<PathBuf>,

    /// Wallet password (if not provided, prompts interactively)
    #[arg(long)]
    password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize error handling
    color_eyre::install()?;

    // Initialize logging. Log lines are captured into an in-memory buffer
    // (rendered on the dashboard's log pane) instead of stderr: while the
    // alternate screen is active, writing to the terminal would corrupt the
    // TUI on every screen. ANSI colors are disabled so escape sequences
    // don't end up as literal text in the log pane.
    let log_buffer = muff::logbuf::LogBuffer::new();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("muff=info")),
        )
        .with_ansi(false)
        .with_writer(log_buffer.clone())
        .init();

    // Parse CLI arguments
    let cli = Cli::parse();

    // Load configuration
    let mut config = Config::load(&cli.config)?;

    // Apply CLI overrides
    if let Some(url) = cli.daemon_url {
        config.daemon.url = url;
    }
    if let Some(network) = cli.network {
        config.wallet.network = match network.to_lowercase().as_str() {
            "mainnet" => config::NetworkKind::Mainnet,
            "stagenet" => config::NetworkKind::Stagenet,
            "testnet" => config::NetworkKind::Testnet,
            _ => {
                eprintln!("Unknown network '{}', using mainnet", network);
                config::NetworkKind::Mainnet
            }
        };
    }
    if let Some(wallet_path) = cli.wallet {
        config.wallet.path = wallet_path;
    }

    config.ensure_wallet_dir()?;

    // Migrate pre-`.wallet` wallets: when the configured wallet file (with
    // the new default name) is missing but a legacy `wallet.enc` sits next
    // to it, rename the legacy file into place.
    if config.wallet.path.file_name() == Some(std::ffi::OsStr::new("muff.wallet"))
        && detect_format(&config.wallet.path)? == WalletFileFormat::Missing
    {
        let legacy = config.wallet.path.with_file_name("wallet.enc");
        if detect_format(&legacy)? == WalletFileFormat::EncryptedDb {
            std::fs::rename(&legacy, &config.wallet.path)?;
            // The legacy file may predate owner-only permissions; tighten
            // it now rather than waiting for the first save.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &config.wallet.path,
                    std::fs::Permissions::from_mode(0o600),
                );
            }
            tracing::info!(
                "Migrated legacy wallet {} -> {}",
                legacy.display(),
                config.wallet.path.display()
            );
        }
    }

    tracing::info!("Starting muff with daemon at {}", config.daemon.url);

    // Wallet setup: use wizard for new wallets, password prompt for existing
    let wallet_format = detect_format(&config.wallet.path)?;
    let (wallet_keys, scan_height, password, wallet_db) = match wallet_format {
        WalletFileFormat::EncryptedDb => {
            // Existing wallet — just prompt for password
            eprintln!("Wallet found at {}", config.wallet.path.display());
            let pw = if let Some(pw) = cli.password {
                Zeroizing::new(pw)
            } else {
                Zeroizing::new(rpassword::prompt_password("Enter wallet password: ")?)
            };
            if pw.is_empty() {
                eprintln!("Password cannot be empty.");
                std::process::exit(1);
            }

            let db = match WalletDb::open(&config.wallet.path, pw.as_bytes()) {
                Ok(db) => db,
                Err(e) => {
                    eprintln!("Failed to load wallet: {}", e);
                    eprintln!("Wrong password or corrupted wallet file.");
                    std::process::exit(1);
                }
            };
            let stored_network = db.network()?;
            let configured_network = config.wallet.network.as_str();
            if stored_network != configured_network {
                return Err(color_eyre::eyre::eyre!(
                    "wallet network is {stored_network}, but configuration selects {configured_network}; refusing to derive or scan with the wrong network"
                ));
            }
            let seed = match db.seed() {
                Ok(seed) => seed,
                Err(e) => {
                    eprintln!("Failed to read wallet database: {e}");
                    std::process::exit(1);
                }
            };
            let keys = wallet::derive_keys(&seed, config.wallet.network.into());
            let height = db.scan_height().unwrap_or(0);
            (keys, height, pw, std::sync::Arc::new(db))
        }
        WalletFileFormat::LegacyJson | WalletFileFormat::Unknown => {
            eprintln!(
                "The file at {} is not a muff encrypted wallet database.",
                config.wallet.path.display()
            );
            eprintln!(
                "If this is an old two-file wallet, move it aside (e.g. `mv {0} {0}.old`) and \
                 start muff again to create or restore a wallet in the new format.",
                config.wallet.path.display()
            );
            std::process::exit(1);
        }
        WalletFileFormat::Missing => {
            // No wallet — run the setup wizard
            let wizard_result =
                wizard::run_wizard(&config.wallet.path, config.wallet.network.into())?;

            // A newly created wallet has no history: start scanning at the
            // current chain tip instead of genesis so the first sync
            // finishes immediately. Restored wallets keep the height the
            // user entered.
            let scan_height = if wizard_result.fresh {
                let tip = fresh_wallet_scan_height(&config).await;
                println!("  ⛓  New wallet — scanning from chain tip: {tip}");
                tip
            } else {
                wizard_result.scan_height
            };

            // Create the encrypted single-file wallet database
            let network = config.wallet.network.as_str();
            let db = WalletDb::create(
                &config.wallet.path,
                wizard_result.password.as_bytes(),
                &wizard_result.keys.seed,
                network,
                scan_height,
            )?;
            // Polyseed wallets: remember the format and the original phrase
            // (the 16 words are not recoverable from the derived spend key).
            if let Some(phrase) = &wizard_result.polyseed_phrase {
                db.set_seed_format(wallet::SeedFormat::Polyseed)?;
                db.set_polyseed_phrase(phrase)?;
                // The db is an in-memory snapshot; persist now so the
                // reveal flow (which re-opens the file) sees the phrase.
                db.save()?;
            }
            tracing::info!("Wallet created at {}", config.wallet.path.display());

            (
                wizard_result.keys,
                scan_height,
                wizard_result.password,
                std::sync::Arc::new(db),
            )
        }
    };

    tracing::info!("Wallet loaded, scan height: {}", scan_height);
    tracing::info!("Primary address: {}", wallet_keys.address_string());

    // Initialize app state
    let mut state = AppState::new(config.clone());
    state.set_log_buffer(log_buffer);
    state.set_config_path(cli.config.clone());
    state.wallet_keys = Some(wallet_keys);
    // Attach the encrypted wallet database, then populate in-memory
    // balances/history from it.
    state.set_wallet_db(wallet_db, &password);
    state.set_scan_start_height(scan_height);
    state.load_persisted_state();

    // Try initial connection
    state.try_connect().await;

    // Set up terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Set up event handler
    let (event_handler, mut event_rx) = EventHandler::new(config.ui.tick_rate_ms);
    event_handler.start();
    state.set_event_tx(event_handler.sender());

    // Start background node status updater
    let status_tx = event_handler.sender();
    let daemon = state.daemon.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let status = daemon.get_status().await;
            let _ = status_tx.send(AppEvent::NodeStatus(status));
        }
    });

    // Start scanner if connected
    if state.daemon.is_connected().await {
        let scan_tx = event_handler.sender();
        state.start_scanner(scan_tx, scan_height);
    }

    // Main render loop
    let result = run_app(&mut terminal, &mut state, &mut event_rx).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        DisableBracketedPaste
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        tracing::error!("Application error: {e:?}");
        eprintln!("Error: {e:?}");
    }

    Ok(())
}

/// Best-effort chain tip for a newly created wallet's initial scan height.
/// Falls back to 0 (full scan) when the daemon is unreachable.
async fn fresh_wallet_scan_height(config: &Config) -> u64 {
    let daemon = DaemonClient::new(config);
    if let Err(e) = daemon.connect().await {
        tracing::warn!(
            "could not reach the daemon for the chain tip ({e:#}); \
             the new wallet will scan from genesis"
        );
        return 0;
    }
    match daemon.get_height().await {
        Ok(count) => count.saturating_sub(1),
        Err(e) => {
            tracing::warn!(
                "could not read the chain tip ({e:#}); \
                 the new wallet will scan from genesis"
            );
            0
        }
    }
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut AppState,
    event_rx: &mut mpsc::UnboundedReceiver<AppEvent>,
) -> Result<()> {
    while state.running {
        // Render
        terminal.draw(|frame| {
            ui::render(frame, state);
        })?;

        // Handle events
        if let Some(event) = event_rx.recv().await {
            state.handle_event(event);
        }

        // 'r' requests an immediate node-status refresh.
        if state.force_status_refresh {
            state.force_status_refresh = false;
            state.refresh_node_status().await;
        }
    }

    Ok(())
}
