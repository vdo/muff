//! Integration test: connect to a remote Monero node and scan recent blocks.
//!
//! Run with: cargo test --test scan_remote -- --nocapture

use std::time::Duration;

fn make_config(url: &str) -> muff::config::Config {
    muff::config::Config {
        daemon: muff::config::DaemonConfig {
            url: url.to_string(),
            proxy: None,
        },
        wallet: muff::config::WalletConfig {
            path: "/tmp/muff-test-unused".into(),
            network: muff::config::NetworkKind::Mainnet,
        },
        ui: muff::config::UiConfig {
            tick_rate_ms: 100,
            show_atomic: false,
        },
        security: muff::config::SecurityConfig::default(),
    }
}

#[tokio::test]
async fn test_connect_and_fetch_block() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("muff=debug,info")
        .with_test_writer()
        .try_init();

    let config = make_config("http://xmr-node.cakewallet.com:18081");
    let daemon = muff::rpc::DaemonClient::new(&config);
    daemon.connect().await.expect("Failed to connect");
    println!("✓ Connected to Cake Wallet node");

    let height = daemon.get_height().await.expect("get_height failed");
    println!("✓ Chain height: {}", height);
    assert!(height > 3_000_000);

    let block = daemon
        .get_block_by_height(height - 5)
        .await
        .expect("get_block failed");
    println!("✓ Block {} has {} txs", height - 5, block.tx_hashes.len());

    if let Some(tx_hash) = block.tx_hashes.first() {
        let tx = daemon
            .get_transaction(*tx_hash)
            .await
            .expect("get_transaction failed");
        println!("✓ TX {} has {} outputs", tx_hash, tx.prefix().outputs.len());
    }
}

#[tokio::test]
async fn test_scanner_pipeline() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("muff=debug,info")
        .with_test_writer()
        .try_init();

    let config = make_config("http://xmr-node.cakewallet.com:18081");
    let daemon = muff::rpc::DaemonClient::new(&config);
    daemon.connect().await.expect("Failed to connect");

    let height = daemon.get_height().await.expect("get_height failed");
    let start = height - 3;

    let seed = muff::wallet::generate_seed();
    let keys = muff::wallet::derive_keys(&seed, monero::Network::Mainnet);
    println!("✓ Test wallet: {}", keys.address_string());

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let wallet_scanner = muff::wallet::build_wallet_scanner(&keys).expect("build scanner");
    let spend = muff::wallet::send::spend_scalar(&keys.keypair.spend).expect("spend scalar");
    let db_path = std::env::temp_dir()
        .join(format!("muff-remote-test-{}", rand::random::<u32>()))
        .join("muff.wallet");
    let db = muff::wallet::WalletDb::create(&db_path, b"testpass", &seed, "mainnet", start)
        .expect("create wallet db");
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let scanner = muff::wallet::Scanner::new(
        daemon,
        tx,
        wallet_scanner,
        spend,
        std::sync::Arc::new(db),
        cancel,
    );

    let handle = tokio::spawn(async move {
        scanner.run(start).await;
    });

    let mut events = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);

    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(event)) => {
                println!("  {:?}", event);
                let done = matches!(
                    &event,
                    muff::event::AppEvent::Scan(muff::wallet::ScanEvent::Completed { .. })
                        | muff::event::AppEvent::Scan(muff::wallet::ScanEvent::Error(_))
                );
                events.push(event);
                if done {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => {
                println!("  TIMEOUT");
                break;
            }
        }
    }

    // The scanner keeps running to watch for new blocks; stop it here.
    handle.abort();

    let has_started = events.iter().any(|e| {
        matches!(
            e,
            muff::event::AppEvent::Scan(muff::wallet::ScanEvent::Started { .. })
        )
    });
    let has_completed = events.iter().any(|e| {
        matches!(
            e,
            muff::event::AppEvent::Scan(muff::wallet::ScanEvent::Completed { .. })
        )
    });
    let errors: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            muff::event::AppEvent::Scan(muff::wallet::ScanEvent::Error(m)) => Some(m.clone()),
            _ => None,
        })
        .collect();
    let outputs = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                muff::event::AppEvent::Scan(muff::wallet::ScanEvent::OutputFound(_))
            )
        })
        .count();

    println!("\n=== Results ===");
    println!("  Started: {}", has_started);
    println!("  Completed: {}", has_completed);
    println!("  Outputs: {}", outputs);
    if !errors.is_empty() {
        println!("  Errors: {:?}", errors);
    }

    assert!(has_started, "Should emit Started");
    assert!(has_completed, "Should emit Completed");
    assert!(errors.is_empty(), "No errors expected: {:?}", errors);
    println!("✓ Scanner pipeline test passed!");
}

#[tokio::test]
async fn test_block_hash_endpoints() {
    let config = make_config("http://xmr-node.cakewallet.com:18081");
    let daemon = muff::rpc::DaemonClient::new(&config);
    daemon.connect().await.expect("Failed to connect");

    let height = daemon.get_height().await.expect("get_height failed");
    let h = height - 100;

    // Single-hash endpoint.
    let hash = daemon
        .get_block_hash(h)
        .await
        .expect("get_block_hash failed");
    assert_eq!(hash.len(), 64, "hash must be 32 bytes hex");

    // Range endpoint must agree with the single endpoint.
    let range = daemon
        .get_block_hashes_range(h, h + 5)
        .await
        .expect("get_block_hashes_range failed");
    assert_eq!(range.len(), 6);
    assert_eq!(range[0], hash);

    println!("✓ Block hash endpoints test passed (hash at {h}: {hash})");
}

#[tokio::test]
async fn test_scan_height_persistence() {
    use std::path::PathBuf;

    let wallet_path = PathBuf::from("/tmp/muff-test-persist/muff.wallet");
    let _ = std::fs::create_dir_all(wallet_path.parent().unwrap());
    let _ = std::fs::remove_file(&wallet_path);

    let seed = muff::wallet::generate_seed();
    let keys = muff::wallet::derive_keys(&seed, monero::Network::Mainnet);
    let db =
        muff::wallet::WalletDb::create(&wallet_path, b"testpass", &seed, "mainnet", 100).unwrap();
    assert_eq!(db.scan_height().unwrap(), 100);
    db.save().unwrap();
    drop(db);

    let db = muff::wallet::WalletDb::open(&wallet_path, b"testpass").unwrap();
    assert_eq!(db.scan_height().unwrap(), 100);
    db.set_scan_height(500).unwrap();
    db.save().unwrap();
    drop(db);

    let db = muff::wallet::WalletDb::open(&wallet_path, b"testpass").unwrap();
    assert_eq!(db.scan_height().unwrap(), 500);
    let loaded_seed = db.seed().unwrap();
    let keys2 = muff::wallet::derive_keys(&loaded_seed, monero::Network::Mainnet);
    assert_eq!(keys.address_string(), keys2.address_string());

    let _ = std::fs::remove_file(&wallet_path);
    println!("✓ Scan height persistence test passed!");
}

#[test]
fn test_output_deduplication() {
    let out1 = muff::wallet::OwnedOutput {
        tx_hash: "abc123".to_string(),
        output_index: 0,
        key_hex: "aa".to_string(),
        height: 100,
        amount: 1_000_000_000_000,
        spent: false,
        subaddress_major: 0,
        subaddress_minor: 0,
        timestamp: 0,
        unlock_height: 110,
    };
    let out2 = muff::wallet::OwnedOutput {
        tx_hash: "abc123".to_string(),
        output_index: 0,
        key_hex: "aa".to_string(),
        height: 100,
        amount: 1_000_000_000_000,
        spent: false,
        subaddress_major: 0,
        subaddress_minor: 0,
        timestamp: 0,
        unlock_height: 110,
    };
    let out3 = muff::wallet::OwnedOutput {
        tx_hash: "abc123".to_string(),
        output_index: 1,
        key_hex: "bb".to_string(),
        height: 100,
        amount: 2_000_000_000_000,
        spent: false,
        subaddress_major: 0,
        subaddress_minor: 0,
        timestamp: 0,
        unlock_height: 110,
    };

    assert_eq!(out1.unique_key(), out2.unique_key());
    assert_eq!(out1, out2);
    assert_ne!(out1.unique_key(), out3.unique_key());
    assert_ne!(out1, out3);
    println!("✓ Output deduplication test passed!");
}
