//! Background blockchain scanner built on `monero-wallet`'s scanning engine.
//!
//! Blocks are fetched in 1000-block chunks via `/getblocks.bin` with a
//! one-chunk prefetch pipeline (network latency overlaps CPU scanning).
//! The global RingCT output index each block needs is tracked incrementally
//! (seeded once via `/get_o_indexes.bin`), so no per-block index RPCs are
//! required.

use color_eyre::Result;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use zeroize::Zeroize;

use monero_wallet::block::Block;
use monero_wallet::interface::ScannableBlock;
use monero_wallet::transaction::{Pruned, Transaction};
use monero_wallet::{Scanner as WalletScanner, WalletOutput};

use crate::event::AppEvent;
use crate::rpc::bin::BlockEntry;
use crate::rpc::{DaemonClient, PublishError};
use crate::wallet::balance::OwnedOutput;
use crate::wallet::db::WalletDb;
use crate::wallet::state::StoredOutput;

/// Messages sent from the scanner to the app.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// Scanner started scanning from a given height.
    Started { from_height: u64 },
    /// Progress update during scanning.
    Progress { current: u64, target: u64 },
    /// Found a newly received output (not previously known).
    OutputFound(OwnedOutput),
    /// A previously-unspent output is now spent (key image seen on-chain).
    OutputSpent { key_hex: String },
    /// An output previously marked spent was found unspent again (its
    /// transaction was dropped from the tx pool — funds are safe).
    OutputUnspent { key_hex: String },
    /// A pending outgoing transfer was confirmed (its change output landed).
    TransferConfirmed { tx_hash: String, height: u64 },
    /// An outgoing transfer was dropped from the tx pool without being
    /// mined; its inputs are spendable again.
    TransferFailed { tx_hash: String, reason: String },
    /// A previously uncertain exact-byte relay has now succeeded.
    TransferRelayed { tx_hash: String },
    /// A chain reorganization was handled; the wallet rolled back to the
    /// fork height and is rescanning the new chain.
    Reorg { fork_height: u64 },
    /// Scanning completed up to (and including) a given height.
    Completed { height: u64 },
    /// An error occurred during scanning.
    Error(String),
}

/// The result of processing one block.
enum BlockOutcome {
    /// Block scanned; its height.
    Scanned(u64),
    /// Already-scanned overlapping block (from an adaptive gap-fill chunk);
    /// skipped.
    Overlap,
    /// The daemon returned a block AHEAD of the expected height. Blocks in
    /// between were never delivered — the caller must refetch.
    GapJump { got: u64 },
    /// `prev_id` mismatch: the daemon's chain diverged from what we scanned.
    /// Caller must invoke `Scanner::handle_reorg`.
    ReorgDetected { height: u64 },
}

/// Background blockchain scanner.
pub struct Scanner {
    daemon: DaemonClient,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    wallet_scanner: WalletScanner,
    /// Spend secret scalar, used for key-image (spentness) checks.
    spend_scalar: monero_wallet::ed25519::Scalar,
    /// Wallet database, shared with the send engine and the UI; every
    /// mutation is persisted immediately (encrypted single-file store).
    db: Arc<WalletDb>,
    /// Set to request a graceful stop (e.g. idle auto-lock): the scanner
    /// exits after the current chunk; the send engine stops too.
    cancel: Arc<AtomicBool>,
    /// Last time key-image spentness was checked (throttled).
    last_ki_check: Option<std::time::Instant>,
    /// Exclusive registered minor-index end for each registered account.
    /// Tracking the frontier avoids re-deriving the full 50×200 lookahead
    /// every time an output is found or the user allocates another address.
    registered_minor_ends: Vec<u32>,
}

impl Drop for Scanner {
    fn drop(&mut self) {
        self.spend_scalar.zeroize();
    }
}

impl Scanner {
    pub fn new(
        daemon: DaemonClient,
        event_tx: mpsc::UnboundedSender<AppEvent>,
        wallet_scanner: WalletScanner,
        spend_scalar: monero_wallet::ed25519::Scalar,
        db: Arc<WalletDb>,
        cancel: Arc<AtomicBool>,
    ) -> Self {
        Self {
            daemon,
            event_tx,
            wallet_scanner,
            spend_scalar,
            db,
            cancel,
            last_ki_check: None,
            // `build_wallet_scanner` guarantees this baseline. Any extended
            // builder registrations may be repeated once, which is harmless;
            // assuming they exist would risk permanently skipping indices
            // when a caller supplied only the baseline scanner.
            registered_minor_ends: vec![200; 50],
        }
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Extend the scanner to wallet2's 50-account/200-minor lookahead beyond
    /// an address frontier. Only newly exposed indices are derived.
    fn ensure_subaddress_lookahead(&mut self, major: u32, minor: u32) -> Result<()> {
        use monero_wallet::address::SubaddressIndex;

        let desired_major_end = usize::try_from(major.saturating_add(50))
            .map_err(|_| color_eyre::eyre::eyre!("subaddress account index is too large"))?;
        while self.registered_minor_ends.len() < desired_major_end {
            let new_major = u32::try_from(self.registered_minor_ends.len())
                .map_err(|_| color_eyre::eyre::eyre!("subaddress account index is too large"))?;
            for new_minor in 0..200u32 {
                if let Some(index) = SubaddressIndex::new(new_major, new_minor) {
                    self.wallet_scanner.register_subaddress(index);
                }
            }
            self.registered_minor_ends.push(200);
        }

        let major_index = usize::try_from(major)
            .map_err(|_| color_eyre::eyre::eyre!("subaddress account index is too large"))?;
        let desired_minor_end = minor.saturating_add(200);
        let current_end = self.registered_minor_ends[major_index];
        for new_minor in current_end..desired_minor_end {
            if major == 0 && new_minor == 0 {
                continue;
            }
            if let Some(index) = SubaddressIndex::new(major, new_minor) {
                self.wallet_scanner.register_subaddress(index);
            }
        }
        self.registered_minor_ends[major_index] = current_end.max(desired_minor_end);
        Ok(())
    }

    /// Pick up addresses allocated by the UI while this background scanner
    /// is already running. This closes the gap between a dynamic address list
    /// and the scanner instance created when the wallet was unlocked.
    fn sync_allocated_address_lookahead(&mut self) -> Result<()> {
        let frontier = self
            .db
            .next_receive_minor()?
            .max(self.db.receive_address_count()?)
            .saturating_sub(1);
        self.ensure_subaddress_lookahead(0, frontier)
    }

    /// Run the scanner in the background, scanning from `start_height` to the
    /// chain tip and then watching for new blocks forever. Transient errors
    /// (network hiccups, daemon restarts) are retried with backoff; only a
    /// sustained failure surfaces an error to the UI.
    pub async fn run(mut self, start_height: u64) {
        let _ = self.event_tx.send(AppEvent::Scan(ScanEvent::Started {
            from_height: start_height,
        }));

        let mut consecutive_failures = 0u32;
        loop {
            if self.cancelled() {
                tracing::info!("scanner cancelled; shutting down");
                return;
            }
            match self.scan_loop(start_height).await {
                Ok(()) => {
                    // scan_loop runs forever; an Ok return means the chain
                    // state was rewound (reorg handling) — resume from the
                    // persisted position.
                    consecutive_failures = 0;
                }
                Err(e) => {
                    consecutive_failures += 1;
                    // Surface every failure so the UI can show *why* sync is
                    // stalled (unreachable daemon, timeouts, …) instead of a
                    // progress bar frozen at 0. The retry continues in the
                    // background regardless.
                    let _ = self.event_tx.send(AppEvent::Scan(ScanEvent::Error(format!(
                        "Scan error (retrying, attempt {consecutive_failures}): {e:#}"
                    ))));
                    tracing::warn!("scan attempt failed ({consecutive_failures}): {e:#}");
                    let backoff = std::time::Duration::from_secs(
                        2u64.saturating_mul(1 << consecutive_failures.min(4)),
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    /// Scan from `start_height` (or the persisted scan height, if further
    /// along) to the chain tip, then watch for new blocks forever. Returns
    /// `Ok(())` only after a reorg rollback, so the caller can restart the
    /// loop from the rewound position.
    async fn scan_loop(&mut self, start_height: u64) -> Result<()> {
        // Resume from persisted state when available, otherwise from the
        // caller-provided (wallet creation) height.
        let mut current = match self.db.scan_height() {
            Ok(0) => {
                if let Err(e) = self
                    .db
                    .set_scan_height(start_height)
                    .and_then(|()| self.db.save())
                {
                    tracing::warn!("failed to persist initial scan height: {e}");
                }
                start_height
            }
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("failed to read scan height ({e}); scanning from wallet start");
                start_height
            }
        };

        // The global RingCT index of the first v2 output in the current
        // block. Tracked incrementally once seeded.
        let mut rct_index: Option<u64> = None;
        // Consecutive daemon block-delivery gaps; reset on any scanned block.
        let mut consecutive_gap_jumps = 0u32;

        loop {
            if self.cancelled() {
                return Ok(());
            }
            self.sync_allocated_address_lookahead()?;
            let tip = self.daemon.get_height().await?.saturating_sub(1);
            if current > tip {
                // Caught up: report, refresh spentness (throttled), persist,
                // then wait for the chain to advance.
                let _ = self.event_tx.send(AppEvent::Scan(ScanEvent::Completed {
                    height: current.saturating_sub(1),
                }));

                let check_due = self
                    .last_ki_check
                    .is_none_or(|t| t.elapsed() > std::time::Duration::from_secs(600));
                // Retry only the previously persisted signed bytes. This must
                // run before spentness refresh so an uncertain first relay is
                // never mistaken for a dropped transaction and rebuilt.
                self.retry_unrelayed_transactions().await;

                if check_due {
                    self.refresh_spent_status().await;
                    self.last_ki_check = Some(std::time::Instant::now());
                }

                // Reconcile pending outgoing transfers against the daemon's
                // view every caught-up pass: cheap (one RPC per pending tx)
                // and it self-heals confirmations the block scan can miss
                // (e.g. a block mined in the instant between publishing the
                // transaction and recording it in the database).
                self.reconcile_pending_out().await;

                // Wait for the chain to advance (interruptible by cancel).
                for _ in 0..30 {
                    if self.cancelled() {
                        return Ok(());
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                continue;
            }

            let _ = self.event_tx.send(AppEvent::Scan(ScanEvent::Progress {
                current,
                target: tip,
            }));

            // Parallel chunk pipeline: keep a few `/getblocks.bin` requests
            // in flight (responses consumed in request order) so network
            // latency overlaps both scanning and other requests. Requests are
            // spaced 500 blocks apart — close to the response *size* cap most
            // daemons apply, so gap-fill round-trips are rare and progress
            // updates flow steadily even on slow/throttled nodes. When a
            // daemon still returns fewer blocks than requested, the fetcher
            // adaptively fills the gap: a gap-fill request is inserted
            // in-line before the next queued chunk.
            const CHUNK: u64 = 500;
            const IN_FLIGHT: usize = 3;
            let (chunk_tx, mut chunk_rx) =
                mpsc::channel::<Result<crate::rpc::bin::GetBlocksResponse>>(IN_FLIGHT + 2);
            {
                let daemon = self.daemon.clone();
                let mut h = current;
                tokio::spawn(async move {
                    let mut in_flight: tokio::task::JoinSet<(
                        u64,
                        Result<crate::rpc::bin::GetBlocksResponse>,
                    )> = tokio::task::JoinSet::new();
                    let mut queue: std::collections::VecDeque<u64> =
                        std::collections::VecDeque::new();
                    let mut completed: std::collections::HashMap<
                        u64,
                        Result<crate::rpc::bin::GetBlocksResponse>,
                    > = std::collections::HashMap::new();
                    let mut done_fetching = false;

                    loop {
                        while !done_fetching && in_flight.len() < IN_FLIGHT {
                            let daemon = daemon.clone();
                            let height = h;
                            in_flight.spawn(async move {
                                (height, daemon.get_blocks_bin(height).await)
                            });
                            queue.push_back(height);
                            h += CHUNK;
                        }
                        if queue.is_empty() {
                            return;
                        }

                        // Forward any buffered response that is next in order.
                        if let Some(front) = queue.front().copied()
                            && let Some(resp) = completed.remove(&front)
                        {
                            queue.pop_front();
                            match &resp {
                                Ok(r) if !r.blocks.is_empty() => {
                                    let end = r.start_height + r.blocks.len() as u64 - 1;
                                    let tip = r.current_height.saturating_sub(1);
                                    if end >= tip {
                                        done_fetching = true;
                                    } else {
                                        // Short chunk (size-capped): fill
                                        // the gap up to the next queued
                                        // chunk's start.
                                        let gap_start = end + 1;
                                        let limit = queue.front().copied().unwrap_or(h);
                                        if gap_start < limit {
                                            queue.insert(0, gap_start);
                                            let daemon = daemon.clone();
                                            in_flight.spawn(async move {
                                                (gap_start, daemon.get_blocks_bin(gap_start).await)
                                            });
                                        }
                                    }
                                }
                                // Empty chunk = tip reached; errors are
                                // forwarded to the consumer which will
                                // surface them.
                                _ => done_fetching = true,
                            }
                            if chunk_tx.send(resp).await.is_err() {
                                return;
                            }
                            continue;
                        }

                        // Nothing ready in order; wait for any completion.
                        match in_flight.join_next().await {
                            Some(Ok((height, resp))) => {
                                completed.insert(height, resp);
                            }
                            _ => return,
                        }
                    }
                });
            }

            let mut last_save = std::time::Instant::now();
            let mut last_progress = std::time::Instant::now();
            let mut scanned_any = false;
            let mut rewound = false;

            while let Some(resp) = chunk_rx.recv().await {
                if self.cancelled() {
                    if let Err(e) = self
                        .db
                        .set_scan_height(current)
                        .and_then(|()| self.db.save())
                    {
                        tracing::warn!("failed to save scan state: {e}");
                    }
                    return Ok(());
                }
                // A fetch/parse error here is transient: drop the pipeline,
                // surface to the outer retry loop which re-fetches from
                // `current` (state is consistent — it only advances past
                // fully-scanned blocks).
                let resp = resp?;
                if resp.blocks.is_empty() {
                    break;
                }

                // Address allocation can happen while a long historical scan
                // is in flight; refresh before consuming each returned chunk.
                self.sync_allocated_address_lookahead()?;

                for entry in resp.blocks {
                    match self.process_block(entry, current, &mut rct_index).await? {
                        BlockOutcome::Scanned(height) => {
                            current = current.max(height + 1);
                            consecutive_gap_jumps = 0;
                        }
                        BlockOutcome::Overlap => {}
                        BlockOutcome::GapJump { got } => {
                            // The daemon skipped blocks (never scan past a
                            // gap — outputs would be missed forever). Drop
                            // this pipeline and refetch from `current`.
                            consecutive_gap_jumps += 1;
                            if consecutive_gap_jumps > 5 {
                                return Err(color_eyre::eyre::eyre!(
                                    "daemon repeatedly jumps from {current} to {got}; \
                                     refusing to skip blocks"
                                ));
                            }
                            tracing::warn!("daemon jumped from {current} to {got}; refetching");
                            rewound = true;
                            break;
                        }
                        BlockOutcome::ReorgDetected { height } => {
                            let fork = self.handle_reorg(height).await?;
                            current = fork + 1;
                            rct_index = None;
                            rewound = true;
                            break;
                        }
                    }
                    scanned_any = true;

                    if last_progress.elapsed() > std::time::Duration::from_millis(250) {
                        last_progress = std::time::Instant::now();
                        let _ = self.event_tx.send(AppEvent::Scan(ScanEvent::Progress {
                            current,
                            target: tip,
                        }));
                    }
                }

                if rewound {
                    break;
                }

                // Persist after every chunk (~1000 blocks) and at least every
                // few seconds so progress is never lost.
                if let Err(e) = self.db.set_scan_height(current) {
                    tracing::warn!("failed to record scan height: {e}");
                }
                if last_save.elapsed() > std::time::Duration::from_secs(2) {
                    last_save = std::time::Instant::now();
                    if let Err(e) = self.db.save() {
                        tracing::warn!("failed to save scan state: {e}");
                    }
                }
            }

            if rewound {
                // Restart the pass immediately from the corrected position.
                continue;
            }

            if !scanned_any {
                // Nothing returned despite `current <= tip`; avoid a tight
                // error loop.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }

            // Final save for this pass; the loop-top handles the caught-up
            // case (completion event, spentness refresh, and backoff).
            if let Err(e) = self
                .db
                .set_scan_height(current)
                .and_then(|()| self.db.save())
            {
                tracing::warn!("failed to save scan state: {e}");
            }
        }
    }

    /// Parse, scan, and fold a single fetched block into the wallet state.
    ///
    /// Never skips blocks: a block ahead of `expected_height` yields
    /// [`BlockOutcome::GapJump`] so the caller refetches; a block whose
    /// `prev_id` disagrees with the recorded hash of the previous block
    /// yields [`BlockOutcome::ReorgDetected`].
    async fn process_block(
        &mut self,
        entry: BlockEntry,
        expected_height: u64,
        rct_index: &mut Option<u64>,
    ) -> Result<BlockOutcome> {
        let block = Block::read(&mut entry.block_blob.as_slice())
            .map_err(|e| color_eyre::eyre::eyre!("failed to parse block blob: {e}"))?;
        let height = block.number() as u64;
        let timestamp = block.header.timestamp;

        if height < expected_height {
            // Overlap from an adaptive gap-fill chunk; already scanned.
            return Ok(BlockOutcome::Overlap);
        }
        if height > expected_height {
            // The daemon jumped ahead (reorg mid-scan or a broken daemon).
            // Refusing to continue protects against silently missing outputs.
            return Ok(BlockOutcome::GapJump { got: height });
        }

        // Chain-continuity check: this block's prev_id must match the hash we
        // recorded for the previous block when we scanned it.
        let prev_hex = hex::encode(block.header.previous);
        if height > 0 {
            let recorded = match self.db.recorded_hash(height - 1) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("failed to read recorded hash: {e}");
                    None
                }
            };
            match recorded {
                Some(recorded) if recorded != prev_hex => {
                    tracing::warn!(
                        "reorg detected at block {height}: prev_id {prev_hex} != recorded {recorded}"
                    );
                    return Ok(BlockOutcome::ReorgDetected { height });
                }
                Some(_) => {}
                None => {
                    // No recorded hash (fresh database or window eviction):
                    // anchor trust-on-first-use from the daemon.
                    if let Ok(hash) = self.daemon.get_block_hash(height - 1).await
                        && let Err(e) = self.db.push_hash(height - 1, &hash)
                    {
                        tracing::warn!("failed to record block hash: {e}");
                    }
                }
            }
        }
        let block_hash = block.hash();

        // Parse the non-miner transactions (pruned is fine for scanning).
        let mut transactions = Vec::with_capacity(entry.txs.len());
        for tx_entry in &entry.txs {
            let tx = Transaction::<Pruned>::read(&mut tx_entry.pruned_blob.as_slice())
                .map_err(|e| color_eyre::eyre::eyre!("failed to parse tx blob: {e}"))?;
            transactions.push(tx);
        }

        // Confirm pending outgoing transfers whose tx hash appears in this
        // block (works even for zero-change transactions). Pruned blobs don't
        // carry the prunable data, so the daemon-provided prunable hashes are
        // used to compute the real transaction ids.
        for (tx, tx_entry) in transactions.iter().zip(entry.txs.iter()) {
            let Some(txid_bytes) = tx.hash_with_prunable_hash(tx_entry.prunable_hash) else {
                continue;
            };
            let txid = hex::encode(txid_bytes);
            // Do not advance past a block whose wallet mutations could not be
            // committed. Reprocessing is safe because the updates are
            // idempotent.
            let confirmed_now = self.db.confirm_out_transfer(&txid, height, timestamp)?;
            if confirmed_now {
                let _ = self
                    .event_tx
                    .send(AppEvent::Scan(ScanEvent::TransferConfirmed {
                        tx_hash: txid,
                        height,
                    }));
            }
        }

        let miner_is_v2 = matches!(block.miner_transaction(), Transaction::V2 { .. });
        // First non-miner v2 transaction and its index in `transactions`.
        let first_v2_tx = transactions
            .iter()
            .enumerate()
            .find(|(_, tx)| matches!(tx, Transaction::V2 { .. }));
        let has_v2_tx = miner_is_v2 || first_v2_tx.is_some();

        // Determine the global RingCT index of this block's first v2 output.
        if has_v2_tx && rct_index.is_none() {
            *rct_index = Some(
                self.seed_rct_index(&block, &entry, miner_is_v2, &transactions)
                    .await?,
            );
        }

        // Self-healing check: cross-check our tracked index against the
        // daemon-provided output indices of the first non-miner v2 tx.
        if miner_is_v2 {
            if let (Some(tracked), Some((tx_pos, _))) = (*rct_index, first_v2_tx) {
                let daemon_indices = &entry.txs[tx_pos].output_indices;
                if let Some(&daemon_first) = daemon_indices.first() {
                    let miner_outputs = block.miner_transaction().prefix().outputs.len() as u64;
                    let expected = tracked + miner_outputs;
                    if expected != daemon_first {
                        tracing::warn!(
                            "RingCT index drift at block {height}: tracked {expected}, \
                             daemon says {daemon_first}; re-seeding"
                        );
                        *rct_index = Some(daemon_first.saturating_sub(miner_outputs));
                    }
                }
            }
        } else if rct_index.is_none() {
            // Pre-RCT blocks: the index value is unused by the scanner, but a
            // value must exist for it to scan v1 outputs.
            *rct_index = Some(0);
        }

        // Count v2 outputs in this block (to advance the index afterwards).
        let miner_v2_outputs = if miner_is_v2 {
            block.miner_transaction().prefix().outputs.len() as u64
        } else {
            0
        };
        let tx_v2_outputs: u64 = transactions
            .iter()
            .map(|tx| match tx {
                Transaction::V2 { .. } => tx.prefix().outputs.len() as u64,
                Transaction::V1 { .. } => 0,
            })
            .sum();

        let scannable = ScannableBlock {
            block,
            transactions,
            output_index_for_first_ringct_output: *rct_index,
        };
        let block_height = scannable.block.number() as u64;
        let hardfork = scannable.block.header.hardfork_version;

        // Advance the tracked index for the next block.
        if let Some(idx) = rct_index.as_mut() {
            *idx += miner_v2_outputs + tx_v2_outputs;
        }

        let found = match self.wallet_scanner.scan(scannable) {
            Ok(found) => found,
            Err(monero_wallet::ScanError::UnsupportedProtocol(v)) => {
                // Advancing would permanently hide every wallet output in an
                // unsupported block. Stop at this exact height until the
                // wallet is upgraded.
                return Err(color_eyre::eyre::eyre!(
                    "block {block_height} uses unsupported protocol v{v}; upgrade muff before continuing"
                ));
            }
            Err(e) => {
                return Err(color_eyre::eyre::eyre!(
                    "scan failed at block {block_height}: {e}"
                ));
            }
        };

        for output in found.ignore_additional_timelock() {
            self.record_output(output, block_height, timestamp, hardfork)?;
        }
        self.db.push_hash(block_height, &hex::encode(block_hash))?;
        Ok(BlockOutcome::Scanned(block_height))
    }

    /// Handle a detected chain reorganization: walk the recorded hash window
    /// back to the fork block (comparing against the daemon's current chain),
    /// roll the wallet state back to it, then re-verify the spent status of
    /// every output via key images. Returns the fork height.
    async fn handle_reorg(&mut self, detected_at: u64) -> Result<u64> {
        // Compare recorded hashes against the daemon's current chain, newest
        // first, in batched ranges.
        let mut window: Vec<(u64, String)> = self
            .db
            .hash_window(detected_at.saturating_sub(1))?
            .into_iter()
            .collect();
        // Defensive: batched comparison below requires heights to be a
        // contiguous range (window[i] == start + i). Heights are pushed in
        // scan order so this normally holds; if not, drop oldest entries
        // until it does.
        while window.len() > 1
            && window[window.len() - 1].0 != window[0].0 + (window.len() as u64 - 1)
        {
            window.remove(0);
        }

        let mut fork: Option<u64> = None;
        if window.is_empty() {
            // No history to compare against (upgraded state file): nothing to
            // roll back; re-anchor on the daemon's chain.
            tracing::warn!("reorg at {detected_at} but no recorded hashes; re-anchoring");
        } else {
            let mut idx = window.len();
            while idx > 0 && fork.is_none() {
                let lo = idx.saturating_sub(256);
                let start_h = window[lo].0;
                let end_h = window[idx - 1].0;
                let daemon_hashes = self.daemon.get_block_hashes_range(start_h, end_h).await?;
                // Heights in `window` are a contiguous range [start_h..=end_h].
                for (i, (h, recorded)) in window[lo..idx].iter().enumerate().rev() {
                    if let Some(daemon_hash) = daemon_hashes.get(i)
                        && daemon_hash == recorded
                    {
                        fork = Some(*h);
                        break;
                    }
                }
                idx = lo;
            }
        }

        let fork = match fork {
            Some(f) => f,
            None => {
                // Fork not found within the recorded window: roll back the
                // whole window and rescan it (the next pass re-anchors).
                let oldest = window.first().map(|(h, _)| *h);
                match oldest {
                    Some(o) if o > 0 => {
                        tracing::warn!(
                            "reorg deeper than recorded window; rolling back to {}",
                            o - 1
                        );
                        o - 1
                    }
                    _ => {
                        // Nothing recorded at all: just rescan from the
                        // detected height minus one, trusting the daemon.
                        detected_at.saturating_sub(1)
                    }
                }
            }
        };

        let removed = self.db.rollback(fork)?;
        tracing::warn!(
            "rolled back to block {fork} ({removed} outputs removed); rescanning new chain"
        );

        // The spend status of surviving outputs may have changed (spends in
        // orphaned blocks are no longer on-chain): re-check everything.
        self.refresh_spent_status_full().await;

        if let Err(e) = self.db.save() {
            tracing::warn!("failed to save state after reorg rollback: {e}");
        }
        let _ = self
            .event_tx
            .send(AppEvent::Scan(ScanEvent::Reorg { fork_height: fork }));
        Ok(fork)
    }

    /// Seed the global RingCT first-output index for the given block, using
    /// the daemon-provided output indices (falling back to a single
    /// `/get_o_indexes.bin` call when they're missing).
    async fn seed_rct_index(
        &self,
        block: &Block,
        entry: &BlockEntry,
        miner_is_v2: bool,
        transactions: &[Transaction<Pruned>],
    ) -> Result<u64> {
        if miner_is_v2 {
            // The miner's v2 output is the block's first RingCT output.
            if let Some(first) = entry.miner_output_indices.first() {
                return Ok(*first);
            }
            // Arithmetic from the first non-miner v2 tx's indices.
            if let Some((tx_pos, _)) = transactions
                .iter()
                .enumerate()
                .find(|(_, tx)| matches!(tx, Transaction::V2 { .. }))
                && let Some(&first) = entry.txs[tx_pos].output_indices.first()
            {
                let miner_outputs = block.miner_transaction().prefix().outputs.len() as u64;
                return Ok(first.saturating_sub(miner_outputs));
            }
            // Last resort: query the miner tx's indices directly.
            let miner_hash = block.miner_transaction().hash();
            let indexes = self.daemon.get_o_indexes(miner_hash).await?;
            if let Some(first) = indexes.first() {
                return Ok(*first);
            }
            return Err(color_eyre::eyre::eyre!(
                "could not determine RingCT index seed for block {}",
                block.number()
            ));
        }

        // v1 miner: the first non-miner v2 tx defines the seed.
        if let Some((tx_pos, _)) = transactions
            .iter()
            .enumerate()
            .find(|(_, tx)| matches!(tx, Transaction::V2 { .. }))
            && let Some(&first) = entry.txs[tx_pos].output_indices.first()
        {
            return Ok(first);
        }
        Err(color_eyre::eyre::eyre!(
            "no v2 transactions to seed the RingCT index from at block {}",
            block.number()
        ))
    }

    /// Record a found output into wallet state and notify the UI.
    fn record_output(
        &mut self,
        output: WalletOutput,
        height: u64,
        timestamp: u64,
        _hardfork: u8,
    ) -> Result<()> {
        let key_hex = hex::encode(output.key().compress().to_bytes());
        let tx_hash = hex::encode(output.transaction());
        let amount = output.commitment().amount;
        let unlock_height = crate::wallet::send::unlock_height(&output, height);
        let output_index = output.index_in_transaction() as usize;
        let (major, minor) = output
            .subaddress()
            .map(|i| (i.account(), i.address()))
            .unwrap_or((0, 0));

        // A hit at the edge moves the lookahead frontier just as wallet2's
        // expandable subaddress map does.
        self.ensure_subaddress_lookahead(major, minor)?;

        let stored = StoredOutput {
            wallet_output_hex: hex::encode(output.serialize()),
            key_hex: key_hex.clone(),
            amount,
            height,
            timestamp,
            spent: false,
            spent_tx: None,
        };
        let note = if major == 0 && minor == 0 {
            "Primary address".to_string()
        } else {
            format!("Subaddress {major}/{minor}")
        };

        // Burning-bug / replay dedup: never track the same output key twice.
        // (Pending outgoing transfers are confirmed by tx-hash matching in
        // `process_block`, which also covers zero-change transactions.)
        let inserted = match self.db.insert_received_output(&stored, &tx_hash, &note) {
            Ok(inserted) => inserted,
            Err(e) => {
                return Err(color_eyre::eyre::eyre!(
                    "record wallet output {key_hex}: {e}"
                ));
            }
        };
        if major == 0 && minor > 0 {
            // Keep the receive cursor beyond every observed subaddress. This
            // gives the UI fresh addresses while the fixed lookahead below
            // preserves restore compatibility with wallet2.
            self.db.advance_receive_minor(minor.saturating_add(1))?;
            self.db
                .ensure_receive_address_count(minor.saturating_add(1))?;
        }
        if !inserted {
            return Ok(());
        }

        let _ = self
            .event_tx
            .send(AppEvent::Scan(ScanEvent::OutputFound(OwnedOutput {
                tx_hash,
                output_index,
                key_hex,
                height,
                amount,
                spent: false,
                subaddress_major: major,
                subaddress_minor: minor,
                timestamp,
                unlock_height,
            })));
        Ok(())
    }

    /// Ask the daemon about every outgoing transfer we believe is still in
    /// the pool; if it has been mined, record the confirmation (with the
    /// real block height/timestamp) and notify the UI.
    ///
    /// Dropped transactions are left to the key-image check, which unlocks
    /// the reserved inputs.
    async fn reconcile_pending_out(&mut self) {
        let pending = match self.db.pending_out_transfers() {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("pool reconciliation: failed to load pending transfers: {e}");
                return;
            }
        };
        if pending.is_empty() {
            return;
        }
        let mut changed = false;
        for txid in pending {
            let Ok(hash) = monero::Hash::from_str(&txid) else {
                continue;
            };
            match self.daemon.get_tx_confirmation(hash).await {
                Ok(Some((height, timestamp))) => {
                    match self.db.confirm_out_transfer(&txid, height, timestamp) {
                        Ok(true) => {
                            changed = true;
                            tracing::info!(
                                "transfer {txid} confirmed at block {height} via pool reconciliation"
                            );
                            let _ =
                                self.event_tx
                                    .send(AppEvent::Scan(ScanEvent::TransferConfirmed {
                                        tx_hash: txid.clone(),
                                        height,
                                    }));
                        }
                        Ok(false) => {}
                        Err(e) => {
                            tracing::warn!("failed to update transfer confirmation: {e}");
                        }
                    }
                }
                // Still in the pool (or the daemon doesn't know it) — keep
                // waiting; a vanishing tx is handled by the KI check.
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!("pool reconciliation query failed: {e}");
                    return;
                }
            }
        }
        if changed && let Err(e) = self.db.save() {
            tracing::warn!("failed to save after pool reconciliation: {e}");
        }
    }

    /// Retry signed transactions whose first relay result was uncertain.
    /// Reusing the byte-for-byte transaction is the ring-intersection safety
    /// boundary: this method must never invoke transaction construction.
    async fn retry_unrelayed_transactions(&mut self) {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs().saturating_sub(30))
            .unwrap_or(0);
        let pending = match self.db.unrelayed_transactions(cutoff) {
            Ok(pending) => pending,
            Err(e) => {
                tracing::warn!("failed to load transactions awaiting relay: {e}");
                return;
            }
        };
        let mut changed = false;
        for (tx_hash, tx_blob) in pending {
            match self.daemon.publish_transaction(&tx_blob).await {
                Ok(_) => match self.db.mark_transaction_relayed(&tx_hash) {
                    Ok(()) => {
                        changed = true;
                        tracing::info!("relayed saved transaction {tx_hash}");
                        let _ = self
                            .event_tx
                            .send(AppEvent::Scan(ScanEvent::TransferRelayed {
                                tx_hash: tx_hash.clone(),
                            }));
                    }
                    Err(e) => tracing::warn!("failed to mark {tx_hash} relayed: {e}"),
                },
                Err(PublishError::Rejected(reason)) => {
                    match self.db.reject_signed_transfer(&tx_hash) {
                        Ok(()) => {
                            changed = true;
                            tracing::warn!("saved transaction {tx_hash} was rejected: {reason}");
                            let _ = self
                                .event_tx
                                .send(AppEvent::Scan(ScanEvent::TransferFailed {
                                    tx_hash,
                                    reason: format!("was rejected by the daemon: {reason}"),
                                }));
                        }
                        Err(e) => tracing::warn!("failed to release rejected {tx_hash}: {e}"),
                    }
                }
                Err(PublishError::Ambiguous(reason)) => {
                    // A duplicate submission commonly has an ambiguous
                    // response. Resolve it by key image before leaving the
                    // exact blob queued for the next pass.
                    let reserved = match self.db.outputs_reserved_by(&tx_hash) {
                        Ok(outputs) => outputs,
                        Err(e) => {
                            tracing::warn!("failed to load inputs for {tx_hash}: {e}");
                            continue;
                        }
                    };
                    let images: Vec<String> = reserved
                        .iter()
                        .filter_map(|output| {
                            crate::wallet::send::key_image_for_stored(output, &self.spend_scalar)
                        })
                        .collect();
                    let relayed = !images.is_empty()
                        && images.len() == reserved.len()
                        && matches!(
                            self.daemon.is_key_images_spent(&images).await,
                            Ok(statuses) if statuses.len() == images.len()
                                && statuses.iter().all(|status| *status != 0)
                        );
                    if relayed {
                        if let Err(e) = self.db.mark_transaction_relayed(&tx_hash) {
                            tracing::warn!("failed to mark {tx_hash} relayed: {e}");
                        } else {
                            changed = true;
                            let _ =
                                self.event_tx
                                    .send(AppEvent::Scan(ScanEvent::TransferRelayed {
                                        tx_hash: tx_hash.clone(),
                                    }));
                        }
                    } else {
                        tracing::debug!(
                            "saved transaction {tx_hash} still has an uncertain relay result: {reason}"
                        );
                    }
                }
            }
        }
        if changed && let Err(e) = self.db.save() {
            tracing::warn!("failed to save transaction relay updates: {e}");
        }
    }

    /// Refresh the spent status of outputs via key image lookups.
    ///
    /// Covers both directions, which is what makes stuck funds impossible:
    /// - unspent outputs whose key image appears on-chain / in the pool are
    ///   marked spent;
    /// - outputs *optimistically* marked spent by one of our pending
    ///   transactions whose key image is no longer known to the daemon (the
    ///   tx was dropped from the pool) are marked unspent again and their
    ///   transfer is flagged as failed.
    async fn refresh_spent_status(&mut self) {
        self.refresh_spent_status_impl(false).await;
    }

    /// Re-check every output (used after a reorg rollback).
    async fn refresh_spent_status_full(&mut self) {
        self.refresh_spent_status_impl(true).await;
    }

    async fn refresh_spent_status_impl(&mut self, full: bool) {
        // Collect key images for outputs worth checking: every output for a
        // full (post-reorg) check; otherwise unspent outputs plus outputs
        // reserved by a still-pending outgoing transfer (so a dropped tx
        // unlocks the funds again).
        let outputs = match self.db.outputs_for_ki_check(full) {
            Ok(o) => o,
            Err(e) => {
                tracing::debug!("key image check: failed to load outputs: {e}");
                return;
            }
        };
        // Keep every derived image attached to the exact output it belongs to.
        // Filtering images into a separate vector and later zipping with
        // `outputs` shifts the response onto the wrong wallet rows whenever a
        // corrupt/unreadable output is skipped.
        let outputs_with_images: Vec<(&StoredOutput, String)> = outputs
            .iter()
            .filter_map(|output| {
                match crate::wallet::send::key_image_for_stored(output, &self.spend_scalar) {
                    Some(image) => Some((output, image)),
                    None => {
                        tracing::warn!(
                            "cannot derive key image for stored output {}; leaving its state unchanged",
                            output.key_hex
                        );
                        None
                    }
                }
            })
            .collect();
        if outputs_with_images.is_empty() {
            return;
        }

        for chunk in outputs_with_images.chunks(200) {
            let images: Vec<String> = chunk.iter().map(|(_, image)| image.clone()).collect();
            let statuses = match self.daemon.is_key_images_spent(&images).await {
                Ok(statuses) => statuses,
                Err(e) => {
                    tracing::debug!("key image spent check failed: {e}");
                    return;
                }
            };

            let mut spent_events = Vec::new();
            let mut unspent_events = Vec::new();
            let mut failed_txs = Vec::new();
            for ((output, _), status) in chunk.iter().zip(statuses.iter()) {
                // 0 = unspent, 1 = spent on-chain, 2 = in pool.
                if *status != 0 {
                    if !output.spent {
                        if let Err(e) = self.db.mark_spent(&output.key_hex) {
                            tracing::warn!("failed to mark output spent: {e}");
                            continue;
                        }
                        spent_events.push(output.key_hex.clone());
                    }
                    continue;
                }
                // Daemon says unspent.
                if output.spent {
                    if output.spent_tx.as_deref().is_some_and(|tx_hash| {
                        // Fail closed on a database error: releasing an input
                        // whose first relay is uncertain is the unsafe choice.
                        self.db.transaction_awaiting_relay(tx_hash).unwrap_or(true)
                    }) {
                        continue;
                    }
                    match self.db.release_output(&output.key_hex) {
                        Ok(released) => {
                            unspent_events.push(output.key_hex.clone());
                            // If the spend was one of our pending transactions,
                            // that transaction was dropped from the pool.
                            if let Some(txid) = released {
                                failed_txs.push(txid);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("failed to release output: {e}");
                        }
                    }
                }
            }
            if (!spent_events.is_empty() || !unspent_events.is_empty())
                && let Err(e) = self.db.save()
            {
                tracing::warn!("failed to save after key-image refresh: {e}");
            }

            for key_hex in spent_events {
                let _ = self
                    .event_tx
                    .send(AppEvent::Scan(ScanEvent::OutputSpent { key_hex }));
            }
            for key_hex in unspent_events {
                let _ = self
                    .event_tx
                    .send(AppEvent::Scan(ScanEvent::OutputUnspent { key_hex }));
            }
            for tx_hash in failed_txs {
                tracing::warn!(
                    "transaction {tx_hash} was dropped from the tx pool; inputs unlocked"
                );
                let _ = self
                    .event_tx
                    .send(AppEvent::Scan(ScanEvent::TransferFailed {
                        tx_hash,
                        reason: "was dropped by the network".to_string(),
                    }));
            }
        }
    }
}

/// Build a `monero-wallet` ViewPair from the wallet's keys.
pub fn build_view_pair(keys: &crate::wallet::WalletKeys) -> Result<monero_wallet::ViewPair> {
    use monero_wallet::ed25519::{CompressedPoint, Scalar};
    use zeroize::Zeroizing;

    let spend_bytes: [u8; 32] = keys
        .spend_public
        .as_bytes()
        .try_into()
        .map_err(|_| color_eyre::eyre::eyre!("spend public key must be 32 bytes"))?;
    let spend_point = CompressedPoint::from(spend_bytes)
        .decompress()
        .ok_or_else(|| color_eyre::eyre::eyre!("invalid spend public key"))?;

    let view_bytes: [u8; 32] = keys
        .viewpair
        .view
        .as_bytes()
        .try_into()
        .map_err(|_| color_eyre::eyre::eyre!("view secret key must be 32 bytes"))?;
    let view_scalar = Scalar::read(&mut view_bytes.as_slice())
        .map_err(|e| color_eyre::eyre::eyre!("invalid view secret key: {e}"))?;

    monero_wallet::ViewPair::new(spend_point, Zeroizing::new(view_scalar))
        .map_err(|e| color_eyre::eyre::eyre!("failed to build view pair: {e}"))
}

/// Convert the wallet's keys into a `monero-wallet` scanner using wallet2's
/// default 50-account by 200-address lookahead window.
pub fn build_wallet_scanner(keys: &crate::wallet::WalletKeys) -> Result<WalletScanner> {
    build_wallet_scanner_with_cursor(keys, 1)
}

/// Build the reference lookahead while extending account 0 past the wallet's
/// highest observed receive address. `next_receive_minor` is the first unused
/// minor index persisted by `WalletDb`.
pub fn build_wallet_scanner_with_cursor(
    keys: &crate::wallet::WalletKeys,
    next_receive_minor: u32,
) -> Result<WalletScanner> {
    use monero_wallet::address::SubaddressIndex;

    let pair = build_view_pair(keys)?;
    let mut scanner = WalletScanner::new(pair);
    // Primary 0/0 is implicit. Keeping the reference lookahead is important
    // for restore behavior: funds must not disappear merely because they were
    // received on an address beyond the small set currently shown by the UI.
    for major in 0..50u32 {
        let minor_end = if major == 0 {
            next_receive_minor
                .saturating_sub(1)
                .saturating_add(200)
                .max(200)
        } else {
            200
        };
        for minor in 0..minor_end {
            if major == 0 && minor == 0 {
                continue;
            }
            if let Some(index) = SubaddressIndex::new(major, minor) {
                scanner.register_subaddress(index);
            }
        }
    }
    Ok(scanner)
}
