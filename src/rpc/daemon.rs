use color_eyre::Result;
use monero::blockdata::block::Block;
use monero::blockdata::transaction::Transaction;
use monero::consensus::encode::deserialize;
use monero_rpc::{GetBlockHeaderSelector, RpcClient, RpcClientBuilder};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use monero_wallet::ed25519::{CompressedPoint, Point};
use monero_wallet::interface::{
    EvaluateUnlocked, FeeError, FeePriority, FeeRate, InterfaceError, ProvidesBlockchainMeta,
    ProvidesUnvalidatedDecoys, ProvidesUnvalidatedFeeRates, TransactionsError,
};

use crate::config::{Config, NetworkKind};

use super::bin;

/// Cached absolute cumulative RingCT output distribution.
///
/// `values[i]` is the number of RingCT outputs created up to and including
/// block `start + i`. The daemon trims leading all-zero blocks, so `start`
/// is typically the first RingCT block height.
#[derive(Debug)]
struct CachedDistribution {
    start: u64,
    values: Vec<u64>,
}

impl CachedDistribution {
    fn end(&self) -> u64 {
        self.start + self.values.len().saturating_sub(1) as u64
    }
}

/// Historic priority multipliers, retained only for bounding a maliciously
/// high daemon response. Current monerod returns one already-adjusted rate per
/// priority in `fees`; applying these to the returned rates would multiply the
/// fee twice and make our transactions differ from wallet2.
pub fn fee_multiplier(priority: u32) -> u64 {
    match priority {
        1 => 1,    // Unimportant / Low
        2 => 5,    // Normal
        3 => 25,   // Elevated
        _ => 1000, // Priority (and any out-of-range custom value)
    }
}

/// Current `/get_fee_estimate` response shape. The rates in `fees` are already
/// ordered by wallet priority: slow, normal, fast, fastest.
#[derive(Debug, serde::Deserialize)]
struct FeeEstimateResponse {
    #[allow(dead_code)]
    fee: Option<u64>,
    fees: Option<Vec<u64>>,
    quantization_mask: Option<u64>,
}

fn fee_rate_from_response(priority: u32, response: FeeEstimateResponse) -> Result<FeeRate> {
    let index = usize::try_from(
        priority
            .checked_sub(1)
            .ok_or_else(|| color_eyre::eyre::eyre!("invalid fee priority {priority}"))?,
    )
    .map_err(|_| color_eyre::eyre::eyre!("invalid fee priority {priority}"))?;
    let fees = response
        .fees
        .ok_or_else(|| color_eyre::eyre::eyre!("fee estimate is missing priority rates"))?;
    let per_weight = fees.get(index).copied().ok_or_else(|| {
        color_eyre::eyre::eyre!("fee estimate has no rate for priority {priority}")
    })?;
    let mask = response
        .quantization_mask
        .ok_or_else(|| color_eyre::eyre::eyre!("fee estimate is missing quantization_mask"))?;
    FeeRate::new(per_weight, mask)
        .ok_or_else(|| color_eyre::eyre::eyre!("daemon returned an invalid fee rate"))
}

/// Wrapper around the monero-rpc daemon client with connection state tracking.
#[derive(Clone)]
pub struct DaemonClient {
    inner: Arc<RwLock<Option<DaemonInner>>>,
    /// Daemon base URL; shared so `set_url` retargets every clone (the
    /// status poller, scanner and send engine all hold clones).
    url: Arc<RwLock<String>>,
    proxy: Option<String>,
    /// reqwest client for binary (`*.bin`) and ad-hoc JSON endpoints.
    http: reqwest::Client,
    /// Refuse nodes serving a different chain before the scanner or send
    /// engine can consume any of their data.
    expected_network: NetworkKind,
    /// Cached cumulative RingCT output distribution (absolute counts).
    rct_distribution_cache: Arc<Mutex<Option<Arc<CachedDistribution>>>>,
}

struct DaemonInner {
    client: RpcClient,
}

/// Cached node status information.
#[derive(Debug, Clone, Default)]
pub struct NodeStatus {
    pub connected: bool,
    pub height: u64,
    pub target_height: u64,
    pub synced: bool,
    pub version: String,
    pub net_type: String,
    pub peer_count: u64,
    pub error: Option<String>,
}

/// A definitive daemon rejection is safe to rebuild (while reusing the saved
/// rings); a transport or response failure is ambiguous and must only retry
/// the exact same signed blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    Rejected(String),
    Ambiguous(String),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(message) => write!(f, "daemon rejected transaction: {message}"),
            Self::Ambiguous(message) => {
                write!(f, "transaction relay result is uncertain: {message}")
            }
        }
    }
}

impl std::error::Error for PublishError {}

/// Response from /get_info endpoint.
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct GetInfoResponse {
    height: Option<u64>,
    target_height: Option<u64>,
    busy_syncing: Option<bool>,
    version: Option<String>,
    nettype: Option<String>,
    outgoing_connections_count: Option<u64>,
    incoming_connections_count: Option<u64>,
    #[serde(default)]
    status: String,
}

/// Normalize a daemon URL so it always carries an explicit scheme.
///
/// The `monero-rpc` builder (and `reqwest`) reject bare `host:port` strings,
/// so users often trip over `builder error for url (...)`. Prepend `http://`
/// when no scheme is present, and strip trailing slashes so endpoint paths
/// like `/json_rpc` and `/get_info` join cleanly.
pub fn normalize_url(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{}", trimmed)
    }
}

impl DaemonClient {
    pub fn new(config: &Config) -> Self {
        let mut http_builder = reqwest::Client::builder()
            .user_agent(concat!("muff/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(120));
        if let Some(ref proxy) = config.daemon.proxy
            && let Ok(p) = reqwest::Proxy::all(proxy)
        {
            http_builder = http_builder.proxy(p);
        }
        let http = http_builder
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            inner: Arc::new(RwLock::new(None)),
            url: Arc::new(RwLock::new(normalize_url(&config.daemon.url))),
            proxy: config.daemon.proxy.clone(),
            http,
            expected_network: config.wallet.network,
            rct_distribution_cache: Arc::new(Mutex::new(None)),
        }
    }

    /// The current daemon base URL.
    pub async fn url(&self) -> String {
        self.url.read().await.clone()
    }

    /// Retarget this client (and every clone) at a different daemon: swap
    /// the URL, drop the cached RPC client so the next call reconnects, and
    /// clear chain-derived caches (a different daemon may serve a different
    /// network).
    pub async fn set_url(&self, new_url: &str) {
        let normalized = normalize_url(new_url);
        *self.url.write().await = normalized;
        *self.inner.write().await = None;
        *self.rct_distribution_cache.lock().await = None;
    }

    /// Attempt to connect to the daemon and cache the client.
    pub async fn connect(&self) -> Result<()> {
        let url = self.url().await;
        let mut builder = RpcClientBuilder::new();
        if let Some(ref proxy) = self.proxy {
            builder = builder.proxy_address(proxy);
        }
        let client = builder
            .build(&url)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to build RPC client: {}", e))?;

        // Test connection by calling get_block_count
        let _count = client
            .clone()
            .daemon()
            .get_block_count()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC connection test failed: {}", e))?;

        let status = self.get_status_at(&url).await;
        if !status.connected {
            return Err(color_eyre::eyre::eyre!(
                "daemon status check failed: {}",
                status.error.as_deref().unwrap_or("unknown error")
            ));
        }
        let expected = self.expected_network.as_str();
        if status.net_type != expected {
            return Err(color_eyre::eyre::eyre!(
                "daemon network mismatch: wallet uses {expected}, daemon reports {}",
                status.net_type
            ));
        }

        // Do not install a client for an endpoint that was replaced while
        // its connection/status checks were in flight. Holding the URL read
        // guard through installation also makes `set_url` clear this client
        // if it begins immediately afterwards.
        let current_url = self.url.read().await;
        if *current_url != url {
            return Err(color_eyre::eyre::eyre!(
                "daemon URL changed while connecting; retrying with the new endpoint"
            ));
        }
        let mut guard = self.inner.write().await;
        *guard = Some(DaemonInner { client });
        Ok(())
    }

    /// Get the current node status by querying the /get_info endpoint directly.
    pub async fn get_status(&self) -> NodeStatus {
        let url = self.url().await;
        self.get_status_at(&url).await
    }

    async fn get_status_at(&self, base_url: &str) -> NodeStatus {
        let url = format!("{base_url}/get_info");
        // Use the configured client so proxy settings (e.g. Tor) apply and
        // timeouts are bounded.
        match self.http.get(&url).send().await {
            Ok(resp) => match resp.json::<GetInfoResponse>().await {
                Ok(info) => NodeStatus {
                    connected: true,
                    height: info.height.unwrap_or(0),
                    target_height: info.target_height.unwrap_or(info.height.unwrap_or(0)),
                    synced: !info.busy_syncing.unwrap_or(false),
                    version: info.version.unwrap_or_default(),
                    net_type: info.nettype.unwrap_or_else(|| "unknown".to_string()),
                    peer_count: info.outgoing_connections_count.unwrap_or(0)
                        + info.incoming_connections_count.unwrap_or(0),
                    error: None,
                },
                Err(e) => NodeStatus {
                    connected: false,
                    error: Some(format!("Failed to parse /get_info: {e}")),
                    ..Default::default()
                },
            },
            Err(e) => NodeStatus {
                connected: false,
                error: Some(format!("HTTP error: {e}")),
                ..Default::default()
            },
        }
    }

    /// Get the current blockchain height.
    pub async fn get_height(&self) -> Result<u64> {
        let guard = self.inner.read().await;
        let inner = guard
            .as_ref()
            .ok_or_else(|| color_eyre::eyre::eyre!("Not connected"))?;
        let count = inner
            .client
            .clone()
            .daemon()
            .get_block_count()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("get_block_count failed: {}", e))?;
        Ok(count.get())
    }

    /// Fetch a full block by height.
    pub async fn get_block_by_height(&self, height: u64) -> Result<Block> {
        let guard = self.inner.read().await;
        let inner = guard
            .as_ref()
            .ok_or_else(|| color_eyre::eyre::eyre!("Not connected"))?;
        let block = inner
            .client
            .clone()
            .daemon()
            .get_block(GetBlockHeaderSelector::Height(height))
            .await
            .map_err(|e| color_eyre::eyre::eyre!("get_block failed at height {}: {}", height, e))?;
        Ok(block)
    }

    /// Fetch a single transaction by hash using the daemon RPC (non-JSON-RPC) endpoint.
    pub async fn get_transaction(&self, tx_hash: monero::Hash) -> Result<Transaction> {
        let guard = self.inner.read().await;
        let inner = guard
            .as_ref()
            .ok_or_else(|| color_eyre::eyre::eyre!("Not connected"))?;

        let response = inner
            .client
            .clone()
            .daemon_rpc()
            .get_transactions(vec![tx_hash], Some(true), Some(false))
            .await
            .map_err(|e| color_eyre::eyre::eyre!("get_transactions failed: {}", e))?;

        // The response contains hex-encoded transaction blobs
        if let Some(txs) = response.txs
            && let Some(tx_entry) = txs.first()
        {
            let bytes = hex::decode(&tx_entry.as_hex)
                .map_err(|e| color_eyre::eyre::eyre!("Hex decode failed: {}", e))?;
            let tx: Transaction = deserialize(&bytes)
                .map_err(|e| color_eyre::eyre::eyre!("TX deserialization failed: {}", e))?;
            return Ok(tx);
        }

        Err(color_eyre::eyre::eyre!("Transaction not found in response"))
    }

    /// Look up a transaction's on-chain status via `/get_transactions`.
    ///
    /// Returns `Ok(Some((block_height, block_timestamp)))` when the daemon
    /// knows the transaction as mined, and `Ok(None)` when it is still in
    /// the pool (or unknown to the daemon — e.g. dropped or never relayed;
    /// callers treat both as "not yet confirmed").
    pub async fn get_tx_confirmation(&self, tx_hash: monero::Hash) -> Result<Option<(u64, u64)>> {
        let guard = self.inner.read().await;
        let inner = guard
            .as_ref()
            .ok_or_else(|| color_eyre::eyre::eyre!("Not connected"))?;

        let response = inner
            .client
            .clone()
            .daemon_rpc()
            .get_transactions(vec![tx_hash], Some(false), Some(true))
            .await
            .map_err(|e| color_eyre::eyre::eyre!("get_transactions failed: {}", e))?;

        if let Some(txs) = response.txs
            && let Some(entry) = txs.first()
        {
            if entry.in_pool {
                return Ok(None);
            }
            if let Some(height) = entry.block_height {
                return Ok(Some((height, entry.block_timestamp.unwrap_or(0))));
            }
        }
        Ok(None)
    }

    /// Check if we have an active connection.
    pub async fn is_connected(&self) -> bool {
        self.inner.read().await.is_some()
    }

    /// Get a reference to the underlying RPC client (for advanced operations).
    pub async fn with_client<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&RpcClient) -> R,
    {
        let guard = self.inner.read().await;
        let inner = guard
            .as_ref()
            .ok_or_else(|| color_eyre::eyre::eyre!("Not connected"))?;
        Ok(f(&inner.client))
    }

    /// Fetch a range of blocks (with their transactions) via `/getblocks.bin`.
    pub async fn get_blocks_bin(&self, start_height: u64) -> Result<bin::GetBlocksResponse> {
        bin::get_blocks(&self.http, &self.url().await, start_height).await
    }

    /// Get the global output indices of a transaction via `/get_o_indexes.bin`.
    pub async fn get_o_indexes(&self, txid: [u8; 32]) -> Result<Vec<u64>> {
        bin::get_o_indexes(&self.http, &self.url().await, txid).await
    }

    /// Query the daemon's recommended fee rate via `/get_fee_estimate`.
    ///
    /// The current network uses daemon-provided, already-tiered rates. Failing
    /// closed is preferable to emitting a distinctive historic fallback fee.
    pub async fn fee_estimate(&self, priority: u32) -> Result<FeeRate> {
        #[derive(serde::Serialize)]
        struct FeeEstimateRequest {
            grace_blocks: u32,
        }

        let response = self
            .http
            .post(format!("{}/get_fee_estimate", self.url().await))
            // Matches wallet2's FEE_ESTIMATE_GRACE_BLOCKS.
            .json(&FeeEstimateRequest { grace_blocks: 10 })
            .send()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("get_fee_estimate failed: {e}"))?;
        let parsed = response
            .json::<FeeEstimateResponse>()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("get_fee_estimate: bad response: {e}"))?;
        fee_rate_from_response(priority, parsed)
    }

    /// Publish a signed transaction to the daemon via `/sendrawtransaction`.
    ///
    /// Returns the daemon's status string ("OK" on success).
    pub async fn publish_transaction(
        &self,
        tx_blob: &[u8],
    ) -> std::result::Result<String, PublishError> {
        #[derive(serde::Serialize)]
        struct SendRawRequest {
            tx_as_hex: String,
            do_not_relay: bool,
            do_sanity_checks: bool,
        }
        #[derive(serde::Deserialize)]
        struct SendRawResponse {
            status: Option<String>,
            reason: Option<String>,
            #[serde(default)]
            not_relayed: bool,
            #[serde(default)]
            double_spend: bool,
            #[serde(default)]
            low_mixin: bool,
            #[serde(default)]
            invalid_input: bool,
            #[serde(default)]
            invalid_output: bool,
            #[serde(default)]
            too_big: bool,
            #[serde(default)]
            overspend: bool,
            #[serde(default)]
            fee_too_low: bool,
            #[serde(default)]
            too_few_outputs: bool,
            #[serde(default)]
            sanity_check_failed: bool,
            #[serde(default)]
            tx_extra_too_big: bool,
            #[serde(default)]
            nonzero_unlock_time: bool,
        }

        let response = self
            .http
            .post(format!("{}/sendrawtransaction", self.url().await))
            .json(&SendRawRequest {
                tx_as_hex: hex::encode(tx_blob),
                do_not_relay: false,
                do_sanity_checks: true,
            })
            .send()
            .await
            .map_err(|e| PublishError::Ambiguous(format!("sendrawtransaction failed: {e}")))?;

        let parsed: SendRawResponse = response.json().await.map_err(|e| {
            PublishError::Ambiguous(format!("sendrawtransaction: bad response: {e}"))
        })?;

        let status = parsed
            .status
            .clone()
            .unwrap_or_else(|| "Failed".to_string());
        if status != "OK" || parsed.not_relayed {
            let mut reason = parsed
                .reason
                .unwrap_or_else(|| "unknown reason".to_string());
            if parsed.not_relayed {
                reason.push_str(" (daemon reports transaction was not relayed)");
            }
            if parsed.double_spend {
                // This may mean an earlier submission of these exact bytes is
                // already present, so it deliberately remains ambiguous.
                reason.push_str(" (key image already spent)");
            }
            if parsed.sanity_check_failed {
                reason.push_str(" (transaction sanity check failed)");
            }
            let invalid_transaction = parsed.low_mixin
                || parsed.invalid_input
                || parsed.invalid_output
                || parsed.too_big
                || parsed.overspend
                || parsed.fee_too_low
                || parsed.too_few_outputs
                || parsed.sanity_check_failed
                || parsed.tx_extra_too_big
                || parsed.nonzero_unlock_time;
            // A generic failure, duplicate, or double-spend response can be
            // the result of an earlier successful relay. Only the daemon's
            // explicit structural-invalid flags authorize rebuilding.
            let message = format!("{status}: {reason}");
            return Err(if invalid_transaction {
                PublishError::Rejected(message)
            } else {
                PublishError::Ambiguous(message)
            });
        }
        Ok(status)
    }

    /// Ensure the cached absolute cumulative RingCT distribution covers
    /// `to_height`, fetching (or extending) it from the daemon as needed.
    async fn ensure_rct_distribution(
        &self,
        to_height: usize,
    ) -> Result<Arc<CachedDistribution>, String> {
        let mut guard = self.rct_distribution_cache.lock().await;

        let covers = guard
            .as_ref()
            .is_some_and(|c| c.end() as usize >= to_height);
        if !covers {
            let from = guard.as_ref().map_or(0, |c| c.end() + 1);
            let dist =
                bin::get_output_distribution(&self.http, &self.url().await, from, to_height as u64)
                    .await
                    .map_err(|e| format!("failed to fetch output distribution: {e}"))?;

            match guard.take() {
                None => {
                    *guard = Some(Arc::new(CachedDistribution {
                        start: dist.start_height,
                        values: dist.values,
                    }));
                }
                Some(old) => {
                    let mut combined = old.values.clone();
                    // Daemon returns absolute cumulative counts even for
                    // non-zero starts, but its start height may differ from
                    // `from` if blocks had no new outputs; fill any gap with
                    // the previous cumulative total.
                    let gap = dist.start_height.saturating_sub(old.end() + 1);
                    let filler = old.values.last().copied().unwrap_or(0);
                    combined.extend(std::iter::repeat_n(filler, gap as usize));
                    combined.extend(dist.values.iter().copied());
                    *guard = Some(Arc::new(CachedDistribution {
                        start: old.start,
                        values: combined,
                    }));
                }
            }
        }

        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| "distribution cache unexpectedly empty".to_string())
    }
}

// ── monero-wallet interface implementations ────────────────────────────────────

impl ProvidesBlockchainMeta for DaemonClient {
    async fn latest_block_number(&self) -> Result<usize, InterfaceError> {
        let count = self
            .get_height()
            .await
            .map_err(|e| InterfaceError::InterfaceError(format!("get_block_count failed: {e}")))?;
        // `get_block_count` is the amount of blocks; the latest block number
        // is one less.
        usize::try_from(count.saturating_sub(1))
            .map_err(|_| InterfaceError::InternalError("block number exceeds usize".to_string()))
    }
}

// Data provider only: decoy SELECTION is monero-wallet's job (see
// wallet/send.rs). This impl merely supplies the raw RingCT output
// distribution and `get_outs` key/unlock data the selection algorithm needs.
impl ProvidesUnvalidatedDecoys for DaemonClient {
    async fn ringct_output_distribution(
        &self,
        range: impl Send + core::ops::RangeBounds<usize>,
    ) -> Result<Vec<u64>, InterfaceError> {
        use core::ops::Bound;

        let start = match range.start_bound() {
            Bound::Included(n) => *n,
            Bound::Excluded(n) => n.saturating_add(1),
            Bound::Unbounded => 0,
        };
        let tip = self.latest_block_number().await?;
        let end = match range.end_bound() {
            Bound::Included(n) => (*n).min(tip),
            Bound::Excluded(n) => n.saturating_sub(1).min(tip),
            Bound::Unbounded => tip,
        };
        if start > end {
            return Ok(vec![]);
        }

        let dist = self
            .ensure_rct_distribution(end)
            .await
            .map_err(InterfaceError::InterfaceError)?;

        // The cache's first entry corresponds to block `dist.start` (the
        // daemon trims leading zero-count blocks; per the trait docs, the
        // result may be smaller than requested in that case).
        let end_idx = (end.saturating_sub(dist.start as usize)).min(dist.values.len() - 1);
        let start_idx = start.saturating_sub(dist.start as usize);
        if start_idx > end_idx {
            return Ok(vec![]);
        }
        Ok(dist.values[start_idx..=end_idx].to_vec())
    }

    async fn unlocked_ringct_outputs(
        &self,
        indexes: &[u64],
        evaluate_unlocked: EvaluateUnlocked,
    ) -> Result<Vec<Option<[Point; 2]>>, TransactionsError> {
        // For the deterministic (fingerprintable) mode we cannot evaluate
        // time-based timelocks locally; conservatively report outputs as
        // locked. The randomized path (used by `OutputWithDecoys::new`) uses
        // `EvaluateUnlocked::Normal` and the daemon's unlocked flag.
        let deterministic = matches!(
            evaluate_unlocked,
            EvaluateUnlocked::FingerprintableDeterministic { .. }
        );

        let entries = bin::get_outs(&self.http, &self.url().await, indexes)
            .await
            .map_err(|e| {
                TransactionsError::InterfaceError(InterfaceError::InterfaceError(format!(
                    "get_outs failed: {e}"
                )))
            })?;
        if entries.len() != indexes.len() {
            return Err(TransactionsError::InterfaceError(
                InterfaceError::InvalidInterface(format!(
                    "get_outs returned {} entries, expected {}",
                    entries.len(),
                    indexes.len()
                )),
            ));
        }

        let mut result = Vec::with_capacity(entries.len());
        for entry in entries {
            let unlocked = entry.unlocked && !deterministic;
            if !unlocked {
                result.push(None);
                continue;
            }
            let key = CompressedPoint::from(entry.key).decompress();
            let commitment = CompressedPoint::from(entry.mask).decompress();
            match (key, commitment) {
                (Some(key), Some(commitment)) => result.push(Some([key, commitment])),
                // Invalid points are unusable as ring members; skip them.
                _ => result.push(None),
            }
        }
        Ok(result)
    }
}

impl ProvidesUnvalidatedFeeRates for DaemonClient {
    async fn fee_rate(&self, priority: FeePriority) -> Result<FeeRate, FeeError> {
        self.fee_estimate(priority.to_u32()).await.map_err(|e| {
            FeeError::InterfaceError(InterfaceError::InterfaceError(format!(
                "fee estimate failed: {e:#}"
            )))
        })
    }
}

impl DaemonClient {
    /// Fetch the block hash at a given height via JSON-RPC
    /// `get_block_header_by_height` (available on restricted nodes).
    pub async fn get_block_hash(&self, height: u64) -> Result<String> {
        let guard = self.inner.read().await;
        let inner = guard
            .as_ref()
            .ok_or_else(|| color_eyre::eyre::eyre!("Not connected"))?;
        let header = inner
            .client
            .clone()
            .daemon()
            .get_block_header(GetBlockHeaderSelector::Height(height))
            .await
            .map_err(|e| color_eyre::eyre::eyre!("get_block_header failed at {height}: {e}"))?;
        Ok(hex::encode(header.hash.as_bytes()))
    }

    /// Fetch block hashes for an inclusive height range via JSON-RPC
    /// `get_block_headers_range` (batched; at most 1000 per call).
    pub async fn get_block_hashes_range(&self, start: u64, end: u64) -> Result<Vec<String>> {
        let guard = self.inner.read().await;
        let inner = guard
            .as_ref()
            .ok_or_else(|| color_eyre::eyre::eyre!("Not connected"))?;
        let (headers, _untrusted) = inner
            .client
            .clone()
            .daemon()
            .get_block_headers_range(start..=end)
            .await
            .map_err(|e| {
                color_eyre::eyre::eyre!("get_block_headers_range {start}..={end} failed: {e}")
            })?;
        Ok(headers
            .iter()
            .map(|h| hex::encode(h.hash.as_bytes()))
            .collect())
    }

    /// Check the spent status of key images via `/is_key_image_spent`.
    ///
    /// Returns one status per key image: 0 = unspent, 1 = spent on-chain,
    /// 2 = spent in the transaction pool.
    pub async fn is_key_images_spent(&self, key_images: &[String]) -> Result<Vec<u8>> {
        #[derive(serde::Serialize)]
        struct Request<'a> {
            key_images: &'a [String],
        }
        #[derive(serde::Deserialize)]
        struct Response {
            spent_status: Option<Vec<u8>>,
        }

        let response = self
            .http
            .post(format!("{}/is_key_image_spent", self.url().await))
            .json(&Request { key_images })
            .send()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("is_key_image_spent failed: {e}"))?;

        let parsed: Response = response
            .json()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("is_key_image_spent: bad response: {e}"))?;

        let statuses = parsed
            .spent_status
            .ok_or_else(|| color_eyre::eyre::eyre!("is_key_image_spent: missing spent_status"))?;
        if statuses.len() != key_images.len() {
            return Err(color_eyre::eyre::eyre!(
                "is_key_image_spent: got {} statuses for {} key images",
                statuses.len(),
                key_images.len()
            ));
        }
        Ok(statuses)
    }
}

#[cfg(test)]
mod fee_tests {
    use super::*;

    #[test]
    fn selects_daemon_priority_rate_without_multiplying_it_again() {
        let response = FeeEstimateResponse {
            fee: Some(99),
            fees: Some(vec![20, 100, 500, 20_000]),
            quantization_mask: Some(10_000),
        };
        let rate = fee_rate_from_response(3, response).unwrap();
        assert_eq!(rate.per_weight(), 500);
        assert_eq!(rate.calculate_fee_from_weight(21), 20_000);
    }

    #[test]
    fn malformed_or_incomplete_fee_estimates_fail_closed() {
        let response = || FeeEstimateResponse {
            fee: Some(20),
            fees: Some(vec![20, 100, 500, 20_000]),
            quantization_mask: Some(10_000),
        };
        assert!(fee_rate_from_response(0, response()).is_err());
        assert!(fee_rate_from_response(5, response()).is_err());
        assert!(
            fee_rate_from_response(
                1,
                FeeEstimateResponse {
                    fee: Some(20),
                    fees: None,
                    quantization_mask: Some(10_000),
                },
            )
            .is_err()
        );
        assert!(
            fee_rate_from_response(
                1,
                FeeEstimateResponse {
                    fee: Some(20),
                    fees: Some(vec![20]),
                    quantization_mask: None,
                },
            )
            .is_err()
        );
    }
}
