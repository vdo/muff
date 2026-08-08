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

use crate::config::Config;

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

/// Default fee quantization mask used by the Monero core wallet when the
/// daemon doesn't provide a mask for a priority level.
const DEFAULT_FEE_MASK: u64 = 10_000;

/// Fee multiplier for a priority tier (monero-wallet-cli's table for the
/// current fee algorithm, HF8+/per-byte: `{1, 5, 25, 1000}` indexed by
/// `priority - 1`; `wallet2::get_fee_multiplier`). The daemon's
/// `estimated_base_fee` is the tier-1 (unimportant) rate.
pub fn fee_multiplier(priority: u32) -> u64 {
    match priority {
        1 => 1,    // Unimportant / Low
        2 => 5,    // Normal
        3 => 25,   // Elevated
        _ => 1000, // Priority (and any out-of-range custom value)
    }
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
        let mut builder = RpcClientBuilder::new();
        if let Some(ref proxy) = self.proxy {
            builder = builder.proxy_address(proxy);
        }
        let client = builder
            .build(&self.url().await)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to build RPC client: {}", e))?;

        // Test connection by calling get_block_count
        let _count = client
            .clone()
            .daemon()
            .get_block_count()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("RPC connection test failed: {}", e))?;

        let mut guard = self.inner.write().await;
        *guard = Some(DaemonInner { client });
        Ok(())
    }

    /// Get the current node status by querying the /get_info endpoint directly.
    pub async fn get_status(&self) -> NodeStatus {
        let url = format!("{}/get_info", self.url().await);
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
    /// Falls back to a conservative static rate when the daemon doesn't
    /// return one.
    pub async fn fee_estimate(&self, priority: u32) -> FeeRate {
        #[derive(serde::Deserialize)]
        struct FeeEstimateResponse {
            estimated_base_fee: Option<u64>,
            fee_mask: Option<u64>,
        }

        #[derive(serde::Serialize)]
        struct FeeEstimateRequest {
            grace_blocks: u32,
        }

        // The daemon only reports the base (lowest-tier) fee; the priority
        // scales it exactly like wallet2's HF8+ multiplier table.
        let multiplier = fee_multiplier(priority);

        let request = self
            .http
            .post(format!("{}/get_fee_estimate", self.url().await))
            .json(&FeeEstimateRequest { grace_blocks: 0 });

        if let Ok(resp) = request.send().await
            && let Ok(parsed) = resp.json::<FeeEstimateResponse>().await
            && let Some(per_weight) = parsed.estimated_base_fee
        {
            let mask = parsed.fee_mask.unwrap_or(DEFAULT_FEE_MASK);
            if let Some(rate) = FeeRate::new(per_weight.saturating_mul(multiplier), mask) {
                return rate;
            }
        }

        // Fallback: 20_000 atomic units per weight unit (monerod's historic
        // default base fee), scaled by the priority multiplier.
        FeeRate::new(20_000u64.saturating_mul(multiplier), DEFAULT_FEE_MASK)
            .expect("static fee rate is valid")
    }

    /// Publish a signed transaction to the daemon via `/sendrawtransaction`.
    ///
    /// Returns the daemon's status string ("OK" on success).
    pub async fn publish_transaction(&self, tx_blob: &[u8]) -> Result<String> {
        #[derive(serde::Serialize)]
        struct SendRawRequest {
            tx_as_hex: String,
            do_not_relay: bool,
        }
        #[derive(serde::Deserialize)]
        struct SendRawResponse {
            status: Option<String>,
            reason: Option<String>,
        }

        let response = self
            .http
            .post(format!("{}/sendrawtransaction", self.url().await))
            .json(&SendRawRequest {
                tx_as_hex: hex::encode(tx_blob),
                do_not_relay: false,
            })
            .send()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("sendrawtransaction failed: {e}"))?;

        let parsed: SendRawResponse = response
            .json()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("sendrawtransaction: bad response: {e}"))?;

        let status = parsed
            .status
            .clone()
            .unwrap_or_else(|| "Failed".to_string());
        if status != "OK" {
            let reason = parsed
                .reason
                .unwrap_or_else(|| "unknown reason".to_string());
            return Err(color_eyre::eyre::eyre!(
                "daemon rejected transaction ({status}): {reason}"
            ));
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
        Ok(self.fee_estimate(priority.to_u32()).await)
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
