//! Shared state types for the wallet database.
//!
//! Rows of the `outputs` table are mapped to/from [`StoredOutput`]; the
//! encrypted single-file store lives in `super::db`.

use serde::{Deserialize, Serialize};

/// A received output tracked by the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOutput {
    /// Hex-encoded `monero_wallet::WalletOutput` serialization.
    pub wallet_output_hex: String,
    /// The output's one-time public key (hex), used for dedup and
    /// key-image (spentness) checks.
    pub key_hex: String,
    /// Amount in atomic units.
    pub amount: u64,
    /// Block height where this output was created.
    pub height: u64,
    /// Timestamp of the block that created it.
    pub timestamp: u64,
    /// Whether this output has been spent.
    pub spent: bool,
    /// If this output was optimistically marked spent by one of OUR
    /// unpublished/unconfirmed transactions, the hash of that transaction.
    /// Used to recover (un-mark) when the tx is dropped from the pool.
    #[serde(default)]
    pub spent_tx: Option<String>,
}
