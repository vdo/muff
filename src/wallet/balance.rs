use serde::{Deserialize, Serialize};

/// Represents a transfer (incoming or outgoing) in the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRecord {
    pub tx_hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub amount: u64,
    pub fee: u64,
    pub direction: TransferDirection,
    pub confirmed: bool,
    /// The transaction was published but dropped from the tx pool without
    /// being mined (its inputs are unspent again). Funds were NOT lost.
    #[serde(default)]
    pub failed: bool,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferDirection {
    In,
    Out,
}

impl std::fmt::Display for TransferDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferDirection::In => write!(f, "IN"),
            TransferDirection::Out => write!(f, "OUT"),
        }
    }
}

/// Wallet balance information.
#[derive(Debug, Clone, Default)]
pub struct BalanceInfo {
    /// Total balance (all outputs)
    pub total: u64,
    /// Unlocked balance (spendable)
    pub unlocked: u64,
    /// Locked balance (not yet spendable)
    pub locked: u64,
}

/// A tracked output owned by this wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedOutput {
    /// Transaction hash containing this output.
    pub tx_hash: String,
    /// Output index within the transaction.
    pub output_index: usize,
    /// The output's one-time public key (hex); used for spentness matching.
    pub key_hex: String,
    /// Block height where this output was found.
    pub height: u64,
    /// Amount in atomic units.
    pub amount: u64,
    /// Whether this output has been spent.
    pub spent: bool,
    /// Subaddress index that received this output.
    pub subaddress_major: u32,
    pub subaddress_minor: u32,
    /// Timestamp from block header (if available).
    pub timestamp: u64,
    /// First chain-tip height at which this output is spendable
    /// (10-block standard lock, 60 blocks for miner outputs).
    pub unlock_height: u64,
}

impl OwnedOutput {
    /// Unique key for deduplication: (tx_hash, output_index).
    pub fn unique_key(&self) -> (&str, usize) {
        (&self.tx_hash, self.output_index)
    }
}
