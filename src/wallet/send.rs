//! Transaction construction, signing, and publication built on
//! `monero-wallet`'s `SignableTransaction` machinery.

use color_eyre::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use monero_wallet::address::{MoneroAddress, Network as WalletNetwork};
use monero_wallet::ed25519::{Point, Scalar};
use monero_wallet::interface::{FeePriority, FeeRate, ProvidesFeeRates};
use monero_wallet::ringct::RctType;
use monero_wallet::send::{Change, SignableTransaction};
use monero_wallet::{OutputWithDecoys, WalletOutput};

use crate::event::AppEvent;
use crate::rpc::DaemonClient;
use crate::wallet::balance::{TransferDirection, TransferRecord};
use crate::wallet::db::WalletDb;
use crate::wallet::state::StoredOutput;

/// Ring size for newly created transactions (consensus-enforced since v15).
const RING_LEN: u8 = 16;

/// Events emitted by the send engine.
#[derive(Debug, Clone)]
pub enum SendEvent {
    /// A human-readable stage update (e.g. "Selecting inputs").
    Stage(String),
    /// The transaction is fully built and awaits user confirmation.
    AwaitingConfirmation {
        address: String,
        amount: u64,
        fee: u64,
        inputs: usize,
    },
    /// The transaction was published to the daemon. A warning means local
    /// bookkeeping could not be durably persisted and must not be mistaken
    /// for a failed broadcast.
    Published {
        tx_hash: String,
        fee: u64,
        warning: Option<String>,
    },
    /// Sending failed.
    Failed(String),
}

/// Fee priority for a transfer, mirroring the monero-wallet-cli tiers.
///
/// The daemon reports only the base (lowest-tier) fee rate; each tier
/// scales it by the multiplier table used by wallet2 for the current
/// (HF8+, per-byte) fee algorithm: 1x / 5x / 25x / 1000x.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SendPriority {
    /// Cheapest; may wait longer for inclusion (multiplier 1x).
    Low,
    /// The wallet default (multiplier 5x).
    #[default]
    Normal,
    /// Faster inclusion (multiplier 25x).
    Elevated,
    /// Urgent; very expensive (multiplier 1000x).
    Priority,
}

impl SendPriority {
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Normal => "Normal",
            Self::Elevated => "Elevated",
            Self::Priority => "Priority",
        }
    }

    /// Cycle to the next tier (Low -> Normal -> Elevated -> Priority -> Low).
    pub fn next(self) -> Self {
        match self {
            Self::Low => Self::Normal,
            Self::Normal => Self::Elevated,
            Self::Elevated => Self::Priority,
            Self::Priority => Self::Low,
        }
    }

    /// The wallet2 HF8+ multiplier applied to the daemon's base fee.
    pub fn multiplier(self) -> u64 {
        crate::rpc::fee_multiplier(self.to_fee_priority().to_u32())
    }

    pub fn to_fee_priority(self) -> FeePriority {
        match self {
            Self::Low => FeePriority::Unimportant,
            Self::Normal => FeePriority::Normal,
            Self::Elevated => FeePriority::Elevated,
            Self::Priority => FeePriority::Priority,
        }
    }
}

/// A request to send funds.
#[derive(Debug, Clone)]
pub struct SendRequest {
    pub address: String,
    pub amount: u64,
    /// Sweep-all: send the entire unlocked balance minus the fee. `amount`
    /// is ignored; the exact payment is computed during construction.
    pub sweep_all: bool,
    /// Fee priority tier.
    pub priority: FeePriority,
}

/// Compute the payment of a sweep transaction: everything minus the fee.
fn sweep_payment(total: u64, fee: u64) -> Result<u64> {
    total
        .checked_sub(fee)
        .filter(|amount| *amount > 0)
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "unlocked balance {} is too small to cover the network fee ({})",
                crate::wallet::format_xmr(total),
                crate::wallet::format_xmr(fee)
            )
        })
}

/// Convert the wallet's spend secret key into a `monero-wallet` scalar.
pub fn spend_scalar(spend_secret: &monero::util::key::PrivateKey) -> Result<Scalar> {
    let bytes: [u8; 32] = spend_secret
        .as_bytes()
        .try_into()
        .map_err(|_| color_eyre::eyre::eyre!("spend secret key must be 32 bytes"))?;
    Scalar::read(&mut bytes.as_slice())
        .map_err(|e| color_eyre::eyre::eyre!("invalid spend secret key: {e}"))
}

/// Compute the key image of an output under the given spend secret key.
///
/// Matches `SignableTransaction::sign`'s internal derivation:
/// `I = (x + key_offset) * Hp(P)` where `x` is the spend secret.
pub fn key_image(spend: &Scalar, output: &WalletOutput) -> [u8; 32] {
    let spend_dalek: curve25519_dalek::Scalar = (*spend).into();
    let offset_dalek: curve25519_dalek::Scalar = output.key_offset().into();
    let input_key = Zeroizing::new(spend_dalek + offset_dalek);
    let hp: curve25519_dalek::EdwardsPoint =
        Point::biased_hash(output.key().compress().to_bytes()).into();
    (*input_key * hp).compress().to_bytes()
}

/// Compute the key image (hex) for a persisted output.
pub fn key_image_for_stored(output: &StoredOutput, spend: &Scalar) -> Option<String> {
    let bytes = hex::decode(&output.wallet_output_hex).ok()?;
    let wallet_output = WalletOutput::read(&mut bytes.as_slice()).ok()?;
    Some(hex::encode(key_image(spend, &wallet_output)))
}

/// Deserialize a persisted output.
pub fn stored_to_wallet_output(output: &StoredOutput) -> Result<WalletOutput> {
    let bytes = hex::decode(&output.wallet_output_hex)
        .map_err(|e| color_eyre::eyre::eyre!("corrupt stored output (bad hex): {e}"))?;
    WalletOutput::read(&mut bytes.as_slice())
        .map_err(|e| color_eyre::eyre::eyre!("corrupt stored output: {e}"))
}

/// Map a `monero` crate network to the address crate's network.
pub fn wallet_network(network: monero::Network) -> WalletNetwork {
    match network {
        monero::Network::Mainnet => WalletNetwork::Mainnet,
        monero::Network::Stagenet => WalletNetwork::Stagenet,
        monero::Network::Testnet => WalletNetwork::Testnet,
    }
}

/// Whether an output is unlocked at the given chain tip block number.
pub fn is_unlocked(output: &WalletOutput, stored: &StoredOutput, tip: u64) -> bool {
    unlock_height(output, stored.height) <= tip
}

/// First chain-tip height at which the output becomes spendable.
///
/// Combines the standard 10-block spend lock with any additional timelock
/// (miner outputs: 60 blocks).
pub fn unlock_height(output: &WalletOutput, creation_height: u64) -> u64 {
    use monero_wallet::transaction::Timelock;
    let standard = creation_height.saturating_add(10);
    match output.additional_timelock() {
        Timelock::None => standard,
        Timelock::Block(h) => standard.max(h as u64),
        // Time-based additional locks are essentially unused; approximate.
        Timelock::Time(_) => standard,
    }
}

/// Run the full send flow: select inputs, build, confirm, sign, publish.
///
/// Emits `SendEvent`s over `event_tx` wrapped in `AppEvent::Send`.
pub async fn execute_send(
    daemon: DaemonClient,
    keys: crate::wallet::WalletKeys,
    db: Arc<WalletDb>,
    req: SendRequest,
    confirm_rx: oneshot::Receiver<bool>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    cancel: Arc<AtomicBool>,
) {
    if cancel.load(Ordering::Relaxed) {
        let _ = event_tx.send(AppEvent::Send(SendEvent::Failed(
            "wallet was locked; send cancelled".to_string(),
        )));
        return;
    }
    let result = send_inner(&daemon, &keys, &db, &req, confirm_rx, &event_tx).await;
    if let Err(e) = result {
        let _ = event_tx.send(AppEvent::Send(SendEvent::Failed(format!("{e:#}"))));
    }
}

fn stage(event_tx: &mpsc::UnboundedSender<AppEvent>, msg: impl Into<String>) {
    let _ = event_tx.send(AppEvent::Send(SendEvent::Stage(msg.into())));
}

/// Assemble a `SignableTransaction` paying `amount` to `recipient`.
///
/// Change returns to the primary address. The outgoing view key is generated
/// independently for each construction attempt; reusing a wallet-wide value
/// leaks a stable secret into every transaction construction.
fn build_signable(
    keys: &crate::wallet::WalletKeys,
    inputs: Vec<OutputWithDecoys>,
    recipient: MoneroAddress,
    amount: u64,
    fee_rate: FeeRate,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<SignableTransaction> {
    let view_pair = crate::wallet::scanner::build_view_pair(keys)?;
    let change = Change::new(view_pair, None);

    let mut ovk = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(ovk.as_mut());

    SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        ovk,
        inputs,
        vec![(recipient, amount)],
        change,
        vec![],
        fee_rate,
    )
    .map_err(|e| color_eyre::eyre::eyre!("failed to build transaction: {e}"))
}

async fn send_inner(
    daemon: &DaemonClient,
    keys: &crate::wallet::WalletKeys,
    db: &WalletDb,
    req: &SendRequest,
    confirm_rx: oneshot::Receiver<bool>,
    event_tx: &mpsc::UnboundedSender<AppEvent>,
) -> Result<()> {
    stage(event_tx, "Validating recipient address");
    let network = wallet_network(keys.network);
    let recipient = MoneroAddress::from_str(network, &req.address)
        .map_err(|e| color_eyre::eyre::eyre!("invalid recipient address: {e}"))?;

    stage(event_tx, "Loading wallet state");
    let stored_list = db.spendable_outputs()?;
    if stored_list.is_empty() && db.scan_height()? == 0 {
        return Err(color_eyre::eyre::eyre!(
            "no scan state found; let the wallet finish syncing"
        ));
    }

    stage(event_tx, "Querying chain state and fee rate");
    use monero_wallet::interface::ProvidesBlockchainMeta;
    let tip = daemon
        .latest_block_number()
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to get chain tip: {e}"))?;
    let tip_u64 = tip as u64;

    // Sanity-cap the daemon's fee estimate: monero-interface validates the
    // post-multiplier rate against this cap and fails with `InvalidFee` when
    // it is exceeded. The ceiling on the daemon-reported *base* fee is a
    // fixed constant — 5x the static fallback of 20_000 atomic units per
    // weight — so a manipulated daemon cannot inflate fees beyond that no
    // matter which tier is selected. The cap itself scales with the priority
    // multiplier only because the interface validates the post-multiplier
    // rate; the base ceiling does not loosen with the daemon's estimate.
    const MAX_BASE_FEE_PER_WEIGHT: u64 = 100_000;
    let fee_cap =
        MAX_BASE_FEE_PER_WEIGHT.saturating_mul(crate::rpc::fee_multiplier(req.priority.to_u32()));
    let fee_rate = daemon
        .fee_rate(req.priority, fee_cap)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to get fee rate: {e}"))?;

    // Gather unlocked, unspent outputs.
    let mut spendable: Vec<(StoredOutput, WalletOutput)> = Vec::new();
    for stored in &stored_list {
        if stored.spent {
            continue;
        }
        // A corrupt stored output must not brick the wallet's ability to
        // send; skip it (its funds remain recorded in the database).
        let Ok(output) = stored_to_wallet_output(stored) else {
            tracing::warn!("skipping corrupt stored output {}", stored.key_hex);
            continue;
        };
        if is_unlocked(&output, stored, tip_u64) {
            spendable.push((stored.clone(), output));
        }
    }
    if spendable.is_empty() {
        return Err(color_eyre::eyre::eyre!("no unlocked outputs available"));
    }

    let estimate_weight = |inputs: usize| -> u64 {
        // Bulletproof+-era weights: ~1569 for 1-in/2-out, ~2443 for 2-in
        // (≈875 per extra input). Slightly overestimated to stay safe.
        (inputs as u64) * 900 + 800
    };
    let fee_for = |inputs: usize| -> u64 {
        fee_rate
            .calculate_fee_from_weight(estimate_weight(inputs))
            .try_into()
            .unwrap_or(u64::MAX)
    };

    // Select inputs. A sweep consumes every unlocked output and derives the
    // payment as `total - fee`; a regular send picks the largest outputs
    // until amount + estimated fee is covered.
    stage(event_tx, "Selecting inputs");
    spendable.sort_by(|a, b| b.1.commitment().amount.cmp(&a.1.commitment().amount));

    let mut selected: Vec<(StoredOutput, WalletOutput)>;
    let mut amount = req.amount;
    let mut fee_estimate;
    if req.sweep_all {
        selected = spendable;
        fee_estimate = fee_for(selected.len());
        amount = sweep_payment(
            selected.iter().map(|(_, o)| o.commitment().amount).sum(),
            fee_estimate,
        )?;
    } else {
        selected = Vec::new();
        let mut selected_sum = 0u64;
        fee_estimate = 0u64;
        for candidate in spendable {
            selected.push(candidate);
            selected_sum = selected
                .iter()
                .map(|(_, o)| o.commitment().amount)
                .sum::<u64>();
            fee_estimate = fee_for(selected.len());
            if selected_sum >= req.amount.saturating_add(fee_estimate) {
                break;
            }
        }
        if selected_sum < req.amount.saturating_add(fee_estimate) {
            return Err(color_eyre::eyre::eyre!(
                "insufficient unlocked balance: have {} + fee, need {}",
                crate::wallet::format_xmr(selected_sum),
                crate::wallet::format_xmr(req.amount)
            ));
        }
    }

    // Select decoys for every input.
    //
    // IMPORTANT: muff implements NO decoy-selection algorithm of its own.
    // Selection is delegated entirely to the `monero-wallet` crate:
    // `OutputWithDecoys::new` (monero-wallet/src/decoys.rs) reproduces the
    // official wallet2 algorithm — a Gamma(19.28, 1/1.61) output-age
    // distribution sampled against the daemon's RingCT output distribution
    // (cf. monero-project/monero src/wallet/wallet2.cpp `get_outs`, around
    // L142-L143). The daemon client only supplies the raw distribution and
    // decoy key data through monero-wallet's `ProvidesDecoys` interface.
    stage(
        event_tx,
        format!("Selecting decoys ({} inputs)", selected.len()),
    );
    let mut rng = rand::rngs::OsRng;
    let mut inputs = Vec::with_capacity(selected.len());
    for (i, (_, output)) in selected.iter().enumerate() {
        stage(
            event_tx,
            format!("Selecting decoys ({}/{})", i + 1, selected.len()),
        );
        let with_decoys = OutputWithDecoys::new(&mut rng, daemon, RING_LEN, tip, output.clone())
            .await
            .map_err(|e| color_eyre::eyre::eyre!("decoy selection failed: {e}"))?;
        inputs.push(with_decoys);
    }

    // Build the signable transaction. For a sweep the exact fee is only
    // known once the transaction exists, and the payment is `total - fee`,
    // so build twice if needed: the fee from the first build fixes the
    // payment of the (weight-identical) second.
    stage(event_tx, "Constructing transaction");
    let input_count = inputs.len();
    let mut signable = build_signable(keys, inputs.clone(), recipient, amount, fee_rate, &mut rng)?;
    let mut fee = signable.necessary_fee();
    if req.sweep_all {
        let total: u64 = selected.iter().map(|(_, o)| o.commitment().amount).sum();
        for _ in 0..3 {
            if fee == fee_estimate {
                break;
            }
            fee_estimate = fee;
            amount = sweep_payment(total, fee)?;
            signable = build_signable(keys, inputs.clone(), recipient, amount, fee_rate, &mut rng)?;
            let refined = signable.necessary_fee();
            if refined == fee {
                break;
            }
            fee = refined;
        }
    }

    // Ask the user to confirm.
    let _ = event_tx.send(AppEvent::Send(SendEvent::AwaitingConfirmation {
        address: req.address.clone(),
        amount,
        fee,
        inputs: input_count,
    }));

    let confirmed = tokio::time::timeout(std::time::Duration::from_secs(180), confirm_rx)
        .await
        .map_err(|_| color_eyre::eyre::eyre!("confirmation timed out"))?
        .unwrap_or(false);
    if !confirmed {
        return Err(color_eyre::eyre::eyre!("transaction cancelled by user"));
    }

    // Sign.
    stage(event_tx, "Signing transaction");
    let spend = Zeroizing::new(spend_scalar(&keys.keypair.spend)?);
    let signed = signable
        .sign(&mut rng, &spend)
        .map_err(|e| color_eyre::eyre::eyre!("signing failed: {e}"))?;
    let tx_hash = hex::encode(signed.hash());

    // Publish.
    stage(event_tx, "Publishing transaction");
    let publish_result = daemon.publish_transaction(&signed.serialize()).await;
    if let Err(e) = publish_result {
        // The publish may have succeeded daemon-side while the response was
        // lost (or the same tx was already relayed). Resolve the ambiguity
        // before giving up: if every input's key image is now spent (in the
        // pool or on-chain), the transaction IS out there — proceed with the
        // normal bookkeeping instead of reporting a failure and leaving the
        // inputs spendable for a conflicting retry.
        stage(event_tx, "Verifying transaction status");
        let input_key_images: Vec<String> = selected
            .iter()
            .map(|(_, o)| hex::encode(key_image(&spend, o)))
            .collect();
        let statuses = daemon.is_key_images_spent(&input_key_images).await;
        match statuses {
            Ok(statuses) if statuses.iter().all(|s| *s != 0) => {
                tracing::warn!(
                    "publish returned an error ({e:#}) but the transaction's key images \
                     are spent — treating {tx_hash} as published"
                );
            }
            _ => {
                return Err(e);
            }
        }
    }

    // Mark spent inputs and record the outgoing transfer. The database is
    // shared with the scanner (single in-memory connection behind a mutex),
    // so these marks are serialized with the scanner's own mutations.
    let note = format!(
        "To {}…{}",
        &req.address[..8.min(req.address.len())],
        &req.address[req.address.len().saturating_sub(6)..]
    );
    let record = TransferRecord {
        tx_hash: tx_hash.clone(),
        height: 0,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        amount,
        fee,
        direction: TransferDirection::Out,
        confirmed: false,
        failed: false,
        note,
    };
    let input_keys: Vec<String> = selected
        .iter()
        .map(|(stored, _)| stored.key_hex.clone())
        .collect();
    let warning = match db.record_published_transfer(&input_keys, &record) {
        Err(e) => {
            tracing::error!("published transaction bookkeeping failed: {e:#}");
            Some(format!(
                "Transaction {tx_hash} was published, but wallet bookkeeping failed. Do not retry this payment; rescan the wallet before spending again."
            ))
        }
        Ok(()) => match db.save() {
            Ok(()) => None,
            Err(e) => {
                tracing::error!("failed to persist state after published transaction: {e:#}");
                Some(format!(
                    "Transaction {tx_hash} was published, but its wallet state was not saved. Do not retry this payment; keep the wallet open and rescan before spending again."
                ))
            }
        },
    };

    let _ = event_tx.send(AppEvent::Send(SendEvent::Published {
        tx_hash,
        fee,
        warning,
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sweep_payment_subtracts_fee() {
        // The reported bug: sending the full balance must subtract the fee
        // instead of failing with "insufficient unlocked balance".
        assert_eq!(
            sweep_payment(29_969_380_000, 28_600_000).unwrap(),
            29_940_780_000
        );
    }

    #[test]
    fn test_sweep_payment_rejects_fee_dust_balance() {
        // Balance exactly equal to (or below) the fee cannot be swept.
        assert!(sweep_payment(28_600_000, 28_600_000).is_err());
        assert!(sweep_payment(1, 28_600_000).is_err());
        let msg = sweep_payment(10, 28_600_000).unwrap_err().to_string();
        assert!(msg.contains("too small to cover the network fee"), "{msg}");
    }
}
