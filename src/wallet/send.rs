//! Transaction construction, signing, and publication built on
//! `monero-wallet`'s `SignableTransaction` machinery.

use color_eyre::Result;
use rand::Rng;
use std::collections::HashSet;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use monero_wallet::address::{MoneroAddress, Network as WalletNetwork};
use monero_wallet::ed25519::{Point, Scalar};
use monero_wallet::interface::{FeePriority, FeeRate, ProvidesDecoys, ProvidesFeeRates};
use monero_wallet::ringct::RctType;
use monero_wallet::send::{Change, SignableTransaction};
use monero_wallet::{OutputWithDecoys, WalletOutput};

use crate::event::AppEvent;
use crate::rpc::{DaemonClient, PublishError};
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
    /// Relay returned an ambiguous result. The exact signed blob is durably
    /// stored and will be retried; constructing a replacement would expose
    /// the true input through ring intersection.
    StoredForRetry { tx_hash: String, fee: u64 },
    /// Sending failed.
    Failed(String),
}

/// Fee priority for a transfer, mirroring the monero-wallet-cli tiers. Current
/// monerod returns a complete array of already-adjusted priority rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SendPriority {
    /// Cheapest; may wait longer for inclusion.
    Low,
    /// The wallet default.
    #[default]
    Normal,
    /// Faster inclusion.
    Elevated,
    /// Urgent; very expensive.
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

    pub fn to_fee_priority(self) -> FeePriority {
        match self {
            Self::Low => FeePriority::Unimportant,
            Self::Normal => FeePriority::Normal,
            Self::Elevated => FeePriority::Elevated,
            Self::Priority => FeePriority::Priority,
        }
    }
}

/// wallet2's notion of how likely two outputs are to have a common owner,
/// represented as integer ranks so comparisons are exact. Transactions try to
/// avoid combining related outputs and randomly choose between equal options.
fn output_relatedness(a: &(StoredOutput, WalletOutput), b: &(StoredOutput, WalletOutput)) -> u8 {
    if a.1.transaction() == b.1.transaction() {
        10
    } else {
        let distance = a.0.height.abs_diff(b.0.height);
        match distance {
            0 => 9,
            1 => 8,
            2..=9 => 2,
            _ => 0,
        }
    }
}

fn output_subaddress(output: &(StoredOutput, WalletOutput)) -> (u32, u32) {
    output
        .1
        .subaddress()
        .map(|index| (index.account(), index.address()))
        .unwrap_or((0, 0))
}

/// wallet2 first looks for an old-enough single input, then for two inputs
/// from the same subaddress, before falling back to its randomized picker.
/// Preserving the same-subaddress constraint avoids linking two receive
/// identities merely to fund an ordinary payment.
fn preferred_input_indices(available: &[(StoredOutput, WalletOutput)], needed: u64) -> Vec<usize> {
    if let Some(index) = available
        .iter()
        .position(|(_, output)| output.commitment().amount >= needed)
    {
        return vec![index];
    }

    let mut best_relatedness = u8::MAX;
    let mut picks = Vec::new();
    for first in 0..available.len() {
        for second in (first + 1)..available.len() {
            if output_subaddress(&available[first]) != output_subaddress(&available[second])
                || available[first]
                    .1
                    .commitment()
                    .amount
                    .saturating_add(available[second].1.commitment().amount)
                    < needed
            {
                continue;
            }
            let relatedness = output_relatedness(&available[first], &available[second]);
            if relatedness < best_relatedness {
                picks = vec![first, second];
                if relatedness == 0 {
                    return picks;
                }
                best_relatedness = relatedness;
            }
        }
    }
    picks
}

fn take_subaddress_group(
    available: &mut Vec<(StoredOutput, WalletOutput)>,
    subaddress: (u32, u32),
) -> Vec<(StoredOutput, WalletOutput)> {
    let mut group = Vec::new();
    let mut remainder = Vec::new();
    for output in available.drain(..) {
        if output_subaddress(&output) == subaddress {
            group.push(output);
        } else {
            remainder.push(output);
        }
    }
    *available = remainder;
    group
}

/// Take the subaddress group with the largest unlocked balance, matching the
/// ordering wallet2 uses when no one- or two-input preferred set exists.
fn take_largest_subaddress_group(
    available: &mut Vec<(StoredOutput, WalletOutput)>,
) -> Vec<(StoredOutput, WalletOutput)> {
    let mut balances: Vec<((u32, u32), u64)> = Vec::new();
    for output in available.iter() {
        let subaddress = output_subaddress(output);
        if let Some((_, balance)) = balances.iter_mut().find(|(key, _)| *key == subaddress) {
            *balance = balance.saturating_add(output.1.commitment().amount);
        } else {
            balances.push((subaddress, output.1.commitment().amount));
        }
    }
    let subaddress = balances
        .into_iter()
        .max_by_key(|(_, balance)| *balance)
        .map(|(subaddress, _)| subaddress)
        .expect("a subaddress group requires at least one output");
    take_subaddress_group(available, subaddress)
}

/// Remove a randomly chosen candidate with the lowest maximum relatedness to
/// the outputs already selected. This mirrors wallet2's `pop_best_value`
/// policy and avoids muff's previous, fingerprintable largest-first ordering.
fn pop_least_related<R: rand::RngCore>(
    available: &mut Vec<(StoredOutput, WalletOutput)>,
    selected: &[(StoredOutput, WalletOutput)],
    smallest: bool,
    rng: &mut R,
) -> (StoredOutput, WalletOutput) {
    debug_assert!(!available.is_empty());
    let mut best_rank = u8::MAX;
    let mut candidates = Vec::new();
    for (index, output) in available.iter().enumerate() {
        let rank = selected
            .iter()
            .map(|chosen| output_relatedness(output, chosen))
            .max()
            .unwrap_or(0);
        match rank.cmp(&best_rank) {
            std::cmp::Ordering::Less => {
                best_rank = rank;
                candidates.clear();
                candidates.push(index);
            }
            std::cmp::Ordering::Equal => candidates.push(index),
            std::cmp::Ordering::Greater => {}
        }
    }
    let index = if smallest {
        candidates
            .into_iter()
            .min_by_key(|index| available[*index].1.commitment().amount)
            .expect("at least one least-related candidate")
    } else {
        candidates[rng.gen_range(0..candidates.len())]
    };
    available.swap_remove(index)
}

/// Reference `tx_sanity_check` policy applied to the complete transaction's
/// ring-member set. It rejects suspiciously duplicated or implausibly old
/// decoy sets before any signatures or network requests are produced.
fn rings_are_sane(inputs: &[OutputWithDecoys], rct_outputs_available: u64) -> bool {
    let positions: Vec<Vec<u64>> = inputs
        .iter()
        .map(|input| input.decoys().positions().to_vec())
        .collect();
    ring_positions_are_sane(&positions, rct_outputs_available)
}

/// Pure form of monerod's `tx_sanity_check`, kept separate so its integer
/// thresholds and even-length median behavior can be regression-tested.
fn ring_positions_are_sane(rings: &[Vec<u64>], rct_outputs_available: u64) -> bool {
    let total: usize = rings.iter().map(Vec::len).sum();
    if total <= 10 || rct_outputs_available < 10_000 {
        return true;
    }
    let mut unique = HashSet::with_capacity(total);
    for ring in rings {
        unique.extend(ring);
    }
    if unique.len() < total.saturating_mul(8) / 10 {
        return false;
    }
    let mut positions: Vec<u64> = unique.into_iter().collect();
    positions.sort_unstable();
    let middle = positions.len() / 2;
    let median = if positions.len().is_multiple_of(2) {
        // Overflow-safe integer average, identical to epee::get_mid.
        let a = positions[middle - 1];
        let b = positions[middle];
        (a / 2) + (b / 2) + ((a % 2) + (b % 2)) / 2
    } else {
        positions[middle]
    };
    u128::from(median) >= u128::from(rct_outputs_available).saturating_mul(6) / 10
}

fn read_saved_ring(blob: &[u8], output: &WalletOutput) -> Option<OutputWithDecoys> {
    let mut cursor = Cursor::new(blob);
    let saved = OutputWithDecoys::read(&mut cursor).ok()?;
    if cursor.position() != blob.len() as u64
        || saved.decoys().len() != usize::from(RING_LEN)
        || saved.key() != output.key()
        || saved.commitment().commit() != output.commitment().commit()
    {
        return None;
    }
    let signer = usize::from(saved.decoys().signer_index());
    (saved.decoys().positions().get(signer).copied() == Some(output.index_on_blockchain()))
        .then_some(saved)
}

async fn select_decoys_with_sanity(
    daemon: &DaemonClient,
    db: &WalletDb,
    selected: &[(StoredOutput, WalletOutput)],
    key_images: &[String],
    tip: usize,
    rng: &mut (impl rand::RngCore + rand::CryptoRng + Send + Sync),
    event_tx: &mpsc::UnboundedSender<AppEvent>,
) -> Result<Vec<OutputWithDecoys>> {
    let distribution = ProvidesDecoys::ringct_output_distribution(daemon, ..=tip)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("output distribution failed: {e}"))?;
    let available = distribution
        .last()
        .copied()
        .ok_or_else(|| color_eyre::eyre::eyre!("empty RingCT output distribution"))?;

    for attempt in 0..3 {
        let mut inputs = Vec::with_capacity(selected.len());
        for (i, ((_, output), key_image)) in selected.iter().zip(key_images).enumerate() {
            stage(
                event_tx,
                format!(
                    "Selecting decoys ({}/{}, attempt {})",
                    i + 1,
                    selected.len(),
                    attempt + 1
                ),
            );
            let saved = match db.ring_for_key_image(key_image) {
                Ok(Some(blob)) => Some(read_saved_ring(&blob, output).ok_or_else(|| {
                    color_eyre::eyre::eyre!(
                        "saved ring for key image {key_image} is corrupt or belongs to another output"
                    )
                })?),
                Ok(None) => None,
                Err(e) => return Err(e.wrap_err("failed to load committed ring")),
            };
            inputs.push(match saved {
                Some(input) => input,
                None => OutputWithDecoys::new(rng, daemon, RING_LEN, tip, output.clone())
                    .await
                    .map_err(|e| color_eyre::eyre::eyre!("decoy selection failed: {e}"))?,
            });
        }
        if rings_are_sane(&inputs, available) {
            return Ok(inputs);
        }
        tracing::warn!(
            "transaction ring sanity check failed on attempt {}",
            attempt + 1
        );
    }
    Err(color_eyre::eyre::eyre!(
        "transaction ring sanity check failed after 3 attempts"
    ))
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
    /// Exact `(account, minor)` subaddress whose outputs may fund this send.
    /// This is intentionally not a preference: silently crossing the source
    /// boundary would defeat the Addresses screen's privacy control.
    pub source: (u32, u32),
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
/// Change returns to minor 0 of the selected source account, matching
/// wallet2's `create_transactions_2` policy. The outgoing view key is
/// generated independently for each construction attempt; reusing a
/// wallet-wide value leaks a stable secret into every construction.
fn build_signable(
    keys: &crate::wallet::WalletKeys,
    inputs: Vec<OutputWithDecoys>,
    recipient: MoneroAddress,
    amount: u64,
    fee_rate: FeeRate,
    source: (u32, u32),
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<SignableTransaction> {
    let view_pair = crate::wallet::scanner::build_view_pair(keys)?;
    // wallet2.cpp: change_dts.addr = get_subaddress({subaddr_account, 0}).
    // Account 0/minor 0 is the legacy primary address represented by `None`.
    let change_subaddress = if source.0 == 0 {
        None
    } else {
        Some(
            monero_wallet::address::SubaddressIndex::new(source.0, 0)
                .ok_or_else(|| color_eyre::eyre::eyre!("invalid change subaddress"))?,
        )
    };
    let change = Change::new(view_pair, change_subaddress);

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

    // Sanity-cap the selected, already-prioritized daemon rate. The historic
    // multiplier is used only to preserve the old per-tier safety ceilings;
    // it is NOT applied to the actual fee returned by current monerod.
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
        let subaddress = output
            .subaddress()
            .map(|index| (index.account(), index.address()))
            .unwrap_or((0, 0));
        if subaddress == req.source && is_unlocked(&output, stored, tip_u64) {
            spendable.push((stored.clone(), output));
        }
    }
    if spendable.is_empty() {
        return Err(color_eyre::eyre::eyre!(
            "no unlocked outputs available in subaddress {}/{}",
            req.source.0,
            req.source.1
        ));
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

    // Select inputs with wallet2's least-related/random-tie policy. A sweep
    // consumes every unlocked output and derives the payment as `total - fee`;
    // a regular send stops once amount + estimated fee is covered.
    stage(event_tx, "Selecting inputs");
    let mut rng = rand::rngs::OsRng;

    let mut selected: Vec<(StoredOutput, WalletOutput)>;
    let mut amount = req.amount;
    let mut fee_estimate;
    if req.sweep_all {
        selected = Vec::with_capacity(spendable.len());
        while !spendable.is_empty() {
            let output = pop_least_related(&mut spendable, &selected, false, &mut rng);
            selected.push(output);
        }
        fee_estimate = fee_for(selected.len());
        amount = sweep_payment(
            selected.iter().map(|(_, o)| o.commitment().amount).sum(),
            fee_estimate,
        )?;
    } else {
        // wallet2 estimates a two-input fee while searching for a preferred
        // one- or two-input set. Its pair search never crosses subaddresses.
        let preferred = preferred_input_indices(&spendable, req.amount.saturating_add(fee_for(2)));
        selected = preferred
            .iter()
            .map(|index| spendable[*index].clone())
            .collect();
        for index in preferred.into_iter().rev() {
            spendable.remove(index);
        }
        let mut active = if let Some(first) = selected.first() {
            take_subaddress_group(&mut spendable, output_subaddress(first))
        } else {
            take_largest_subaddress_group(&mut spendable)
        };
        let mut selected_sum = selected
            .iter()
            .map(|(_, output)| output.commitment().amount)
            .sum::<u64>();
        fee_estimate = fee_for(selected.len().max(1));
        while selected_sum < req.amount.saturating_add(fee_estimate) {
            if active.is_empty() {
                if spendable.is_empty() {
                    break;
                }
                // The candidate set was pre-filtered to the user's explicit
                // source. This fallback can therefore never cross into a
                // different receiving identity.
                active = take_largest_subaddress_group(&mut spendable);
            }
            let candidate = pop_least_related(&mut active, &selected, false, &mut rng);
            selected.push(candidate);
            selected_sum = selected
                .iter()
                .map(|(_, o)| o.commitment().amount)
                .sum::<u64>();
            fee_estimate = fee_for(selected.len());
        }

        // wallet2 normally turns a one-input/two-output RingCT payment into a
        // 2/2 transaction when an unrelated small input is available. Match
        // its cleanup guard so this wallet does not emit a distinctive stream
        // of 1/2 transactions or consume its last few large outputs.
        if selected.len() == 1 && !active.is_empty() {
            const DEFAULT_MIN_OUTPUT_VALUE: u64 = 2_000_000_000_000;
            const DEFAULT_MIN_OUTPUT_COUNT: usize = 5;
            let candidate = pop_least_related(&mut active, &selected, true, &mut rng);
            let enough_large_outputs = candidate.1.commitment().amount < DEFAULT_MIN_OUTPUT_VALUE
                || active
                    .iter()
                    .filter(|(_, output)| output.commitment().amount >= DEFAULT_MIN_OUTPUT_VALUE)
                    .count()
                    .saturating_add(1)
                    >= DEFAULT_MIN_OUTPUT_COUNT;
            if enough_large_outputs && output_relatedness(&candidate, &selected[0]) == 0 {
                selected.push(candidate);
                selected_sum = selected
                    .iter()
                    .map(|(_, output)| output.commitment().amount)
                    .sum();
                fee_estimate = fee_for(selected.len());
            } else {
                active.push(candidate);
            }
        }
        while selected_sum < req.amount.saturating_add(fee_estimate) {
            if active.is_empty() {
                if spendable.is_empty() {
                    break;
                }
                active = take_largest_subaddress_group(&mut spendable);
            }
            let candidate = pop_least_related(&mut active, &selected, false, &mut rng);
            selected.push(candidate);
            selected_sum = selected
                .iter()
                .map(|(_, output)| output.commitment().amount)
                .sum();
            fee_estimate = fee_for(selected.len());
        }
        if selected_sum < req.amount.saturating_add(fee_estimate) {
            return Err(color_eyre::eyre::eyre!(
                "insufficient unlocked balance in subaddress {}/{}: have {} + fee, need {}",
                req.source.0,
                req.source.1,
                crate::wallet::format_xmr(selected_sum),
                crate::wallet::format_xmr(req.amount)
            ));
        }
    }

    // Select decoys for every input and apply wallet2's transaction-wide
    // sanity policy. A ring already committed for this key image is reused on
    // every attempt; only new rings may be resampled. This is the core defense
    // against intersection when a signed transaction was rejected, dropped,
    // or created across a fork.
    //
    // IMPORTANT: muff implements NO decoy-selection algorithm of its own.
    // Selection is delegated entirely to the `monero-wallet` crate:
    // `OutputWithDecoys::new` (monero-wallet/src/decoys.rs) implements the
    // same Gamma(19.28, 1/1.61) statistical age model as wallet2. It is not a
    // byte-for-byte implementation (see README's alignment note). The daemon
    // client only supplies distribution and key data through `ProvidesDecoys`.
    stage(
        event_tx,
        format!("Selecting decoys ({} inputs)", selected.len()),
    );
    let spend = Zeroizing::new(spend_scalar(&keys.keypair.spend)?);
    let key_images: Vec<String> = selected
        .iter()
        .map(|(_, output)| hex::encode(key_image(&spend, output)))
        .collect();
    let inputs =
        select_decoys_with_sanity(daemon, db, &selected, &key_images, tip, &mut rng, event_tx)
            .await?;

    // Build the signable transaction. For a sweep the exact fee is only
    // known once the transaction exists, and the payment is `total - fee`,
    // so build twice if needed: the fee from the first build fixes the
    // payment of the (weight-identical) second.
    stage(event_tx, "Constructing transaction");
    let input_count = inputs.len();
    let mut signable = build_signable(
        keys,
        inputs.clone(),
        recipient,
        amount,
        fee_rate,
        req.source,
        &mut rng,
    )?;
    let mut fee = signable.necessary_fee();
    if req.sweep_all {
        let total: u64 = selected.iter().map(|(_, o)| o.commitment().amount).sum();
        for _ in 0..3 {
            if fee == fee_estimate {
                break;
            }
            fee_estimate = fee;
            amount = sweep_payment(total, fee)?;
            signable = build_signable(
                keys,
                inputs.clone(),
                recipient,
                amount,
                fee_rate,
                req.source,
                &mut rng,
            )?;
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
    let signed = signable
        .sign(&mut rng, &spend)
        .map_err(|e| color_eyre::eyre::eyre!("signing failed: {e}"))?;
    let tx_hash = hex::encode(signed.hash());
    let tx_blob = signed.serialize();

    // PRIVACY INVARIANT: commit the exact signed bytes and every input ring
    // before the first network write. After an ambiguous relay, rebuilding a
    // transaction would create intersectable rings and may reveal its true
    // inputs; retrying these identical bytes is safe and idempotent.
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
    let committed_rings: Vec<(String, Vec<u8>)> = key_images
        .iter()
        .cloned()
        .zip(inputs.iter().map(OutputWithDecoys::serialize))
        .collect();
    db.record_signed_transfer(&input_keys, &committed_rings, &tx_blob, &record)?;
    if let Err(e) = db.save() {
        // Nothing has been broadcast. Restore the in-memory reservation so
        // the user can retry after fixing storage; make a best effort to keep
        // the chosen rings for that future construction.
        let rollback_error = db.rollback_unpersisted_transfer(&tx_hash).err();
        let _ = db.save();
        return Err(color_eyre::eyre::eyre!(
            "refusing to relay because signed transaction state could not be saved: {e}; rollback: {}",
            rollback_error
                .map(|error| format!("failed ({error})"))
                .unwrap_or_else(|| "complete".to_string())
        ));
    }

    stage(event_tx, "Publishing transaction");
    let mut warning = None;
    match daemon.publish_transaction(&tx_blob).await {
        Ok(_) => {
            db.mark_transaction_relayed(&tx_hash)?;
        }
        Err(PublishError::Rejected(message)) => {
            // The daemon explicitly proved the transaction structurally
            // invalid. Release its reservation, but keep its rings so a
            // corrected replacement cannot create a ring-intersection leak.
            db.reject_signed_transfer(&tx_hash)?;
            db.save().map_err(|e| {
                color_eyre::eyre::eyre!(
                    "transaction was rejected ({message}), and the released state could not be saved: {e}"
                )
            })?;
            return Err(color_eyre::eyre::eyre!(
                "daemon rejected transaction: {message}"
            ));
        }
        Err(PublishError::Ambiguous(message)) => {
            // A lost response may hide a successful submission. A positive
            // key-image result is enough to present success; otherwise leave
            // the durable reservation and exact blob for background retry.
            stage(event_tx, "Verifying transaction status");
            match daemon.is_key_images_spent(&key_images).await {
                Ok(statuses)
                    if statuses.len() == key_images.len()
                        && statuses.iter().all(|status| *status != 0) =>
                {
                    tracing::warn!(
                        "relay was ambiguous ({message}), but every key image is spent; treating {tx_hash} as relayed"
                    );
                    db.mark_transaction_relayed(&tx_hash)?;
                }
                _ => {
                    tracing::warn!(
                        "relay was ambiguous ({message}); saved {tx_hash} for exact-byte retry"
                    );
                    let _ =
                        event_tx.send(AppEvent::Send(SendEvent::StoredForRetry { tx_hash, fee }));
                    return Ok(());
                }
            }
        }
    }

    if let Err(e) = db.save() {
        // The pre-relay snapshot still contains the exact transaction as
        // unrelayed, so reopening/retrying cannot produce a conflicting tx.
        tracing::error!("failed to save relayed marker for {tx_hash}: {e:#}");
        warning = Some(format!(
            "Transaction {tx_hash} was relayed, but its relay marker was not saved. The wallet may safely rebroadcast the identical transaction."
        ));
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

    #[test]
    fn ring_sanity_matches_reference_thresholds() {
        let valid = vec![
            (7_000..7_016).collect::<Vec<_>>(),
            (7_016..7_032).collect::<Vec<_>>(),
        ];
        assert!(ring_positions_are_sane(&valid, 10_000));

        // Thirty-two members with only sixteen distinct indices must not be
        // exempted merely because the unique set is small.
        let duplicate = vec![
            (7_000..7_016).collect::<Vec<_>>(),
            (7_000..7_016).collect::<Vec<_>>(),
        ];
        assert!(!ring_positions_are_sane(&duplicate, 10_000));

        let old = vec![(0..16).collect::<Vec<_>>(), (16..32).collect::<Vec<_>>()];
        assert!(!ring_positions_are_sane(&old, 10_000));
    }

    #[test]
    fn ring_sanity_uses_wallet2_integer_rounding() {
        // wallet2 accepts floor(32 * 8 / 10) == 25 unique members.
        let first = (7_000..7_016).collect::<Vec<_>>();
        let mut second = (7_016..7_025).collect::<Vec<_>>();
        second.extend(7_000..7_007);
        assert_eq!(second.len(), 16);
        assert!(ring_positions_are_sane(&[first, second], 10_000));
    }
}
