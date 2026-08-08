//! Raw binary (`*.bin`) daemon RPC endpoints, encoded with epee.
//!
//! These endpoints are used for fast block syncing (`/getblocks.bin`),
//! RingCT output index lookups (`/get_o_indexes.bin`), decoy fetching
//! (`/get_outs.bin`), and decoy sampling (`/get_output_distribution.bin`).

use color_eyre::Result;

use super::epee::{Value, decode_document, encode_document};

/// One transaction entry within a `/getblocks.bin` block.
#[derive(Debug, Clone)]
pub struct BlockTxEntry {
    /// The raw pruned (or full) transaction blob.
    pub pruned_blob: Vec<u8>,
    /// The hash of the tx's prunable data ([0; 32] for v1 / missing),
    /// required to compute the transaction id of a pruned transaction.
    pub prunable_hash: [u8; 32],
    /// Global indices of this transaction's outputs (RingCT pool for v2 txs).
    pub output_indices: Vec<u64>,
}

/// One block entry within a `/getblocks.bin` response.
#[derive(Debug, Clone)]
pub struct BlockEntry {
    /// The serialized block (header + miner tx + tx hashes).
    pub block_blob: Vec<u8>,
    /// The miner transaction's global output indices.
    pub miner_output_indices: Vec<u64>,
    /// The block's non-miner transactions, in `block.transactions` order.
    pub txs: Vec<BlockTxEntry>,
}

/// Response from `/getblocks.bin`.
#[derive(Debug)]
pub struct GetBlocksResponse {
    /// Starting height of the returned range (echoed by the daemon).
    pub start_height: u64,
    /// Chain height the daemon knows about.
    pub current_height: u64,
    /// The returned blocks.
    pub blocks: Vec<BlockEntry>,
}

/// A single output entry from `/get_outs.bin`.
#[derive(Debug, Clone)]
pub struct OutEntry {
    /// Output's public key (32 bytes, compressed Edwards point).
    pub key: [u8; 32],
    /// Output's commitment (32 bytes, Edwards point).
    pub mask: [u8; 32],
    /// Whether the daemon believes the output is unlocked.
    pub unlocked: bool,
    /// Block height where the output was created.
    pub height: u64,
}

/// POST helper for binary endpoints.
async fn post_bin(
    client: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
) -> Result<Vec<(String, Value)>> {
    let response = client
        .post(url)
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .map_err(|e| color_eyre::eyre::eyre!("binary RPC POST {url} failed: {e}"))?;

    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| color_eyre::eyre::eyre!("binary RPC {url}: failed to read body: {e}"))?;

    if !status.is_success() {
        return Err(color_eyre::eyre::eyre!(
            "binary RPC {url} returned HTTP {status}"
        ));
    }
    decode_document(&bytes)
        .map_err(|e| color_eyre::eyre::eyre!("binary RPC {url}: epee decode failed: {e}"))
}

/// Fetch a range of blocks with their transactions via `/getblocks.bin`.
///
/// Requests pruned transactions (sufficient for scanning; ~1/8th the size).
pub async fn get_blocks(
    client: &reqwest::Client,
    base_url: &str,
    start_height: u64,
) -> Result<GetBlocksResponse> {
    let body = encode_document(&[
        ("start_height".to_string(), Value::U64(start_height)),
        ("prune".to_string(), Value::Bool(true)),
        ("no_miner_tx".to_string(), Value::Bool(false)),
    ]);
    let root = post_bin(client, &format!("{base_url}/getblocks.bin"), body).await?;

    let start_height = Value::get_u64(&root, "start_height").unwrap_or(start_height);
    let current_height = Value::get_u64(&root, "current_height").unwrap_or(0);

    let mut blocks = Vec::new();
    // `output_indices[i].indices[0]` = miner tx of block i;
    // `output_indices[i].indices[j+1]` = non-miner tx j of block i.
    let all_output_indices = Value::get_object_array(&root, "output_indices");
    if let Some(block_entries) = Value::get_object_array(&root, "blocks") {
        for (block_idx, entry) in block_entries.iter().enumerate() {
            let block_blob = Value::get_bytes(entry, "block")
                .ok_or_else(|| color_eyre::eyre::eyre!("getblocks: block entry missing blob"))?
                .to_vec();

            let block_indices: Option<&[Vec<(String, Value)>]> = all_output_indices
                .and_then(|all| all.get(block_idx))
                .and_then(|blk| Value::get_object_array(blk, "indices"));
            let indices_for = |tx_pos: usize| -> Vec<u64> {
                block_indices
                    .and_then(|bi| bi.get(tx_pos))
                    .and_then(|tx| Value::get_u64_array(tx, "indices"))
                    .map(|s| s.to_vec())
                    .unwrap_or_default()
            };
            let miner_output_indices = indices_for(0);

            let mut txs = Vec::new();
            if let Some(tx_entries) = Value::get_object_array(entry, "txs") {
                for (tx_idx, tx_entry) in tx_entries.iter().enumerate() {
                    let pruned_blob = Value::get_bytes(tx_entry, "blob")
                        .or_else(|| Value::get_bytes(tx_entry, "pruned_tx_blob"))
                        .or_else(|| Value::get_bytes(tx_entry, "tx_blob"))
                        .ok_or_else(|| color_eyre::eyre::eyre!("getblocks: tx entry missing blob"))?
                        .to_vec();
                    let output_indices = indices_for(tx_idx + 1);
                    let mut prunable_hash = [0u8; 32];
                    if let Some(bytes) = Value::get_bytes(tx_entry, "prunable_hash")
                        && bytes.len() == 32
                    {
                        prunable_hash.copy_from_slice(bytes);
                    }
                    txs.push(BlockTxEntry {
                        pruned_blob,
                        prunable_hash,
                        output_indices,
                    });
                }
            }

            blocks.push(BlockEntry {
                block_blob,
                miner_output_indices,
                txs,
            });
        }
    }

    Ok(GetBlocksResponse {
        start_height,
        current_height,
        blocks,
    })
}

/// Get the global output indices for a transaction via `/get_o_indexes.bin`.
///
/// For RingCT-era transactions these are indices into the global zero-amount
/// (RingCT) output pool, in output order.
pub async fn get_o_indexes(
    client: &reqwest::Client,
    base_url: &str,
    txid: [u8; 32],
) -> Result<Vec<u64>> {
    let body = encode_document(&[("txid".to_string(), Value::String(txid.to_vec()))]);
    let root = post_bin(client, &format!("{base_url}/get_o_indexes.bin"), body).await?;
    Ok(Value::get_u64_array(&root, "o_indexes")
        .map(|s| s.to_vec())
        .unwrap_or_default())
}

/// Fetch RingCT output keys/commitments via `/get_outs.bin`.
pub async fn get_outs(
    client: &reqwest::Client,
    base_url: &str,
    indexes: &[u64],
) -> Result<Vec<OutEntry>> {
    let outputs: Vec<Vec<(String, Value)>> = indexes
        .iter()
        .map(|index| vec![("index".to_string(), Value::U64(*index))])
        .collect();
    let body = encode_document(&[("outputs".to_string(), Value::ObjectArray(outputs))]);
    let root = post_bin(client, &format!("{base_url}/get_outs.bin"), body).await?;

    let mut outs = Vec::with_capacity(indexes.len());
    if let Some(entries) = Value::get_object_array(&root, "outs") {
        for entry in entries {
            let key_bytes = Value::get_bytes(entry, "key")
                .ok_or_else(|| color_eyre::eyre::eyre!("get_outs: entry missing key"))?;
            let mask_bytes = Value::get_bytes(entry, "mask")
                .ok_or_else(|| color_eyre::eyre::eyre!("get_outs: entry missing mask"))?;
            let mut key = [0u8; 32];
            let mut mask = [0u8; 32];
            if key_bytes.len() != 32 || mask_bytes.len() != 32 {
                return Err(color_eyre::eyre::eyre!(
                    "get_outs: key/mask must be 32 bytes (got {}/{})",
                    key_bytes.len(),
                    mask_bytes.len()
                ));
            }
            key.copy_from_slice(key_bytes);
            mask.copy_from_slice(mask_bytes);
            outs.push(OutEntry {
                key,
                mask,
                unlocked: Value::get_bool(entry, "unlocked").unwrap_or(false),
                height: Value::get_u64(entry, "height").unwrap_or(0),
            });
        }
    }
    Ok(outs)
}

/// The cumulative RingCT output distribution returned by the daemon.
#[derive(Debug)]
pub struct Distribution {
    /// First block height the values correspond to (the daemon may trim
    /// leading zero-count blocks, e.g. everything before the first RingCT
    /// block).
    pub start_height: u64,
    /// Absolute cumulative RingCT output counts; entry `i` is the count up
    /// to and including block `start_height + i`.
    pub values: Vec<u64>,
}

/// Fetch the cumulative RingCT output distribution via
/// `/get_output_distribution.bin`.
///
/// The daemon requires `binary = true`, under which `distribution` is a
/// packed little-endian integer string (u64 on modern daemons; u32 on older
/// ones). Values are absolute cumulative counts even for non-zero
/// `from_height`.
pub async fn get_output_distribution(
    client: &reqwest::Client,
    base_url: &str,
    from_height: u64,
    to_height: u64,
) -> Result<Distribution> {
    let body = encode_document(&[
        ("amounts".to_string(), Value::U64Array(vec![0])),
        ("from_height".to_string(), Value::U64(from_height)),
        ("to_height".to_string(), Value::U64(to_height)),
        ("cumulative".to_string(), Value::Bool(true)),
        ("binary".to_string(), Value::Bool(true)),
    ]);
    let root = post_bin(
        client,
        &format!("{base_url}/get_output_distribution.bin"),
        body,
    )
    .await?;

    let distributions = Value::get_object_array(&root, "distributions")
        .ok_or_else(|| color_eyre::eyre::eyre!("get_output_distribution: missing distributions"))?;
    let first = distributions
        .first()
        .ok_or_else(|| color_eyre::eyre::eyre!("get_output_distribution: empty distributions"))?;

    let start_height = Value::get_u64(first, "start_height").unwrap_or(from_height);
    let binary = Value::get_bool(first, "binary").unwrap_or(true);

    let values = if binary {
        let packed = Value::get_bytes(first, "distribution").ok_or_else(|| {
            color_eyre::eyre::eyre!("get_output_distribution: missing binary distribution")
        })?;
        if packed.len() % 8 == 0 {
            packed
                .chunks_exact(8)
                .map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes")))
                .collect()
        } else if packed.len() % 4 == 0 {
            packed
                .chunks_exact(4)
                .map(|c| u64::from(u32::from_le_bytes(c.try_into().expect("4 bytes"))))
                .collect()
        } else {
            return Err(color_eyre::eyre::eyre!(
                "get_output_distribution: distribution blob length {} not a multiple of 4/8",
                packed.len()
            ));
        }
    } else {
        Value::get_u64_array(first, "distribution")
            .map(|s| s.to_vec())
            .unwrap_or_default()
    };

    Ok(Distribution {
        start_height,
        values,
    })
}
