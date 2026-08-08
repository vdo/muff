//! Map a wallet creation date to a block height to start scanning from.
//!
//! Restoring a wallet needs a starting height, but nobody remembers the
//! block height they created a seed at — they remember roughly *when*. This
//! turns a date into a height using a checkpoint table, the same approach
//! Feather takes (`src/utils/RestoreHeightLookup.h`); the tables themselves
//! are vendored from Feather under `assets/` (see `assets/README.md`).
//!
//! Erring early is free — the scanner just checks some extra blocks — while
//! erring late silently hides funds received before the start height. Every
//! rounding decision here is therefore biased backwards, and the result is
//! additionally rolled back by [`CLEARANCE_BLOCKS`].

use crate::config::NetworkKind;
use std::sync::OnceLock;

/// `unix_timestamp:height` checkpoints, ascending, vendored from Feather.
const MAINNET_TABLE: &str = include_str!("../../assets/restore_heights_monero_mainnet.txt");
const STAGENET_TABLE: &str = include_str!("../../assets/restore_heights_monero_stagenet.txt");

/// Monero's target block time, used to extrapolate past the last checkpoint.
const SECONDS_PER_BLOCK: u64 = 120;

/// Blocks subtracted from every lookup: five days at 720 blocks/day.
///
/// Absorbs both the gap between checkpoints and any clock skew in the date
/// the user typed. Feather uses the same margin.
const CLEARANCE_BLOCKS: u64 = 720 * 5;

fn table(network: NetworkKind) -> Option<&'static [(u64, u64)]> {
    static MAINNET: OnceLock<Vec<(u64, u64)>> = OnceLock::new();
    static STAGENET: OnceLock<Vec<(u64, u64)>> = OnceLock::new();
    match network {
        NetworkKind::Mainnet => Some(
            MAINNET
                .get_or_init(|| parse_table(MAINNET_TABLE))
                .as_slice(),
        ),
        NetworkKind::Stagenet => Some(
            STAGENET
                .get_or_init(|| parse_table(STAGENET_TABLE))
                .as_slice(),
        ),
        // Testnet is reset often enough that a checkpoint table would be
        // wrong more often than it is right; scanning it from genesis is
        // cheap.
        NetworkKind::Testnet => None,
    }
}

/// Parse `timestamp:height` lines, skipping anything malformed.
///
/// A corrupt line should cost precision, not startup: the table is a
/// convenience, and a shorter table still extrapolates correctly.
fn parse_table(raw: &str) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = raw
        .lines()
        .filter_map(|line| {
            let (ts, height) = line.trim().split_once(':')?;
            Some((ts.trim().parse().ok()?, height.trim().parse().ok()?))
        })
        .collect();
    // The file ships sorted; sorting defensively costs microseconds once and
    // means `partition_point` below cannot silently return nonsense.
    out.sort_unstable();
    out
}

/// Approximate the block height at `timestamp` (seconds since the epoch).
///
/// Always returns a height at or before the true one, so a wallet restored
/// with it cannot miss earlier transactions.
pub fn date_to_height(network: NetworkKind, timestamp: u64) -> u64 {
    let Some(table) = table(network) else {
        return 0;
    };
    let Some(&(first_ts, _)) = table.first() else {
        return 0;
    };
    // Before the chain existed: genesis.
    if timestamp <= first_ts {
        return 0;
    }

    // Index of the first checkpoint strictly after `timestamp`; the one
    // before it is the latest checkpoint at or before the target date.
    let idx = table.partition_point(|&(ts, _)| ts <= timestamp);

    let height = match table.get(idx) {
        // Inside the table: take the preceding checkpoint.
        Some(_) => table[idx - 1].1,
        // Past the last checkpoint (the table is a snapshot and goes stale):
        // extrapolate at the target block time.
        None => {
            let (last_ts, last_height) = table[table.len() - 1];
            last_height + timestamp.saturating_sub(last_ts) / SECONDS_PER_BLOCK
        }
    };

    height.saturating_sub(CLEARANCE_BLOCKS)
}

/// Parse a `YYYY-MM-DD` date into a scan height for `network`.
///
/// Returns `None` if the date is not a real calendar date, so the caller can
/// re-prompt rather than silently scanning from genesis.
pub fn parse_date_to_height(network: NetworkKind, input: &str) -> Option<u64> {
    use chrono::NaiveDate;
    let date = NaiveDate::parse_from_str(input.trim(), "%Y-%m-%d").ok()?;
    // Midnight UTC on the given day — the earliest instant it could be, which
    // keeps the estimate on the safe side.
    let timestamp = date.and_hms_opt(0, 0, 0)?.and_utc().timestamp();
    Some(date_to_height(network, u64::try_from(timestamp).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_parse_and_are_ascending() {
        for network in [NetworkKind::Mainnet, NetworkKind::Stagenet] {
            let table = table(network).expect("table present");
            assert!(table.len() > 100, "{network:?} table looks truncated");
            for pair in table.windows(2) {
                assert!(
                    pair[0].0 < pair[1].0 && pair[0].1 <= pair[1].1,
                    "{network:?} table is not ascending at {pair:?}"
                );
            }
        }
    }

    #[test]
    fn testnet_has_no_table_and_scans_from_genesis() {
        assert!(table(NetworkKind::Testnet).is_none());
        assert_eq!(date_to_height(NetworkKind::Testnet, 1_700_000_000), 0);
    }

    #[test]
    fn dates_before_genesis_return_zero() {
        assert_eq!(date_to_height(NetworkKind::Mainnet, 0), 0);
        // Monero's genesis is April 2014; 2010 predates it.
        assert_eq!(
            parse_date_to_height(NetworkKind::Mainnet, "2010-01-01"),
            Some(0)
        );
    }

    /// The whole point of the clearance is that the estimate never lands
    /// after the real height, so a restore cannot miss earlier funds.
    #[test]
    fn lookup_never_overshoots_its_checkpoint() {
        let table = table(NetworkKind::Mainnet).unwrap();
        for &(ts, height) in table.iter().step_by(97) {
            let got = date_to_height(NetworkKind::Mainnet, ts);
            assert!(
                got <= height,
                "estimate {got} overshot checkpoint {height} at ts {ts}"
            );
        }
    }

    #[test]
    fn lookup_is_monotonic_in_time() {
        let mut previous = 0;
        for year in 2015..=2026 {
            let got = parse_date_to_height(NetworkKind::Mainnet, &format!("{year}-06-01")).unwrap();
            assert!(got >= previous, "{year} went backwards: {got} < {previous}");
            previous = got;
        }
    }

    /// Past the final checkpoint the table extrapolates; check it stays in
    /// the right ballpark rather than collapsing to zero or exploding.
    #[test]
    fn extrapolates_past_the_last_checkpoint() {
        let table = table(NetworkKind::Mainnet).unwrap();
        let &(last_ts, last_height) = table.last().unwrap();
        let a_year_later = last_ts + 365 * 24 * 3600;
        let got = date_to_height(NetworkKind::Mainnet, a_year_later);
        let expected = last_height + (365 * 24 * 3600 / SECONDS_PER_BLOCK) - CLEARANCE_BLOCKS;
        assert_eq!(got, expected);
        assert!(got > last_height);
    }

    #[test]
    fn rejects_garbage_dates() {
        for bad in ["", "yesterday", "2024-13-01", "2024-02-30", "20240101"] {
            assert!(
                parse_date_to_height(NetworkKind::Mainnet, bad).is_none(),
                "{bad:?} should not parse"
            );
        }
    }

    #[test]
    fn malformed_table_lines_are_skipped() {
        let parsed = parse_table("100:1\nnot-a-line\n200:2\n:\n300:x\n400:4\n");
        assert_eq!(parsed, vec![(100, 1), (200, 2), (400, 4)]);
    }
}
