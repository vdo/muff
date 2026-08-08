//! CSV export of transaction history.
//!
//! Modelled on Feather's `HistoryExportDialog`, with the column set adapted
//! to what muff actually records (no account index or payment id; a real
//! status column, since muff tracks dropped transactions).
//!
//! Amounts appear twice: `amount` in atomic units, which is exact, and
//! `amountXMR` for humans. Anything doing arithmetic downstream — tax tools
//! especially — should use the atomic column, because the decimal one is
//! there to be read, not summed.

use crate::wallet::{TransferDirection, TransferRecord};

/// Header row; also the column contract for anything parsing these files.
const HEADER: &str =
    "blockHeight,timestamp,date,direction,status,amount,amountXMR,fee,feeXMR,txid,note";

/// Quote a field per RFC 4180.
///
/// Notes are free text the user typed, so they can contain commas, quotes and
/// newlines. Emitting those raw is how an export silently corrupts every row
/// after it, so quote whenever a delimiter could appear and double any
/// embedded quote.
fn escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Format an amount in XMR without a unit suffix, for the decimal column.
fn xmr_plain(amount: u64) -> String {
    format!(
        "{}.{:012}",
        amount / 1_000_000_000_000,
        amount % 1_000_000_000_000
    )
}

/// `YYYY-MM-DDTHH:MM:SSZ`, or empty when the timestamp is unknown.
fn iso_date(timestamp: u64) -> String {
    if timestamp == 0 {
        return String::new();
    }
    chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// Render transfers as a CSV document, oldest first.
///
/// Takes the records in storage order (as `AppState::transfers` holds them)
/// and emits chronological order, which is what a spreadsheet or tax tool
/// expects — the reverse of the on-screen newest-first view.
pub fn history_to_csv(transfers: &[TransferRecord]) -> String {
    let mut out = String::with_capacity(HEADER.len() + transfers.len() * 160);
    out.push_str(HEADER);

    for t in transfers {
        let direction = match t.direction {
            TransferDirection::In => "in",
            TransferDirection::Out => "out",
        };
        let status = if t.failed {
            "dropped"
        } else if t.confirmed {
            "confirmed"
        } else {
            "pending"
        };

        out.push('\n');
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{}",
            t.height,
            t.timestamp,
            iso_date(t.timestamp),
            direction,
            status,
            t.amount,
            xmr_plain(t.amount),
            t.fee,
            xmr_plain(t.fee),
            escape(&t.tx_hash),
            escape(&t.note),
        ));
    }

    out.push('\n');
    out
}

/// Default export filename, timestamped so repeated exports never silently
/// overwrite one another.
pub fn default_filename(now: chrono::DateTime<chrono::Utc>) -> String {
    format!("muff-history-{}.csv", now.format("%Y%m%d-%H%M%S"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(note: &str) -> TransferRecord {
        TransferRecord {
            tx_hash: "abc123".to_string(),
            height: 100,
            timestamp: 1_700_000_000,
            amount: 1_500_000_000_000,
            fee: 30_000_000,
            direction: TransferDirection::Out,
            confirmed: true,
            failed: false,
            note: note.to_string(),
        }
    }

    #[test]
    fn empty_history_still_emits_a_header() {
        let csv = history_to_csv(&[]);
        assert_eq!(csv, format!("{HEADER}\n"));
    }

    #[test]
    fn renders_amounts_exactly_and_readably() {
        let csv = history_to_csv(&[record("")]);
        let row = csv.lines().nth(1).unwrap();
        // Atomic units are exact; the decimal column is for humans.
        assert!(row.contains(",1500000000000,1.500000000000,"), "{row}");
        assert!(row.contains(",30000000,0.000030000000,"), "{row}");
        assert!(row.contains("2023-11-14T22:13:20Z"), "{row}");
        assert!(row.contains(",out,confirmed,"), "{row}");
    }

    /// The bug this guards against: an unescaped note shifts every later
    /// column, silently corrupting the file rather than failing.
    #[test]
    fn notes_with_delimiters_are_quoted() {
        let csv = history_to_csv(&[record("coffee, tea")]);
        let row = csv.lines().nth(1).unwrap();
        assert!(row.ends_with(r#","coffee, tea""#), "{row}");
        // Field count must survive the embedded comma.
        assert_eq!(split_csv(row).len(), 11);
    }

    #[test]
    fn notes_with_quotes_and_newlines_are_escaped() {
        let csv = history_to_csv(&[record("say \"hi\"\nthen go")]);
        let row = csv.split_once('\n').unwrap().1;
        assert!(row.contains(r#""say ""hi""#), "{row}");
        // A newline inside a quoted field is legal CSV; the field must stay
        // wrapped so a reader keeps it as one value.
        assert!(row.trim_end().ends_with('"'), "{row}");
    }

    #[test]
    fn unknown_timestamp_leaves_the_date_blank() {
        let mut r = record("");
        r.timestamp = 0;
        let csv = history_to_csv(&[r]);
        let fields = split_csv(csv.lines().nth(1).unwrap());
        assert_eq!(fields[1], "0");
        assert_eq!(fields[2], "");
    }

    #[test]
    fn statuses_are_distinguished() {
        let mut dropped = record("");
        dropped.failed = true;
        let mut pending = record("");
        pending.confirmed = false;
        let csv = history_to_csv(&[dropped, pending]);
        assert!(csv.lines().nth(1).unwrap().contains(",dropped,"));
        assert!(csv.lines().nth(2).unwrap().contains(",pending,"));
    }

    #[test]
    fn rows_follow_input_order() {
        let mut first = record("first");
        first.height = 1;
        let mut second = record("second");
        second.height = 2;
        let csv = history_to_csv(&[first, second]);
        assert!(csv.lines().nth(1).unwrap().starts_with("1,"));
        assert!(csv.lines().nth(2).unwrap().starts_with("2,"));
    }

    #[test]
    fn filename_is_timestamped() {
        let when = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        assert_eq!(default_filename(when), "muff-history-20231114-221320.csv");
    }

    /// Minimal RFC 4180 reader, used only to prove the writer's field
    /// boundaries survive escaping.
    fn split_csv(line: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' if in_quotes && chars.peek() == Some(&'"') => {
                    current.push('"');
                    chars.next();
                }
                '"' => in_quotes = !in_quotes,
                ',' if !in_quotes => fields.push(std::mem::take(&mut current)),
                _ => current.push(c),
            }
        }
        fields.push(current);
        fields
    }
}
