//! Dev scaffold: inject fake transfer records into a wallet db so the
//! history UI can be exercised end-to-end. Deleted after use.

use muff::wallet::{TransferDirection, TransferRecord, WalletDb};

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let path = std::env::args()
        .nth(1)
        .expect("usage: seed_history <wallet>");
    let password = std::env::args()
        .nth(2)
        .expect("usage: seed_history <wallet> <pw>");
    let db = WalletDb::open(path.as_ref(), password.as_bytes())?;

    let records = [
        TransferRecord {
            tx_hash: "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233".into(),
            height: 2_500_100,
            timestamp: 1_754_500_000,
            amount: 1_234_500_000_000, // 1.2345 XMR
            fee: 0,
            direction: TransferDirection::In,
            confirmed: true,
            failed: false,
            note: "payment from Alice".into(),
        },
        TransferRecord {
            tx_hash: "ff00ee11dd22cc33bb44aa5599887766554433221100ffeeddccbbaa99887766".into(),
            height: 0,
            timestamp: 1_754_990_000,
            amount: 42_000_000_000, // 0.042 XMR
            fee: 28_600_000,
            direction: TransferDirection::Out,
            confirmed: false,
            failed: false,
            note: String::new(),
        },
        TransferRecord {
            tx_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            height: 2_499_000,
            timestamp: 1_753_200_000,
            amount: 500_000_000_000, // 0.5 XMR
            fee: 31_200_000,
            direction: TransferDirection::Out,
            confirmed: true,
            failed: false,
            note: "donation".into(),
        },
    ];
    for r in &records {
        db.insert_history(r)?;
    }
    db.save()?;
    println!("inserted {} transfers", records.len());
    Ok(())
}
