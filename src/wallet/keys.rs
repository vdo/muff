use monero::Network;
use monero::cryptonote::subaddress;
use monero::util::address::Address;
use monero::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};
use rand::RngCore;
use zeroize::Zeroize;

/// In-memory wallet keys using real Monero types (zeroized on drop).
#[derive(Clone)]
pub struct WalletKeys {
    /// The original 256-bit seed.
    pub seed: [u8; 32],
    /// Full key pair (view secret + spend secret).
    pub keypair: KeyPair,
    /// View pair (view secret + spend public) for scanning.
    pub viewpair: ViewPair,
    /// Public spend key.
    pub spend_public: PublicKey,
    /// Public view key.
    pub view_public: PublicKey,
    /// Network this wallet belongs to.
    pub network: Network,
}

impl WalletKeys {
    /// Get the primary (0/0) address for this wallet.
    pub fn primary_address(&self) -> Address {
        Address::standard(self.network, self.spend_public, self.view_public)
    }

    /// Get a subaddress at the given index.
    pub fn get_subaddress(&self, index: subaddress::Index) -> Address {
        subaddress::get_subaddress(&self.viewpair, index, Some(self.network))
    }

    /// Get the primary address as a string.
    pub fn address_string(&self) -> String {
        self.primary_address().to_string()
    }
}

impl Drop for WalletKeys {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Generate a new random 256-bit seed.
pub fn generate_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

/// Derive spend and view keys from a seed using proper Monero key derivation.
///
/// Matches monero-project/monero `cryptonote_basic_impl`/wallet2 exactly, so a
/// seed restored in the official GUI/CLI derives the same keys and address:
///
/// spend_secret = sc_reduce32(seed)   (little-endian reduce mod l)
/// view_secret  = Hs(spend_secret)    (keccak -> sc_reduce32)
/// spend_public = spend_secret * G
/// view_public  = view_secret * G
pub fn derive_keys(seed: &[u8; 32], network: Network) -> WalletKeys {
    let reduced = sc_reduce32(seed);
    let spend_secret =
        PrivateKey::from_slice(&reduced).expect("sc_reduce32 always yields a canonical scalar");
    let view_secret = monero::cryptonote::hash::Hash::hash_to_scalar(spend_secret.as_bytes());
    let spend_public = PublicKey::from_private_key(&spend_secret);
    let view_public = PublicKey::from_private_key(&view_secret);

    let keypair = KeyPair {
        view: view_secret,
        spend: spend_secret,
    };
    let viewpair = ViewPair {
        view: view_secret,
        spend: spend_public,
    };

    WalletKeys {
        seed: *seed,
        keypair,
        viewpair,
        spend_public,
        view_public,
        network,
    }
}

/// Reduce arbitrary 32 bytes to a valid ed25519 scalar, byte-for-byte
/// identical to Monero's `sc_reduce32`: interpret as a little-endian integer
/// and reduce modulo l (the ed25519 group order). This is what wallet2 applies
/// to the 32-byte decoded seed to obtain the private spend key, and to fresh
/// randomness when creating a new wallet.
///
/// `curve25519_dalek::Scalar::from_bytes_mod_order` performs exactly that
/// reduction. (An earlier version of this function instead re-hashed until
/// `PrivateKey::from_slice` accepted the bytes, which diverged from wallet2
/// for ~1/16 of seeds — those seeds restored to a different address in the
/// official wallets.)
pub fn sc_reduce32(bytes: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::Scalar::from_bytes_mod_order(*bytes).to_bytes()
}

/// Format an amount in atomic units to an exact XMR string.
///
/// Integer math only — no f64 — so every u64 value (including very large
/// balances) renders exactly, with always-12 decimal places.
pub fn format_xmr(amount: u64) -> String {
    let int_part = amount / 1_000_000_000_000;
    let frac_part = amount % 1_000_000_000_000;
    format!("{int_part}.{frac_part:012} XMR")
}

/// Parse an XMR string to atomic units (piconero) exactly.
///
/// Accepts up to 12 decimal places, e.g. "1.5", "0.000000000001", "1 XMR".
pub fn parse_xmr(s: &str) -> Option<u64> {
    let s = s.trim().trim_end_matches("XMR").trim();
    if s.is_empty() || s.starts_with('-') || s.starts_with('+') {
        return None;
    }
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return None;
    }
    if !int_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if frac_part.len() > 12 {
        return None;
    }
    let int_atomic = if int_part.is_empty() {
        0
    } else {
        int_part
            .parse::<u128>()
            .ok()?
            .checked_mul(1_000_000_000_000)?
    };
    let mut frac_atomic: u128 = 0;
    let mut scale: u128 = 100_000_000_000;
    for c in frac_part.chars() {
        frac_atomic += u128::from(c.to_digit(10)?) * scale;
        scale /= 10;
    }
    let total = int_atomic.checked_add(frac_atomic)?;
    u64::try_from(total).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_xmr_zero() {
        assert_eq!(format_xmr(0), "0.000000000000 XMR");
    }

    #[test]
    fn test_format_xmr_one_atomic() {
        assert_eq!(format_xmr(1), "0.000000000001 XMR");
    }

    #[test]
    fn test_format_xmr_one_xmr() {
        assert_eq!(format_xmr(1_000_000_000_000), "1.000000000000 XMR");
    }

    #[test]
    fn test_format_xmr_fractional() {
        assert_eq!(format_xmr(500_000_000_000), "0.500000000000 XMR");
    }

    #[test]
    fn test_format_xmr_large_values_exact() {
        // Beyond f64's exact integer range (2^53 ≈ 9.007e15 atomic ≈ 9 XMR),
        // the old f64-based formatter lost piconero. Integer math must not.
        assert_eq!(format_xmr(u64::MAX), "18446744.073709551615 XMR");
        assert_eq!(format_xmr(9_007_199_254_740_993), "9007.199254740993 XMR");
        assert_eq!(format_xmr(18_446_744_073_709), "18.446744073709 XMR");
        assert_eq!(
            format_xmr(123_456_789_012_345_678),
            "123456.789012345678 XMR"
        );
    }

    #[test]
    fn test_format_parse_roundtrip() {
        for amount in [
            0u64,
            1,
            999_999_999_999,
            1_000_000_000_000,
            1_234_567_890_123,
            9_007_199_254_740_993,
            u64::MAX,
        ] {
            let formatted = format_xmr(amount);
            assert_eq!(
                parse_xmr(&formatted),
                Some(amount),
                "roundtrip failed for {amount} ({formatted})"
            );
        }
    }

    #[test]
    fn test_parse_xmr_exact() {
        assert_eq!(parse_xmr("1"), Some(1_000_000_000_000));
        assert_eq!(parse_xmr("1 XMR"), Some(1_000_000_000_000));
        assert_eq!(parse_xmr("0.000000000001"), Some(1));
        assert_eq!(parse_xmr(".5"), Some(500_000_000_000));
        assert_eq!(parse_xmr("1.5"), Some(1_500_000_000_000));
        assert_eq!(parse_xmr("123.456789012345"), Some(123_456_789_012_345));
        // Precision cases that break f64 math:
        assert_eq!(parse_xmr("0.1"), Some(100_000_000_000));
        assert_eq!(parse_xmr("0.007"), Some(7_000_000_000));
        assert_eq!(parse_xmr("18446744.073709551615"), Some(u64::MAX));
        // Rejections:
        assert_eq!(parse_xmr(""), None);
        assert_eq!(parse_xmr("abc"), None);
        assert_eq!(parse_xmr("-1"), None);
        assert_eq!(parse_xmr("1.0000000000001"), None); // >12 decimals
        assert_eq!(parse_xmr("1.5.3"), None);
        assert_eq!(parse_xmr("18446744.073709551616"), None); // u64 overflow
    }

    #[test]
    fn test_parse_xmr_basic() {
        assert_eq!(parse_xmr("1.0"), Some(1_000_000_000_000));
        assert_eq!(parse_xmr("0.5"), Some(500_000_000_000));
        assert_eq!(parse_xmr("0.000000000001"), Some(1));
    }

    #[test]
    fn test_parse_xmr_with_suffix() {
        assert_eq!(parse_xmr("1.0 XMR"), Some(1_000_000_000_000));
        assert_eq!(parse_xmr("  2.5 XMR  "), Some(2_500_000_000_000));
    }

    #[test]
    fn test_parse_xmr_invalid() {
        assert_eq!(parse_xmr("notanumber"), None);
        assert_eq!(parse_xmr("-1.0"), None);
    }

    #[test]
    fn test_derive_keys_deterministic() {
        let seed = [42u8; 32];
        let k1 = derive_keys(&seed, Network::Mainnet);
        let k2 = derive_keys(&seed, Network::Mainnet);
        assert_eq!(k1.spend_public, k2.spend_public);
        assert_eq!(k1.view_public, k2.view_public);
        assert_eq!(k1.keypair.spend, k2.keypair.spend);
        assert_eq!(k1.keypair.view, k2.keypair.view);
    }

    #[test]
    fn test_derive_keys_different_seeds() {
        let k1 = derive_keys(&[1u8; 32], Network::Mainnet);
        let k2 = derive_keys(&[2u8; 32], Network::Mainnet);
        assert_ne!(k1.spend_public, k2.spend_public);
    }

    #[test]
    fn test_sc_reduce32_group_order_reduces_to_zero() {
        // The ed25519 group order l must reduce to 0 (LE encoding per
        // curve25519-dalek's constants).
        let mut l = [0u8; 32];
        l[..16].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14,
        ]);
        l[31] = 0x10;
        assert_eq!(sc_reduce32(&l), [0u8; 32]);
    }

    #[test]
    fn test_derive_keys_matches_wallet2_reduction() {
        // For seeds >= l the private spend key must be sc_reduce32(seed) —
        // exactly what wallet2 derives when the same 25-word phrase is
        // restored in the official GUI/CLI.
        let seed = [0xFFu8; 32];
        let keys = derive_keys(&seed, Network::Mainnet);
        assert_eq!(
            &sc_reduce32(&seed)[..],
            keys.keypair.spend.as_bytes(),
            "spend key must equal sc_reduce32(seed)"
        );
    }

    #[test]
    fn test_derive_keys_network_affects_address() {
        let seed = [42u8; 32];
        let mainnet = derive_keys(&seed, Network::Mainnet);
        let stagenet = derive_keys(&seed, Network::Stagenet);
        assert_eq!(mainnet.spend_public, stagenet.spend_public);
        assert_ne!(mainnet.address_string(), stagenet.address_string());
    }

    #[test]
    fn test_primary_address_valid() {
        let keys = derive_keys(&[42u8; 32], Network::Mainnet);
        let addr = keys.address_string();
        assert!(
            addr.starts_with('4'),
            "Mainnet address should start with 4: {}",
            addr
        );
    }

    #[test]
    fn test_subaddress_differs_from_primary() {
        let keys = derive_keys(&[42u8; 32], Network::Mainnet);
        let primary = keys.primary_address();
        let sub = keys.get_subaddress(subaddress::Index { major: 0, minor: 1 });
        assert_ne!(primary, sub);
    }

    #[test]
    fn test_generate_seed_randomness() {
        let s1 = generate_seed();
        let s2 = generate_seed();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_wallet_keys_drop_zeroizes_seed() {
        let seed_ptr;
        {
            let keys = derive_keys(&[0xAA; 32], Network::Mainnet);
            seed_ptr = keys.seed.as_ptr();
            assert_eq!(keys.seed, [0xAA; 32]);
        }
        unsafe {
            let bytes = std::slice::from_raw_parts(seed_ptr, 32);
            assert!(
                bytes.iter().all(|&b| b == 0),
                "Seed should be zeroized after drop"
            );
        }
    }
}
