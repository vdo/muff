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

    fn zeroize_secrets(&mut self) {
        self.seed.zeroize();
        self.keypair.spend.scalar.zeroize();
        self.keypair.view.scalar.zeroize();
        self.viewpair.view.scalar.zeroize();
    }
}

impl Drop for WalletKeys {
    fn drop(&mut self) {
        self.zeroize_secrets();
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

    /// The ed25519 group order l = 2^252 + 27742317777372353535851937790883648493,
    /// little-endian, as `sc_reduce32` interprets its input.
    const GROUP_ORDER_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    /// Little-endian 256-bit addition (wrapping), for building scalar edges.
    fn le_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
            out[i] = sum as u8;
            carry = sum >> 8;
        }
        out
    }

    /// Little-endian 256-bit subtraction (wrapping).
    fn le_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in 0..32 {
            let diff = i16::from(a[i]) - i16::from(b[i]) - borrow;
            if diff < 0 {
                out[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                out[i] = diff as u8;
                borrow = 0;
            }
        }
        out
    }

    fn le_from_u8(value: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = value;
        out
    }

    /// `sc_reduce32` at the exact boundaries of the group order.
    ///
    /// Restoring a seed derives the spend key through this reduction, so a
    /// mistake at the wrap point produces a wrong wallet for the affected
    /// seeds — the class of bug the module docs record as having already
    /// happened once (~1/16 of seeds derived a different address than the
    /// official wallets). One value below, at, and above each multiple of l
    /// is where such a mistake is visible.
    #[test]
    fn test_sc_reduce32_at_group_order_boundaries() {
        let one = le_from_u8(1);
        let l = GROUP_ORDER_LE;
        let two_l = le_add(&l, &l);
        let three_l = le_add(&two_l, &l);

        // Below l: unchanged.
        assert_eq!(sc_reduce32(&le_sub(&l, &one)), le_sub(&l, &one));
        assert_eq!(sc_reduce32(&le_from_u8(0)), le_from_u8(0));
        assert_eq!(sc_reduce32(&one), one);

        // Exact multiples reduce to zero.
        assert_eq!(sc_reduce32(&l), [0u8; 32]);
        assert_eq!(sc_reduce32(&two_l), [0u8; 32]);
        assert_eq!(sc_reduce32(&three_l), [0u8; 32]);

        // One past each multiple reduces to one.
        assert_eq!(sc_reduce32(&le_add(&l, &one)), one);
        assert_eq!(sc_reduce32(&le_add(&two_l, &one)), one);
        assert_eq!(sc_reduce32(&le_add(&three_l, &one)), one);

        // One before each multiple reduces to l - 1.
        let l_minus_one = le_sub(&l, &one);
        assert_eq!(sc_reduce32(&le_sub(&two_l, &one)), l_minus_one);
        assert_eq!(sc_reduce32(&le_sub(&three_l, &one)), l_minus_one);

        // The largest possible input is still reduced, canonical, and stable.
        let max = [0xffu8; 32];
        let reduced = sc_reduce32(&max);
        assert_ne!(reduced, max);
        assert_eq!(
            sc_reduce32(&reduced),
            reduced,
            "reduction must be idempotent"
        );
        assert!(PrivateKey::from_slice(&reduced).is_ok());
    }

    /// Every reduction must yield a key the `monero` crate accepts, including
    /// for inputs deliberately placed above the group order.
    #[test]
    fn test_sc_reduce32_always_yields_a_canonical_key() {
        let mut inputs: Vec<[u8; 32]> = vec![[0u8; 32], [0xffu8; 32], GROUP_ORDER_LE];
        for byte in [0x0f, 0x10, 0x11, 0x7f, 0x80, 0xfe] {
            let mut candidate = [0xffu8; 32];
            candidate[31] = byte;
            inputs.push(candidate);
        }
        for _ in 0..256 {
            inputs.push(generate_seed());
        }
        for input in inputs {
            let reduced = sc_reduce32(&input);
            assert!(
                PrivateKey::from_slice(&reduced).is_ok(),
                "sc_reduce32({}) is not a canonical scalar",
                hex::encode(input)
            );
            assert_eq!(sc_reduce32(&reduced), reduced);
        }
    }

    /// Cross-implementation check: the addresses shown to the user and the
    /// view pair the scanner scans with must agree.
    ///
    /// `keys.rs` derives addresses through the `monero` crate, while
    /// `scanner.rs` scans through a `monero-wallet` (monero-oxide) `ViewPair`
    /// built from the same keys. These are two independent implementations of
    /// Monero's address derivation, so agreeing is real evidence rather than
    /// self-consistency — and disagreeing would be severe: the Receive tab
    /// would hand out addresses whose incoming funds the scanner can never
    /// see, with no error anywhere.
    ///
    /// Covers the primary address, the subaddresses the Receive tab offers
    /// (`0/1`..`0/4`), the edge of the scanner's registration window
    /// (`0/19`), and indices outside it, on all three networks.
    #[test]
    fn test_addresses_match_independent_implementation() {
        use crate::wallet::scanner::build_view_pair;
        use crate::wallet::send::wallet_network;
        use monero_wallet::address::SubaddressIndex;

        for fill in [0x00u8, 0x01, 0x42, 0xAA, 0xFF] {
            let seed = sc_reduce32(&[fill; 32]);
            for network in [Network::Mainnet, Network::Stagenet, Network::Testnet] {
                let keys = derive_keys(&seed, network);
                let view_pair = build_view_pair(&keys).expect("view pair must build");
                let oxide_network = wallet_network(network);

                assert_eq!(
                    keys.primary_address().to_string(),
                    view_pair.legacy_address(oxide_network).to_string(),
                    "primary address mismatch (seed {fill:#04x}, {network:?})"
                );

                for (major, minor) in [(0u32, 1u32), (0, 4), (0, 19), (0, 20), (1, 0), (3, 7)] {
                    let index = SubaddressIndex::new(major, minor).expect("non-zero index");
                    assert_eq!(
                        keys.get_subaddress(subaddress::Index { major, minor })
                            .to_string(),
                        view_pair.subaddress(oxide_network, index).to_string(),
                        "subaddress {major}/{minor} mismatch (seed {fill:#04x}, {network:?})"
                    );
                }
            }
        }
    }

    /// Addresses must be distinct per network and per subaddress index.
    ///
    /// Guards against a mapping collapse (e.g. the network argument being
    /// dropped, or an index being ignored) that the equality checks above
    /// would not notice if both implementations were fed the same wrong value.
    #[test]
    fn test_addresses_are_distinct_across_networks_and_indices() {
        let seed = sc_reduce32(&[0x37u8; 32]);
        let mut seen = std::collections::HashSet::new();

        for network in [Network::Mainnet, Network::Stagenet, Network::Testnet] {
            let keys = derive_keys(&seed, network);
            assert!(
                seen.insert(keys.address_string()),
                "primary address repeats across networks at {network:?}"
            );
            for minor in 1..8u32 {
                let address = keys
                    .get_subaddress(subaddress::Index { major: 0, minor })
                    .to_string();
                assert!(
                    seen.insert(address),
                    "subaddress 0/{minor} collides at {network:?}"
                );
            }
        }
    }

    #[test]
    fn test_generate_seed_randomness() {
        let s1 = generate_seed();
        let s2 = generate_seed();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_wallet_keys_zeroizes_all_private_material() {
        let mut keys = derive_keys(&[0xAA; 32], Network::Mainnet);
        keys.zeroize_secrets();
        assert!(keys.seed.iter().all(|byte| *byte == 0));
        assert!(keys.keypair.spend.as_bytes().iter().all(|byte| *byte == 0));
        assert!(keys.keypair.view.as_bytes().iter().all(|byte| *byte == 0));
        assert!(keys.viewpair.view.as_bytes().iter().all(|byte| *byte == 0));
    }
}
