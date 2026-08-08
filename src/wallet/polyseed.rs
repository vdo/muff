//! Polyseed support (16-word mnemonic for Monero).
//!
//! Implements the final [tevador/polyseed](https://github.com/tevador/polyseed)
//! specification (the format adopted by Feather/Cake):
//!
//! - 16 words encode 16 GF(2^11) digits: digit 0 is a polynomial-code
//!   checksum; digits 1-15 each carry 10 secret bits plus one extra bit
//!   (5 feature bits then 10 birthday bits, MSB first).
//! - The checksum evaluates the digit polynomial at x = 2 over GF(2^11);
//!   `coeff[0]` is chosen so the full evaluation is zero. Any single-word
//!   error is detected (the code has distance 2).
//! - The spend key is PBKDF2-HMAC-SHA256 (10 000 iterations) over the
//!   zero-padded 32-byte secret buffer with a salt domain-separated by
//!   coin, birthday and features, reduced mod l.
//!
//! An earlier draft of the spec (memory-hard coefficients, sum checksum)
//! was never deployed; this module only implements the final format.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const BIP39_WORDLIST: &[&str] = &include!("words_bip39.rs");
const POLYSEED_WORDS: usize = 16;
const GF_BITS: u32 = 11;
const SHARE_BITS: u32 = GF_BITS - 1; // secret bits per word
const SECRET_BITS: u32 = 150;
const SECRET_SIZE: usize = (SECRET_BITS as usize).div_ceil(8); // 19
const DATE_BITS: u32 = 10;
const FEATURE_BITS: u32 = 5;
const DATE_MASK: u32 = (1 << DATE_BITS) - 1;
/// 1st November 2021 12:00 UTC (spec value; do not "fix" to midnight).
const EPOCH: u64 = 1_635_768_000;
/// 1/12 of the average Gregorian year, in seconds.
const TIME_STEP: u64 = 2_629_746;
const KDF_ITERATIONS: u32 = 10_000;
/// `polyseed_coin` value for Monero (seeds are incompatible between coins).
const COIN_MONERO: u32 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolyseedError {
    InvalidWordCount(usize),
    UnknownWord(String),
    InvalidChecksum,
    UnsupportedFeatures,
}

impl std::fmt::Display for PolyseedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWordCount(n) => write!(f, "Expected 16 words, got {}", n),
            Self::UnknownWord(w) => write!(f, "Unknown BIP39 word: '{}'", w),
            Self::InvalidChecksum => write!(f, "Invalid Polyseed checksum"),
            Self::UnsupportedFeatures => write!(f, "Unsupported feature bits"),
        }
    }
}

impl std::error::Error for PolyseedError {}

/// Decoded polyseed payload.
struct PolyseedData {
    secret: [u8; SECRET_SIZE],
    features: u8,
    /// Birthday in `TIME_STEP` units since `EPOCH` (the encoded form).
    birthday: u16,
}

/// `birthday_encode`: unix time -> 10-bit encoded birthday (clamped).
fn birthday_encode(time: u64) -> u16 {
    if time == u64::MAX || time < EPOCH {
        return 0;
    }
    (((time - EPOCH) / TIME_STEP) as u32).min(DATE_MASK) as u16
}

/// `birthday_decode`: encoded birthday -> approximate unix time.
fn birthday_decode(birthday: u32) -> u64 {
    EPOCH + birthday as u64 * TIME_STEP
}

// ---------------------------------------------------------------------------
// GF(2^11) checksum (polynomial code evaluated at x = 2)
// ---------------------------------------------------------------------------

/// Multiplication by 2 in GF(2^11); the table encodes the reduction by the
/// field's primitive polynomial for x >= 1024 (from the reference gf.h).
const MUL2_TABLE: [u16; 8] = [5, 7, 1, 3, 13, 15, 9, 11];

fn gf_elem_mul2(x: u16) -> u16 {
    if x < 1024 {
        2 * x
    } else {
        MUL2_TABLE[(x % 8) as usize] + 16 * ((x - 1024) / 8)
    }
}

/// Horner evaluation of the digit polynomial at x = 2.
fn gf_poly_eval(coeff: &[u16; POLYSEED_WORDS]) -> u16 {
    let mut result = coeff[POLYSEED_WORDS - 1];
    for i in (0..POLYSEED_WORDS - 1).rev() {
        result = gf_elem_mul2(result) ^ coeff[i];
    }
    result
}

// ---------------------------------------------------------------------------
// Bit packing: seed data <-> polynomial digits (reference storage layout)
// ---------------------------------------------------------------------------

fn data_to_poly(data: &PolyseedData) -> [u16; POLYSEED_WORDS] {
    let mut coeff = [0u16; POLYSEED_WORDS];
    let extra_val = ((data.features as u32) << DATE_BITS) | data.birthday as u32;
    let mut extra_bits = FEATURE_BITS + DATE_BITS;

    let mut secret_idx = 0usize;
    let mut secret_val = data.secret[0] as u32;
    let mut secret_bits = 8u32;
    let mut seed_rem_bits = SECRET_BITS - 8;

    for i in 0..POLYSEED_WORDS - 1 {
        let mut word_bits = 0u32;
        let mut word_val = 0u32;
        while word_bits < SHARE_BITS {
            if secret_bits == 0 {
                secret_idx += 1;
                secret_bits = seed_rem_bits.min(8);
                secret_val = data.secret[secret_idx] as u32;
                seed_rem_bits -= secret_bits;
            }
            let chunk_bits = secret_bits.min(SHARE_BITS - word_bits);
            secret_bits -= chunk_bits;
            word_bits += chunk_bits;
            word_val <<= chunk_bits;
            word_val |= (secret_val >> secret_bits) & ((1u32 << chunk_bits) - 1);
        }
        word_val <<= 1;
        extra_bits -= 1;
        word_val |= (extra_val >> extra_bits) & 1;
        coeff[1 + i] = word_val as u16;
    }
    debug_assert_eq!(seed_rem_bits, 0);
    debug_assert_eq!(extra_bits, 0);
    coeff
}

fn poly_to_data(coeff: &[u16; POLYSEED_WORDS]) -> PolyseedData {
    let mut secret = [0u8; SECRET_SIZE];
    let mut extra_val = 0u32;
    let mut secret_idx = 0usize;
    let mut secret_bits = 0u32;

    for &word in coeff.iter().skip(1) {
        let mut word_val = word as u32;
        extra_val = (extra_val << 1) | (word_val & 1);
        word_val >>= 1;
        let mut word_bits = SHARE_BITS;
        while word_bits > 0 {
            if secret_bits == 8 {
                secret_idx += 1;
                secret_bits = 0;
            }
            let chunk_bits = word_bits.min(8 - secret_bits);
            word_bits -= chunk_bits;
            let chunk_mask = (1u32 << chunk_bits) - 1;
            if chunk_bits < 8 {
                secret[secret_idx] <<= chunk_bits;
            }
            secret[secret_idx] |= ((word_val >> word_bits) & chunk_mask) as u8;
            secret_bits += chunk_bits;
        }
    }

    PolyseedData {
        secret,
        features: (extra_val >> DATE_BITS) as u8,
        birthday: (extra_val & DATE_MASK) as u16,
    }
}

// ---------------------------------------------------------------------------
// Key derivation (reference polyseed_keygen)
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC-SHA256 over the zero-padded 32-byte secret buffer with a
/// 32-byte salt domain-separated by coin, birthday and features.
fn polyseed_keygen(secret: &[u8; SECRET_SIZE], birthday: u32, features: u32) -> [u8; 32] {
    let mut salt = [0u8; 32];
    salt[..12].copy_from_slice(b"POLYSEED key");
    salt[13] = 0xff;
    salt[14] = 0xff;
    salt[15] = 0xff;
    salt[16..20].copy_from_slice(&COIN_MONERO.to_le_bytes());
    salt[20..24].copy_from_slice(&birthday.to_le_bytes());
    salt[24..28].copy_from_slice(&features.to_le_bytes());

    // The password is the 32-byte secret buffer (zero-padded for future
    // compatibility with longer seeds, per the reference implementation).
    let mut password = Zeroizing::new([0u8; 32]);
    password[..SECRET_SIZE].copy_from_slice(secret);
    pbkdf2_hmac_sha256(password.as_ref(), &salt, KDF_ITERATIONS)
}

/// Derive the Monero spend key from decoded seed data.
fn data_to_key(data: &PolyseedData) -> [u8; 32] {
    let raw = Zeroizing::new(polyseed_keygen(
        &data.secret,
        data.birthday as u32,
        data.features as u32,
    ));
    super::keys::sc_reduce32(&raw)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Decode a 16-word Polyseed phrase into `(spend_key, birthday_timestamp)`.
pub fn polyseed_to_key(words_str: &str) -> Result<([u8; 32], u64), PolyseedError> {
    let words: Vec<&str> = words_str.split_whitespace().collect();
    if words.len() != POLYSEED_WORDS {
        return Err(PolyseedError::InvalidWordCount(words.len()));
    }
    let mut coeff = [0u16; POLYSEED_WORDS];
    for (i, word) in words.iter().enumerate() {
        coeff[i] = find_bip39_index(word)?;
    }
    // Monero is coin 0, so the coin XOR into coeff[1] is a no-op.
    if gf_poly_eval(&coeff) != 0 {
        return Err(PolyseedError::InvalidChecksum);
    }
    let data = poly_to_data(&coeff);
    // Only feature set 0 (no passphrase encryption, no custom bits) is
    // supported; anything else cannot be unlocked with the phrase alone.
    if data.features != 0 {
        return Err(PolyseedError::UnsupportedFeatures);
    }
    let key = data_to_key(&data);
    Ok((key, birthday_decode(data.birthday as u32)))
}

/// Generate a new Polyseed: `(words, spend_key, birthday_timestamp)`.
///
/// The birthday is "now" at month resolution; the caller turns it into an
/// approximate scan height. `spend_key` is already reduced mod l, so the
/// standard `derive_keys` pipeline can consume it directly.
pub fn generate_polyseed() -> (Vec<String>, [u8; 32], u64) {
    use rand::RngCore;
    let mut secret = Zeroizing::new([0u8; SECRET_SIZE]);
    rand::thread_rng().fill_bytes(secret.as_mut_slice());
    // Clear the top 2 bits of the last byte: exactly 150 bits.
    secret[SECRET_SIZE - 1] &= 0x3f;
    let mut data = PolyseedData {
        secret: *secret,
        features: 0,
        birthday: birthday_encode(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        ),
    };
    let mut coeff = data_to_poly(&data);
    coeff[0] = gf_poly_eval(&coeff);
    let words: Vec<String> = coeff
        .iter()
        .map(|&i| BIP39_WORDLIST[i as usize].to_string())
        .collect();
    let key = data_to_key(&data);
    let birthday = birthday_decode(data.birthday as u32);
    data.secret.zeroize();
    (words, key, birthday)
}

/// BIP39 word suggestions for a prefix (wizard autocomplete).
pub fn polyseed_autocomplete(prefix: &str) -> Vec<&'static str> {
    if prefix.is_empty() {
        return Vec::new();
    }
    let lower = prefix.to_lowercase();
    BIP39_WORDLIST
        .iter()
        .filter(|w| w.starts_with(lower.as_str()))
        .copied()
        .collect()
}

pub fn is_valid_bip39_word(word: &str) -> bool {
    find_bip39_index(word).is_ok()
}

fn find_bip39_index(word: &str) -> Result<u16, PolyseedError> {
    let lower = word.to_lowercase();
    if let Some(idx) = BIP39_WORDLIST.iter().position(|&w| w == lower) {
        return Ok(idx as u16);
    }
    // The first 4 characters uniquely identify a BIP39 word.
    if lower.len() >= 4 {
        let prefix: String = lower.chars().take(4).collect();
        let matches: Vec<usize> = BIP39_WORDLIST
            .iter()
            .enumerate()
            .filter(|(_, w)| w.starts_with(&prefix))
            .map(|(i, _)| i)
            .collect();
        if matches.len() == 1 {
            return Ok(matches[0] as u16);
        }
    }
    Err(PolyseedError::UnknownWord(word.to_string()))
}

/// Convert a wallet birthday (unix timestamp) to an approximate scan height.
///
/// Deliberately approximate (linear from genesis): the polyseed birthday has
/// month resolution, and the scanner re-checks every block from here anyway.
pub fn birthday_to_height(timestamp: u64) -> u64 {
    const GENESIS_TIME: u64 = 1397865600;
    const SECONDS_PER_BLOCK: u64 = 120;
    if timestamp <= GENESIS_TIME {
        return 0;
    }
    (timestamp - GENESIS_TIME) / SECONDS_PER_BLOCK
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 / PBKDF2 (sha2 0.10, compatible with the monero crate)
// ---------------------------------------------------------------------------

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let block_size = 64;
    let mut padded_key = vec![0u8; block_size];
    if key.len() > block_size {
        let hash = Sha256::digest(key);
        padded_key[..32].copy_from_slice(&hash);
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    for &byte in padded_key.iter().take(block_size) {
        inner.update([byte ^ 0x36]);
    }
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    for &byte in padded_key.iter().take(block_size) {
        outer.update([byte ^ 0x5c]);
    }
    outer.update(inner_hash);
    let result = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// PBKDF2-HMAC-SHA256 (single block, dkLen=32).
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut salt_with_index = salt.to_vec();
    salt_with_index.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha256(password, &salt_with_index);
    let mut result = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for j in 0..32 {
            result[j] ^= u[j];
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector from the reference implementation (tevador/polyseed
    /// tests/tests.c): Monero coin, features 0, created at unix 1638446400
    /// (Dec 2021, birthday units = 1).
    const GOLDEN_PHRASE: &str = "raven tail swear infant grief assist regular lamp \
                                 duck valid someone little harsh puppy airport language";

    fn golden_coeff() -> [u16; POLYSEED_WORDS] {
        let words: Vec<&str> = GOLDEN_PHRASE.split_whitespace().collect();
        assert_eq!(words.len(), POLYSEED_WORDS);
        let mut coeff = [0u16; POLYSEED_WORDS];
        for (i, w) in words.iter().enumerate() {
            coeff[i] = find_bip39_index(w).unwrap();
        }
        coeff
    }

    #[test]
    fn test_golden_vector_checksum_and_fields() {
        let coeff = golden_coeff();
        assert_eq!(gf_poly_eval(&coeff), 0, "GF checksum must hold");
        let data = poly_to_data(&coeff);
        assert_eq!(data.features, 0);
        assert_eq!(data.birthday, 1); // 1638446400 -> 1 unit past EPOCH
    }

    #[test]
    fn test_golden_vector_decodes() {
        let (key, birthday) = polyseed_to_key(GOLDEN_PHRASE).expect("golden phrase must decode");
        assert_eq!(birthday, EPOCH + TIME_STEP);
        assert!(monero::util::key::PrivateKey::from_slice(&key).is_ok());
        // Deterministic.
        assert_eq!(polyseed_to_key(GOLDEN_PHRASE).unwrap().0, key);
    }

    #[test]
    fn test_generate_roundtrip() {
        let (words, key, birthday) = generate_polyseed();
        assert_eq!(words.len(), POLYSEED_WORDS);
        assert!(words.iter().all(|w| is_valid_bip39_word(w)));
        let (key2, birthday2) = polyseed_to_key(&words.join(" ")).unwrap();
        assert_eq!(key, key2);
        assert_eq!(birthday, birthday2);
    }

    #[test]
    fn test_single_word_corruption_detected() {
        let mut words: Vec<&str> = GOLDEN_PHRASE.split_whitespace().collect();
        words[5] = if words[5] == "abandon" {
            "ability"
        } else {
            "abandon"
        };
        assert_eq!(
            polyseed_to_key(&words.join(" ")),
            Err(PolyseedError::InvalidChecksum)
        );
    }

    #[test]
    fn test_feature_bits_rejected() {
        let data = PolyseedData {
            secret: [7u8; SECRET_SIZE],
            features: 1,
            birthday: 42,
        };
        let mut coeff = data_to_poly(&data);
        coeff[0] = gf_poly_eval(&coeff);
        let words: Vec<String> = coeff
            .iter()
            .map(|&i| BIP39_WORDLIST[i as usize].to_string())
            .collect();
        assert_eq!(
            polyseed_to_key(&words.join(" ")),
            Err(PolyseedError::UnsupportedFeatures)
        );
    }

    #[test]
    fn test_data_poly_roundtrip() {
        let mut secret = [0xABu8; SECRET_SIZE];
        secret[SECRET_SIZE - 1] &= 0x3f; // 150 bits
        let data = PolyseedData {
            secret,
            features: 0,
            birthday: 1023,
        };
        let coeff = data_to_poly(&data);
        let back = poly_to_data(&coeff);
        assert_eq!(back.secret, secret);
        assert_eq!(back.features, 0);
        assert_eq!(back.birthday, 1023);
    }

    #[test]
    fn test_checksum_detects_any_digit_flip() {
        let data = PolyseedData {
            secret: [0x11; SECRET_SIZE],
            features: 0,
            birthday: 7,
        };
        let mut coeff = data_to_poly(&data);
        coeff[0] = gf_poly_eval(&coeff);
        assert_eq!(gf_poly_eval(&coeff), 0);
        for (i, slot) in coeff.iter().enumerate() {
            let mut bad = coeff;
            bad[i] = slot ^ 1;
            assert_ne!(gf_poly_eval(&bad), 0, "digit {i} flip not detected");
        }
    }

    #[test]
    fn test_birthday_encode_decode() {
        assert_eq!(birthday_encode(0), 0);
        assert_eq!(birthday_encode(EPOCH - 1), 0);
        assert_eq!(birthday_encode(EPOCH), 0);
        assert_eq!(birthday_encode(EPOCH + TIME_STEP), 1);
        assert_eq!(birthday_encode(1638446400), 1); // reference test time
        assert_eq!(birthday_decode(0), EPOCH);
        assert_eq!(birthday_decode(1), EPOCH + TIME_STEP);
    }

    #[test]
    fn test_keygen_domain_separation() {
        let secret = [3u8; SECRET_SIZE];
        let base = polyseed_keygen(&secret, 1, 0);
        assert_eq!(base, polyseed_keygen(&secret, 1, 0));
        assert_ne!(base, polyseed_keygen(&secret, 2, 0));
        assert_ne!(base, polyseed_keygen(&secret, 1, 1));
    }

    #[test]
    fn test_pbkdf2_rfc6070() {
        // RFC 6070 PBKDF2-HMAC-SHA256 vectors.
        let dk = pbkdf2_hmac_sha256(b"password", b"salt", 1);
        assert_eq!(
            hex::encode(dk),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        let dk2 = pbkdf2_hmac_sha256(b"password", b"salt", 2);
        assert_eq!(
            hex::encode(dk2),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
    }

    #[test]
    fn test_birthday_to_height() {
        assert_eq!(birthday_to_height(0), 0);
        assert_eq!(birthday_to_height(1397865600), 0);
        assert_eq!(birthday_to_height(1397865600 + 86400), 720);
    }

    #[test]
    fn test_wordlist_and_autocomplete() {
        assert_eq!(BIP39_WORDLIST.len(), 2048);
        assert!(polyseed_autocomplete("aban").contains(&"abandon"));
        assert!(polyseed_autocomplete("").is_empty());
        assert!(is_valid_bip39_word("abandon"));
        assert!(!is_valid_bip39_word("zzzz"));
        // Prefixes >= 4 chars that uniquely identify a word are accepted.
        assert!(is_valid_bip39_word("notable"));
        // 4-char prefix resolves uniquely.
        assert_eq!(
            find_bip39_index("aban").unwrap(),
            find_bip39_index("abandon").unwrap()
        );
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", PolyseedError::InvalidWordCount(5)),
            "Expected 16 words, got 5"
        );
        assert_eq!(
            format!("{}", PolyseedError::UnknownWord("foo".into())),
            "Unknown BIP39 word: 'foo'"
        );
        assert_eq!(
            format!("{}", PolyseedError::InvalidChecksum),
            "Invalid Polyseed checksum"
        );
        assert_eq!(
            format!("{}", PolyseedError::UnsupportedFeatures),
            "Unsupported feature bits"
        );
    }

    #[test]
    fn test_word_count_error() {
        assert_eq!(
            polyseed_to_key("abandon abandon"),
            Err(PolyseedError::InvalidWordCount(2))
        );
    }
}
