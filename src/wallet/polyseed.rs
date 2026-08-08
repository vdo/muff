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
///
/// The clamp is applied in `u64`: narrowing first would let a clock set far
/// enough ahead (>= 2^32 time steps past the epoch) wrap to a small value
/// instead of saturating at `DATE_MASK`.
fn birthday_encode(time: u64) -> u16 {
    if time == u64::MAX || time < EPOCH {
        return 0;
    }
    ((time - EPOCH) / TIME_STEP).min(DATE_MASK as u64) as u16
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

    /// Cross-implementation KDF vector: a phrase and the exact 32 bytes
    /// `polyseed_keygen` must produce for it.
    ///
    /// Origin: monero-oxide/monero-wallet-util `polyseed/src/tests.rs`,
    /// `test_key`. tevador/polyseed's own `tests/tests.c` calls
    /// `polyseed_keygen` but never compares its output to a constant, so this
    /// Rust reference — maintained alongside the `monero-wallet` crate this
    /// wallet depends on — is the usable source of a pinned key.
    ///
    /// This covers everything the existing golden-phrase test does not: the
    /// `"POLYSEED key"` salt layout (including the 0xff domain bytes at
    /// 13..16 and the little-endian coin/birthday/features at 16..28), the
    /// 10 000-iteration PBKDF2-HMAC-SHA256, and the secret's zero-padding to
    /// 32 bytes. A mistake in any of those still yields a valid-looking
    /// private key, so without a pinned vector the failure mode is silent:
    /// seeds written down from muff would not restore in Feather/Cake.
    ///
    /// Note the reference exposes the RAW KDF output, before the reduction
    /// mod l that produces a Monero spend key — byte 31 here is 0x7e, well
    /// above l's leading 0x10, so this value is not a canonical scalar.
    /// `data_to_key` applies `sc_reduce32` on top, which is asserted too.
    #[test]
    fn test_keygen_matches_reference_vector() {
        const PHRASE: &str = "comic blanket chair inject end snow rural improve cereal \
             better initial replace ribbon brother gather unaware";
        const RAW_KEY: [u8; 32] = [
            216, 82, 37, 164, 252, 122, 170, 61, 52, 152, 131, 26, 181, 226, 191, 131, 204, 3, 242,
            225, 229, 175, 37, 151, 18, 143, 53, 175, 136, 17, 47, 126,
        ];

        let words: Vec<&str> = PHRASE.split_whitespace().collect();
        assert_eq!(words.len(), POLYSEED_WORDS);
        let mut coeff = [0u16; POLYSEED_WORDS];
        for (i, word) in words.iter().enumerate() {
            coeff[i] = find_bip39_index(word).unwrap();
        }
        assert_eq!(
            gf_poly_eval(&coeff),
            0,
            "reference phrase checksum must hold"
        );

        let data = poly_to_data(&coeff);
        assert_eq!(data.features, 0);
        let raw = polyseed_keygen(&data.secret, data.birthday as u32, data.features as u32);
        assert_eq!(
            raw, RAW_KEY,
            "polyseed KDF diverged from the reference implementation"
        );

        // The public API returns the same value reduced to a canonical scalar.
        let (key, _) = polyseed_to_key(PHRASE).expect("reference phrase must decode");
        assert_eq!(key, super::super::keys::sc_reduce32(&RAW_KEY));
        assert!(monero::util::key::PrivateKey::from_slice(&key).is_ok());
    }

    /// The 150-bit secret the golden phrase must decode to.
    ///
    /// Origin: monero-oxide/monero-wallet-util `polyseed/src/tests.rs`,
    /// `test_polyseed`, the `Language::English` vector (`entropy` field, which
    /// is the 19-byte secret zero-padded to 32 bytes).
    #[test]
    fn test_golden_vector_entropy_matches_reference() {
        const ENTROPY: &str = "dd76e7359a0ded37cd0ff0f3c829a5ae01673300000000000000000000000000";

        let coeff = golden_coeff();
        let data = poly_to_data(&coeff);
        let expected = hex::decode(ENTROPY).unwrap();
        assert_eq!(
            data.secret[..],
            expected[..SECRET_SIZE],
            "decoded secret diverged from the reference implementation"
        );
        assert!(
            expected[SECRET_SIZE..].iter().all(|b| *b == 0),
            "reference entropy must be zero-padded past the 19-byte secret"
        );
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

    /// Random secrets must survive the full words round trip: packing,
    /// checksum, wordlist mapping and unpacking.
    ///
    /// The checksum digit and the bit-packing both depend on the secret, so a
    /// packing edge case (a carry across a byte boundary, the 6-bit tail in
    /// `secret[18]`, a birthday at the 10-bit limit) can hide behind any one
    /// fixture — and a failure means a user could write down 16 words that do
    /// not restore. `test_data_poly_roundtrip` covers one fixed secret; this
    /// samples fresh ones every run so coverage accumulates across CI runs.
    ///
    /// Deliberately skips `data_to_key`: the KDF is pinned exactly by
    /// `test_keygen_matches_reference_vector`, and running two
    /// 10 000-iteration PBKDF2 derivations per sample would dominate the
    /// runtime of the whole suite for no added coverage of the packing.
    #[test]
    fn test_random_secrets_always_roundtrip_through_words() {
        use rand::RngCore;

        for i in 0..1_000 {
            let mut secret = [0u8; SECRET_SIZE];
            rand::thread_rng().fill_bytes(&mut secret);
            secret[SECRET_SIZE - 1] &= 0x3f; // exactly 150 bits
            let birthday = (rand::random::<u32>() & DATE_MASK) as u16;

            let data = PolyseedData {
                secret,
                features: 0,
                birthday,
            };
            let mut coeff = data_to_poly(&data);
            coeff[0] = gf_poly_eval(&coeff);

            let phrase = coeff
                .iter()
                .map(|&idx| BIP39_WORDLIST[idx as usize])
                .collect::<Vec<_>>()
                .join(" ");

            // Re-derive the digits from the words, exactly as decoding does.
            let mut parsed = [0u16; POLYSEED_WORDS];
            for (slot, word) in parsed.iter_mut().zip(phrase.split_whitespace()) {
                *slot = find_bip39_index(word)
                    .unwrap_or_else(|e| panic!("iteration {i}: {e} in {phrase}"));
            }
            assert_eq!(
                parsed, coeff,
                "iteration {i}: word mapping is not injective"
            );
            assert_eq!(
                gf_poly_eval(&parsed),
                0,
                "iteration {i}: checksum does not verify for {phrase}"
            );

            let back = poly_to_data(&parsed);
            assert_eq!(back.secret, secret, "iteration {i}: secret mismatch");
            assert_eq!(back.features, 0, "iteration {i}: features mismatch");
            assert_eq!(back.birthday, birthday, "iteration {i}: birthday mismatch");
        }
    }

    /// End-to-end check that a freshly generated phrase restores to the same
    /// key and birthday. Kept to a few samples because each iteration runs
    /// two 10 000-iteration PBKDF2 derivations; the packing itself is covered
    /// far more broadly by `test_random_secrets_always_roundtrip_through_words`.
    #[test]
    fn test_generated_seeds_always_roundtrip() {
        for i in 0..4 {
            let (words, key, birthday) = generate_polyseed();
            let phrase = words.join(" ");
            match polyseed_to_key(&phrase) {
                Ok((decoded_key, decoded_birthday)) => {
                    assert_eq!(decoded_key, key, "iteration {i}: key mismatch for {phrase}");
                    assert_eq!(
                        decoded_birthday, birthday,
                        "iteration {i}: birthday mismatch for {phrase}"
                    );
                }
                Err(e) => panic!("iteration {i}: generated polyseed rejected ({e}): {phrase}"),
            }
        }
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

    /// BIP39's defining property for prefix matching: truncating each word to
    /// its first 4 characters (or the whole word, when shorter) must be
    /// injective. `find_bip39_index` accepts 4-char prefixes, so a collision
    /// would silently resolve a typo to the wrong word — changing the seed.
    #[test]
    fn test_bip39_four_char_prefixes_are_unique() {
        const BIP39_PREFIX_LEN: usize = 4;
        let mut seen: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::with_capacity(BIP39_WORDLIST.len());
        for (i, word) in BIP39_WORDLIST.iter().enumerate() {
            let key = &word[..word.len().min(BIP39_PREFIX_LEN)];
            if let Some(prev) = seen.insert(key, i) {
                panic!(
                    "'{}' and '{}' share the prefix '{}'",
                    BIP39_WORDLIST[prev], word, key
                );
            }
        }
    }

    /// Multiplication by 2 in GF(2^11) must be a permutation of the field.
    ///
    /// Doubling is invertible in any field of characteristic 2 (2 = x is a
    /// non-zero element), so this must map 0..2048 onto itself bijectively. A
    /// wrong reduction constant in `MUL2_TABLE` shows up immediately as a
    /// collision or an out-of-range result, which would silently weaken the
    /// checksum's error detection rather than break it outright.
    #[test]
    fn test_gf_elem_mul2_is_a_field_permutation() {
        let mut seen = vec![false; 2048];
        for x in 0u16..2048 {
            let doubled = gf_elem_mul2(x);
            assert!(
                doubled < 2048,
                "gf_elem_mul2({x}) = {doubled} escapes GF(2^11)"
            );
            assert!(
                !seen[doubled as usize],
                "gf_elem_mul2 is not injective at {x}"
            );
            seen[doubled as usize] = true;
        }
        assert_eq!(gf_elem_mul2(0), 0);
        // The reduction only kicks in at the top half of the field.
        assert_eq!(gf_elem_mul2(1023), 2046);
        assert_eq!(gf_elem_mul2(1024), MUL2_TABLE[0]);
    }

    /// Secret and birthday extremes must survive the packing round trip.
    ///
    /// The secret's last byte carries only 6 of the 150 bits and the birthday
    /// occupies exactly 10, so the all-zero and all-one patterns at both ends
    /// are where an off-by-one in the bit shuffling surfaces.
    #[test]
    fn test_secret_and_birthday_edges_roundtrip() {
        let mut all_ones = [0xffu8; SECRET_SIZE];
        all_ones[SECRET_SIZE - 1] = 0x3f; // 150 bits, top 2 cleared

        let mut low_bit = [0u8; SECRET_SIZE];
        low_bit[0] = 0x01;
        let mut high_bit = [0u8; SECRET_SIZE];
        high_bit[SECRET_SIZE - 1] = 0x20; // most significant retained bit

        let secrets = [
            [0u8; SECRET_SIZE],
            all_ones,
            low_bit,
            high_bit,
            [0xaau8; SECRET_SIZE],
            [0x55u8; SECRET_SIZE],
        ];
        let birthdays = [0u16, 1, 512, DATE_MASK as u16 - 1, DATE_MASK as u16];

        for secret in secrets {
            let mut secret = secret;
            secret[SECRET_SIZE - 1] &= 0x3f;
            for birthday in birthdays {
                let data = PolyseedData {
                    secret,
                    features: 0,
                    birthday,
                };
                let mut coeff = data_to_poly(&data);
                coeff[0] = gf_poly_eval(&coeff);
                assert_eq!(gf_poly_eval(&coeff), 0);
                assert!(
                    coeff.iter().all(|&c| (c as usize) < BIP39_WORDLIST.len()),
                    "digit escapes the wordlist for birthday {birthday}"
                );

                let back = poly_to_data(&coeff);
                assert_eq!(
                    back.secret, secret,
                    "secret mismatch at birthday {birthday}"
                );
                assert_eq!(back.birthday, birthday, "birthday mismatch");
                assert_eq!(back.features, 0, "features mismatch");
            }
        }
    }

    /// Every non-zero feature set must be refused, not silently ignored.
    ///
    /// Feature bit 0 marks a passphrase-encrypted seed; decoding one as if it
    /// were unencrypted would derive a wrong key and present an empty wallet
    /// rather than an error. Only the 5 feature bits exist, so all 31 non-zero
    /// combinations are enumerated.
    #[test]
    fn test_all_nonzero_feature_sets_rejected() {
        for features in 1u8..(1 << FEATURE_BITS) {
            let data = PolyseedData {
                secret: [0x24u8; SECRET_SIZE],
                features,
                birthday: 42,
            };
            let mut coeff = data_to_poly(&data);
            coeff[0] = gf_poly_eval(&coeff);
            let phrase = coeff
                .iter()
                .map(|&i| BIP39_WORDLIST[i as usize])
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(
                polyseed_to_key(&phrase),
                Err(PolyseedError::UnsupportedFeatures),
                "feature set {features:#07b} must be rejected"
            );
        }
    }

    /// Malformed input must produce the matching error rather than a key.
    #[test]
    fn test_malformed_input_rejected() {
        let (words, _, _) = generate_polyseed();

        assert_eq!(polyseed_to_key(""), Err(PolyseedError::InvalidWordCount(0)));
        assert_eq!(
            polyseed_to_key(&words[..POLYSEED_WORDS - 1].join(" ")),
            Err(PolyseedError::InvalidWordCount(POLYSEED_WORDS - 1))
        );
        let mut too_many = words.clone();
        too_many.push("abandon".to_string());
        assert_eq!(
            polyseed_to_key(&too_many.join(" ")),
            Err(PolyseedError::InvalidWordCount(POLYSEED_WORDS + 1))
        );

        let mut unknown = words.clone();
        unknown[3] = "zzzzzzzz".to_string();
        assert!(matches!(
            polyseed_to_key(&unknown.join(" ")),
            Err(PolyseedError::UnknownWord(_))
        ));

        // A word swapped for another valid word breaks the GF checksum.
        let mut swapped = words.clone();
        swapped[7] = if swapped[7] == "abandon" {
            "ability".to_string()
        } else {
            "abandon".to_string()
        };
        assert_eq!(
            polyseed_to_key(&swapped.join(" ")),
            Err(PolyseedError::InvalidChecksum)
        );

        // Transposing two distinct words also breaks it (the checksum is
        // position-dependent, not a sum).
        let mut transposed = words.clone();
        if transposed[2] != transposed[9] {
            transposed.swap(2, 9);
            assert_eq!(
                polyseed_to_key(&transposed.join(" ")),
                Err(PolyseedError::InvalidChecksum)
            );
        }
    }

    /// Capitalization, ragged whitespace and 4-char prefixes must all decode
    /// to the same key.
    #[test]
    fn test_equivalent_input_forms_decode_identically() {
        let (words, key, birthday) = generate_polyseed();
        let canonical = words.join(" ");

        for variant in [
            canonical.to_uppercase(),
            format!("  \t{}\n ", words.join("  \n\t ")),
            words
                .iter()
                .map(|w| w.chars().take(4).collect::<String>())
                .collect::<Vec<_>>()
                .join(" "),
        ] {
            let (decoded_key, decoded_birthday) = polyseed_to_key(&variant)
                .unwrap_or_else(|e| panic!("variant rejected ({e}): {variant}"));
            assert_eq!(decoded_key, key, "key mismatch for {variant}");
            assert_eq!(decoded_birthday, birthday, "birthday mismatch");
        }
    }

    /// Prefix matching resolves any input sharing a word's first 4 characters
    /// — including trailing garbage.
    ///
    /// Pinned because it is easy to mistake for a bug: "notabip39word" is
    /// accepted as "notable". This mirrors upstream polyseed, which compares
    /// words by their 4-character prefix rather than in full, and it is why
    /// the GF checksum (not word validation) is what actually catches typos.
    #[test]
    fn test_prefix_matching_accepts_overlong_input() {
        let notable = find_bip39_index("notable").unwrap();
        assert_eq!(find_bip39_index("nota").unwrap(), notable);
        assert_eq!(find_bip39_index("notabip39word").unwrap(), notable);
        assert_eq!(find_bip39_index("NoTaBlE").unwrap(), notable);

        // Input matching no word, or fewer than 4 characters of one, is not.
        assert!(find_bip39_index("zzzzzzzz").is_err());
        assert!(find_bip39_index("not").is_err());
    }

    /// The birthday clamp must saturate, not wrap.
    ///
    /// `birthday_encode` narrows to 10 bits; a clock set far enough ahead
    /// (>= 2^32 time steps past the epoch) truncated to a small value instead
    /// of saturating at `DATE_MASK` when the clamp was applied after the cast.
    #[test]
    fn test_birthday_encode_saturates_for_far_future_clocks() {
        assert_eq!(birthday_encode(EPOCH + DATE_MASK as u64 * TIME_STEP), 1023);
        assert_eq!(
            birthday_encode(EPOCH + (DATE_MASK as u64 + 1) * TIME_STEP),
            1023
        );
        // 2^32 time steps past the epoch: the value that used to wrap to 0.
        assert_eq!(birthday_encode(EPOCH + (1u64 << 32) * TIME_STEP), 1023);
        assert_eq!(birthday_encode(u64::MAX - 1), 1023);
        // The explicit sentinel and any pre-epoch time stay at 0.
        assert_eq!(birthday_encode(u64::MAX), 0);
        assert_eq!(birthday_encode(0), 0);
        assert_eq!(birthday_encode(EPOCH - 1), 0);
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
