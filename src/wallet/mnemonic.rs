//! Monero standard mnemonic seed phrase support (25-word format).
//!
//! Implements the official Monero mnemonic encoding/decoding as used by
//! monero-project/monero (`src/mnemonics/electrum-words.cpp`). Each group of
//! 3 words encodes 4 bytes of the 32-byte seed; the 25th word is a checksum:
//! a repetition of one of the phrase's own 24 words, at position
//! `crc32(3-char prefixes of the 24 words) % 24`. Because both the wordlist
//! (`words_en.rs`, from `src/mnemonics/english.h`) and the checksum rule match
//! upstream exactly, phrases generated here pass the Electrum wordlist check
//! in the official GUI/CLI and vice versa.
//!
//! The seed phrase is the wallet's master secret: it is rendered exactly
//! once, on the wizard's backup screen, and is never written to logs or any
//! other console output.

/// The 1626-word English wordlist for Monero mnemonics.
const WORDLIST: &[&str] = &include!("words_en.rs");

/// Number of words in a seed phrase without checksum.
const SEED_LENGTH: usize = 24;
/// Number of words in a seed phrase with checksum.
const SEED_LENGTH_WITH_CHECKSUM: usize = 25;
/// Unique prefix length for English word matching.
const PREFIX_LENGTH: usize = 3;

/// Errors that can occur when working with mnemonics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MnemonicError {
    /// Wrong number of words.
    InvalidWordCount(usize),
    /// A word is not in the wordlist.
    UnknownWord(String),
    /// Checksum verification failed.
    InvalidChecksum,
    /// The decoded bytes don't form a valid scalar.
    InvalidSeed,
}

impl std::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWordCount(n) => write!(f, "Expected 25 words, got {}", n),
            Self::UnknownWord(w) => write!(f, "Unknown word: '{}'", w),
            Self::InvalidChecksum => write!(f, "Invalid checksum word"),
            Self::InvalidSeed => write!(f, "Decoded seed is not a valid scalar"),
        }
    }
}

impl std::error::Error for MnemonicError {}

/// Encode a 32-byte seed into a 25-word mnemonic phrase.
pub fn seed_to_mnemonic(seed: &[u8; 32]) -> Vec<String> {
    let mut words = Vec::with_capacity(SEED_LENGTH_WITH_CHECKSUM);
    let n = WORDLIST.len();

    // Process 4 bytes at a time → 3 words
    for chunk in seed.chunks(4) {
        let val = u32::from_le_bytes([
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
            chunk.get(3).copied().unwrap_or(0),
        ]);

        let w1 = (val % n as u32) as usize;
        let w2 = ((val / n as u32 + w1 as u32) % n as u32) as usize;
        let w3 = ((val / (n as u32 * n as u32) + w2 as u32) % n as u32) as usize;

        words.push(WORDLIST[w1].to_string());
        words.push(WORDLIST[w2].to_string());
        words.push(WORDLIST[w3].to_string());
    }

    // Add checksum word: a repetition of one of the phrase's own 24 words,
    // at position crc32(3-char prefixes of the 24 words) % 24 — exactly as
    // electrum-words.cpp bytes_to_words does. The official GUI/CLI rejects
    // phrases whose 25th word is anything else.
    let checksum_idx = checksum_index(&words);
    let checksum_word = words[checksum_idx].clone();
    words.push(checksum_word);

    words
}

/// Decode a 25-word mnemonic phrase back to a 32-byte seed.
pub fn mnemonic_to_seed(words_str: &str) -> Result<[u8; 32], MnemonicError> {
    let words: Vec<&str> = words_str.split_whitespace().collect();

    if words.len() != SEED_LENGTH_WITH_CHECKSUM {
        return Err(MnemonicError::InvalidWordCount(words.len()));
    }

    // Resolve each word to its index (using prefix matching)
    let mut indices = Vec::with_capacity(SEED_LENGTH_WITH_CHECKSUM);
    for word in &words {
        let idx = find_word_index(word)?;
        indices.push(idx);
    }

    // Verify checksum: the 25th word must repeat the phrase word at position
    // crc32(3-char prefixes of the 24 words) % 24 (electrum-words.cpp
    // words_to_bytes). Compare 3-char prefixes, as the official code does.
    let checksum_pos = checksum_index_from_indices(&indices[..SEED_LENGTH]);
    let expected_prefix = prefix_of(WORDLIST[indices[checksum_pos]]);
    let actual_prefix = prefix_of(words[SEED_LENGTH]);

    if actual_prefix != expected_prefix
        && actual_prefix != legacy_checksum_prefix(&indices[..SEED_LENGTH])
    {
        return Err(MnemonicError::InvalidChecksum);
    }

    // Decode indices back to bytes
    let mut seed = [0u8; 32];
    let n = WORDLIST.len();

    for i in 0..8 {
        let base = i * 3;
        let w1 = indices[base];
        let w2 = indices[base + 1];
        let w3 = indices[base + 2];

        let val = w1 as u64
            + n as u64
                * (((n as u64 + w2 as u64 - w1 as u64) % n as u64)
                    + n as u64 * ((n as u64 + w3 as u64 - w2 as u64) % n as u64));

        let bytes = (val as u32).to_le_bytes();
        seed[i * 4] = bytes[0];
        seed[i * 4 + 1] = bytes[1];
        seed[i * 4 + 2] = bytes[2];
        seed[i * 4 + 3] = bytes[3];
    }

    Ok(seed)
}

/// Get autocomplete suggestions for a partial word input.
pub fn autocomplete(prefix: &str) -> Vec<&'static str> {
    if prefix.is_empty() {
        return Vec::new();
    }
    let lower = prefix.to_lowercase();
    WORDLIST
        .iter()
        .filter(|w| w.starts_with(&lower))
        .copied()
        .collect()
}

/// Check if a word (or its prefix) matches a valid wordlist entry.
pub fn is_valid_word(word: &str) -> bool {
    find_word_index(word).is_ok()
}

/// Find the index of a word in the wordlist, supporting prefix matching.
fn find_word_index(word: &str) -> Result<usize, MnemonicError> {
    let lower = word.to_lowercase();

    // Exact match first
    if let Some(idx) = WORDLIST.iter().position(|&w| w == lower) {
        return Ok(idx);
    }

    // Prefix match (must be unique within prefix length)
    if lower.len() >= PREFIX_LENGTH {
        let prefix: String = lower.chars().take(PREFIX_LENGTH).collect();
        let matches: Vec<usize> = WORDLIST
            .iter()
            .enumerate()
            .filter(|(_, w)| w.starts_with(&prefix))
            .map(|(i, _)| i)
            .collect();

        if matches.len() == 1 {
            return Ok(matches[0]);
        }
    }

    Err(MnemonicError::UnknownWord(word.to_string()))
}

/// Compute the checksum word position (0..24) from the 24 seed words.
fn checksum_index(words: &[String]) -> usize {
    let indices: Vec<usize> = words.iter().map(|w| find_word_index(w).unwrap()).collect();
    checksum_index_from_indices(&indices)
}

/// The 3-character unique prefix of a word, as used for checksum input and
/// prefix matching (mirrors electrum-words' trimmed words).
fn prefix_of(word: &str) -> String {
    word.chars().take(PREFIX_LENGTH).collect()
}

/// Official checksum: CRC32 over the concatenated 3-character prefixes of the
/// 24 words, modulo 24. The result indexes the phrase's OWN first 24 words —
/// that word is repeated as the 25th (monero-project/monero
/// src/mnemonics/electrum-words.cpp `words_checksum`).
fn checksum_index_from_indices(indices: &[usize]) -> usize {
    debug_assert_eq!(indices.len(), SEED_LENGTH);
    let mut trimmed = String::new();
    for &idx in indices {
        trimmed.push_str(&prefix_of(WORDLIST[idx]));
    }

    let crc = crc32(trimmed.as_bytes());
    (crc as usize) % SEED_LENGTH
}

/// Legacy muff checksum acceptance: releases before the GUI-compatibility fix
/// used `crc32(prefixes) % WORDLIST.len()` (a wordlist index) as the 25th
/// word. That is incompatible with the official wallets, but self-consistent
/// within muff, so phrases generated by those releases restore to the same
/// 32-byte seed here. Accept them on restore (the checksum word plays no role
/// in decoding) so existing muff wallets stay recoverable; newly generated
/// wallets always get the official checksum word.
fn legacy_checksum_prefix(indices: &[usize]) -> String {
    let mut trimmed = String::new();
    for &idx in indices {
        trimmed.push_str(&prefix_of(WORDLIST[idx]));
    }

    let crc = crc32(trimmed.as_bytes());
    prefix_of(WORDLIST[(crc as usize) % WORDLIST.len()])
}

/// Simple CRC32 implementation (IEEE 802.3 polynomial).
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFFFFFF
}

/// Generate a new random seed and return both the seed bytes and mnemonic.
///
/// Mirrors wallet2 wallet creation: draw 32 random bytes, `sc_reduce32` them
/// to a canonical ed25519 scalar, and use those reduced bytes both as the
/// private spend key and as the entropy encoded into the 25-word phrase — so
/// the phrase restores to the same address in the official GUI/CLI.
pub fn generate_mnemonic_seed() -> ([u8; 32], Vec<String>) {
    let seed = super::keys::generate_seed();
    let reduced = super::keys::sc_reduce32(&seed);
    let mnemonic = seed_to_mnemonic(&reduced);
    (reduced, mnemonic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::keys::sc_reduce32;

    #[test]
    fn test_wordlist_size() {
        assert_eq!(WORDLIST.len(), 1626);
    }

    #[test]
    fn test_wordlist_no_duplicates() {
        let mut sorted = WORDLIST.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            WORDLIST.len(),
            "Wordlist contains duplicate entries"
        );
    }

    #[test]
    fn test_wordlist_no_empty_strings() {
        for (i, word) in WORDLIST.iter().enumerate() {
            assert!(!word.is_empty(), "Word at index {} is empty", i);
        }
    }

    #[test]
    fn test_roundtrip_all_zeros_seed() {
        let seed = sc_reduce32(&[0u8; 32]);
        let mnemonic = seed_to_mnemonic(&seed);
        assert_eq!(mnemonic.len(), 25);
        let decoded = mnemonic_to_seed(&mnemonic.join(" ")).unwrap();
        assert_eq!(seed, decoded);
    }

    #[test]
    fn test_roundtrip_all_ones_seed() {
        let seed = sc_reduce32(&[0xFF; 32]);
        let mnemonic = seed_to_mnemonic(&seed);
        assert_eq!(mnemonic.len(), 25);
        let decoded = mnemonic_to_seed(&mnemonic.join(" ")).unwrap();
        assert_eq!(seed, decoded);
    }

    #[test]
    fn test_roundtrip_sequential_seed() {
        let mut raw = [0u8; 32];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        let seed = sc_reduce32(&raw);
        let mnemonic = seed_to_mnemonic(&seed);
        let decoded = mnemonic_to_seed(&mnemonic.join(" ")).unwrap();
        assert_eq!(seed, decoded);
    }

    #[test]
    fn test_roundtrip_multiple_seeds() {
        let test_seeds: Vec<[u8; 32]> = vec![
            [1u8; 32],
            [0xAA; 32],
            [0x55; 32],
            {
                let mut s = [0u8; 32];
                s[0] = 0xFF;
                s[31] = 0xFF;
                s
            },
            {
                let mut s = [0u8; 32];
                s[15] = 0x80;
                s
            },
        ];
        for raw in test_seeds {
            let seed = sc_reduce32(&raw);
            let mnemonic = seed_to_mnemonic(&seed);
            assert_eq!(mnemonic.len(), 25);
            let decoded = mnemonic_to_seed(&mnemonic.join(" ")).unwrap();
            assert_eq!(seed, decoded, "Roundtrip failed for seed {:?}", raw);
        }
    }

    #[test]
    fn test_mnemonic_is_25_words() {
        let seed = sc_reduce32(&[42u8; 32]);
        let mnemonic = seed_to_mnemonic(&seed);
        assert_eq!(mnemonic.len(), SEED_LENGTH_WITH_CHECKSUM);
    }

    #[test]
    fn test_mnemonic_all_words_in_wordlist() {
        let seed = sc_reduce32(&[77u8; 32]);
        let mnemonic = seed_to_mnemonic(&seed);
        for word in &mnemonic {
            assert!(
                WORDLIST.contains(&word.as_str()),
                "Word '{}' not in wordlist",
                word
            );
        }
    }

    #[test]
    fn test_autocomplete_exact_match() {
        let results = autocomplete("abbey");
        assert!(results.contains(&"abbey"));
    }

    #[test]
    fn test_autocomplete_prefix() {
        let results = autocomplete("abb");
        assert!(results.contains(&"abbey"));
    }

    #[test]
    fn test_autocomplete_single_char() {
        let results = autocomplete("a");
        assert!(!results.is_empty());
        for w in &results {
            assert!(w.starts_with('a'));
        }
    }

    #[test]
    fn test_autocomplete_empty() {
        assert!(autocomplete("").is_empty());
    }

    #[test]
    fn test_autocomplete_no_match() {
        assert!(autocomplete("zzz").is_empty());
        assert!(autocomplete("xyz").is_empty());
    }

    #[test]
    fn test_autocomplete_case_insensitive() {
        let lower = autocomplete("abb");
        let upper = autocomplete("ABB");
        assert_eq!(lower, upper);
    }

    #[test]
    fn test_is_valid_word() {
        assert!(is_valid_word("abbey"));
        assert!(is_valid_word("ability"));
        assert!(!is_valid_word("zzzznotvalid"));
        assert!(!is_valid_word(""));
    }

    #[test]
    fn test_is_valid_word_prefix() {
        assert!(is_valid_word("abb")); // abbey
    }

    #[test]
    fn test_invalid_word_count_zero() {
        assert!(matches!(
            mnemonic_to_seed(""),
            Err(MnemonicError::InvalidWordCount(0))
        ));
    }

    #[test]
    fn test_invalid_word_count_24() {
        let seed = sc_reduce32(&[42u8; 32]);
        let mnemonic = seed_to_mnemonic(&seed);
        let without_checksum = &mnemonic[..24].join(" ");
        assert!(matches!(
            mnemonic_to_seed(without_checksum),
            Err(MnemonicError::InvalidWordCount(24))
        ));
    }

    #[test]
    fn test_invalid_word_count_26() {
        let seed = sc_reduce32(&[42u8; 32]);
        let mut mnemonic = seed_to_mnemonic(&seed);
        mnemonic.push("abbey".to_string());
        assert!(matches!(
            mnemonic_to_seed(&mnemonic.join(" ")),
            Err(MnemonicError::InvalidWordCount(26))
        ));
    }

    #[test]
    fn test_unknown_word_error() {
        let seed = sc_reduce32(&[42u8; 32]);
        let mut mnemonic = seed_to_mnemonic(&seed);
        mnemonic[0] = "zzzznotaword".to_string();
        assert!(matches!(
            mnemonic_to_seed(&mnemonic.join(" ")),
            Err(MnemonicError::UnknownWord(_))
        ));
    }

    #[test]
    fn test_bad_checksum_detected() {
        let seed = sc_reduce32(&[42u8; 32]);
        let mut mnemonic = seed_to_mnemonic(&seed);
        let original_prefix = prefix_of(&mnemonic[24]);
        let indices: Vec<usize> = mnemonic[..24]
            .iter()
            .map(|w| find_word_index(w).unwrap())
            .collect();
        let legacy_prefix = legacy_checksum_prefix(&indices);
        // Find a replacement word whose 3-char prefix satisfies NEITHER the
        // official nor the legacy checksum rule.
        let replacement = WORDLIST
            .iter()
            .find(|w| prefix_of(w) != original_prefix && prefix_of(w) != legacy_prefix)
            .expect("wordlist must contain a non-matching word");
        mnemonic[24] = replacement.to_string();
        let result = mnemonic_to_seed(&mnemonic.join(" "));
        assert!(matches!(result, Err(MnemonicError::InvalidChecksum)));
    }

    /// Regression test for the GUI-compatibility bug: the 25th word must be
    /// a repetition of one of the phrase's own 24 words (official rule),
    /// not an arbitrary wordlist entry.
    #[test]
    fn test_checksum_word_repeats_a_phrase_word() {
        for fill in [0u8, 1, 42, 99, 0xFF] {
            let seed = sc_reduce32(&[fill; 32]);
            let mnemonic = seed_to_mnemonic(&seed);
            assert!(
                mnemonic[..24].contains(&mnemonic[24]),
                "checksum word '{}' is not one of the 24 seed words",
                mnemonic[24]
            );
        }
    }

    /// Phrases generated by pre-fix muff releases (checksum word =
    /// wordlist[crc % 1626]) must still restore here.
    #[test]
    fn test_legacy_checksum_phrase_still_accepted() {
        for fill in [7u8, 42, 99, 123] {
            let seed = sc_reduce32(&[fill; 32]);
            let mut mnemonic = seed_to_mnemonic(&seed);
            let indices: Vec<usize> = mnemonic[..24]
                .iter()
                .map(|w| find_word_index(w).unwrap())
                .collect();
            let legacy_prefix = legacy_checksum_prefix(&indices);
            let legacy_word = WORDLIST
                .iter()
                .find(|w| prefix_of(w) == legacy_prefix)
                .unwrap()
                .to_string();
            if legacy_word == mnemonic[24] {
                // Legacy and official words coincide for this seed; try the
                // next fixture so the test actually exercises the fallback.
                continue;
            }
            mnemonic[24] = legacy_word;
            let decoded =
                mnemonic_to_seed(&mnemonic.join(" ")).expect("legacy-checksum phrase must restore");
            assert_eq!(decoded, seed);
            return;
        }
        panic!("test fixtures all coincided with the official checksum word");
    }

    #[test]
    fn test_crc32_known_vectors() {
        assert_eq!(crc32(b""), 0x00000000);
        assert_eq!(crc32(b"a"), 0xE8B7BE43);
        assert_eq!(crc32(b"abc"), 0x352441C2);
        assert_eq!(crc32(b"message digest"), 0x20159D7F);
        assert_eq!(crc32(b"abcdefghijklmnopqrstuvwxyz"), 0x4C2750BD);
    }

    #[test]
    fn test_checksum_deterministic() {
        let seed = sc_reduce32(&[99u8; 32]);
        let m1 = seed_to_mnemonic(&seed);
        let m2 = seed_to_mnemonic(&seed);
        assert_eq!(m1, m2, "Same seed must produce same mnemonic");
    }

    #[test]
    fn test_different_seeds_different_mnemonics() {
        let s1 = sc_reduce32(&[1u8; 32]);
        let s2 = sc_reduce32(&[2u8; 32]);
        let m1 = seed_to_mnemonic(&s1);
        let m2 = seed_to_mnemonic(&s2);
        assert_ne!(m1, m2);
    }

    #[test]
    fn test_generate_produces_valid_mnemonic() {
        let (seed, mnemonic) = generate_mnemonic_seed();
        assert_eq!(mnemonic.len(), 25);
        let decoded = mnemonic_to_seed(&mnemonic.join(" ")).unwrap();
        assert_eq!(seed, decoded);
    }

    #[test]
    fn test_generate_produces_unique_seeds() {
        let (s1, _) = generate_mnemonic_seed();
        let (s2, _) = generate_mnemonic_seed();
        assert_ne!(s1, s2, "Two generated seeds should differ");
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", MnemonicError::InvalidWordCount(3)),
            "Expected 25 words, got 3"
        );
        assert_eq!(
            format!("{}", MnemonicError::UnknownWord("foo".into())),
            "Unknown word: 'foo'"
        );
        assert_eq!(
            format!("{}", MnemonicError::InvalidChecksum),
            "Invalid checksum word"
        );
        assert_eq!(
            format!("{}", MnemonicError::InvalidSeed),
            "Decoded seed is not a valid scalar"
        );
    }

    #[test]
    fn test_whitespace_handling() {
        let seed = sc_reduce32(&[42u8; 32]);
        let mnemonic = seed_to_mnemonic(&seed);
        let spaced = mnemonic.join("   ");
        let decoded = mnemonic_to_seed(&spaced).unwrap();
        assert_eq!(seed, decoded);
    }

    #[test]
    fn test_find_word_index_full_word() {
        let idx = find_word_index("abbey").unwrap();
        assert_eq!(WORDLIST[idx], "abbey");
    }

    #[test]
    fn test_find_word_index_prefix() {
        let idx = find_word_index("abb").unwrap();
        assert_eq!(WORDLIST[idx], "abbey");
    }

    #[test]
    fn test_find_word_index_unknown() {
        assert!(find_word_index("zzzzz").is_err());
    }

    #[test]
    fn test_sc_reduce32_canonical_unchanged() {
        // [1u8; 32] as a little-endian integer is well below the group order
        // l (top byte 0x01 < 0x10), so reduction is a no-op.
        let bytes = [1u8; 32];
        assert_eq!(sc_reduce32(&bytes), bytes);
    }

    #[test]
    fn test_sc_reduce32_reduces_noncanonical() {
        // 0xFFFF...FF >> l, so it must be reduced, deterministically and
        // idempotently (this is wallet2's sc_reduce32 behavior).
        let high = [0xFFu8; 32];
        let reduced = sc_reduce32(&high);
        assert_ne!(reduced, high);
        assert_eq!(sc_reduce32(&high), reduced);
        assert_eq!(sc_reduce32(&reduced), reduced);
    }
}
