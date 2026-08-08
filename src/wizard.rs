//! Interactive wallet setup wizard for the TUI.
//!
//! Runs before entering the main app to handle wallet creation or restoration.

use std::io::{self, Write};
use std::path::Path;

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode},
};

use zeroize::Zeroizing;

use crate::wallet;

/// Line writer that expands `\n` to `\r\n` so line-oriented output renders
/// correctly while the terminal is in raw mode (raw mode disables ONLCR).
struct RawWriter<W: Write>(W);

impl<W: Write> Write for RawWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut last = 0;
        for (i, &b) in buf.iter().enumerate() {
            if b == b'\n' {
                self.0.write_all(&buf[last..i])?;
                self.0.write_all(b"\r\n")?;
                last = i + 1;
            }
        }
        self.0.write_all(&buf[last..])?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Abort the wizard: restore the terminal and exit with the SIGINT exit code.
fn abort() -> ! {
    let _ = disable_raw_mode();
    println!("\nAborted.");
    std::process::exit(130);
}

/// Result of the wallet setup wizard.
pub struct WizardResult {
    pub keys: wallet::WalletKeys,
    /// Wrapped so the password is scrubbed from memory on drop.
    pub password: Zeroizing<String>,
    pub scan_height: u64,
    /// `true` when the wallet was newly created (no history can exist), so
    /// the caller should start scanning at the current chain tip instead of
    /// `scan_height` (which is 0 in this case).
    pub fresh: bool,
    /// For polyseed wallets: the original 16-word phrase (stored in the
    /// wallet db so it can be re-displayed later — it is not recoverable
    /// from the derived spend key). `None` for standard 25-word seeds.
    pub polyseed_phrase: Option<String>,
}

#[derive(PartialEq)]
enum WalletMode {
    Create,
    Restore,
}

/// Run the wallet setup wizard in the terminal (raw mode).
pub fn run_wizard(
    wallet_path: &Path,
    network: monero::Network,
) -> color_eyre::Result<WizardResult> {
    enable_raw_mode()?;
    let result = wizard_inner(wallet_path, network);
    disable_raw_mode()?;
    result
}

fn wizard_inner(_wallet_path: &Path, network: monero::Network) -> color_eyre::Result<WizardResult> {
    let stdout = io::stdout();
    let mut stdout = RawWriter(stdout);

    execute!(
        stdout,
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
    )?;
    write!(stdout, "\x1b[H")?;
    writeln!(stdout)?;
    writeln!(stdout, "  ╔══════════════════════════════════════╗")?;
    writeln!(stdout, "  ║         🧁 Muff Wallet Setup         ║")?;
    writeln!(stdout, "  ╚══════════════════════════════════════╝")?;
    writeln!(stdout)?;

    let mode = prompt_create_or_restore(&mut stdout)?;

    let (seed, scan_height, fresh, polyseed_phrase) = match mode {
        WalletMode::Create => {
            match prompt_seed_type(&mut stdout)? {
                SeedType::Standard => {
                    let (seed, mnemonic) = wallet::generate_mnemonic_seed();
                    display_new_seed(&mut stdout, &mnemonic)?;
                    // A brand-new wallet has no history; the caller replaces
                    // the scan height with the current chain tip at startup.
                    (seed, 0u64, true, None)
                }
                SeedType::Polyseed => {
                    let (mnemonic, seed, _birthday) = wallet::generate_polyseed();
                    display_new_seed(&mut stdout, &mnemonic)?;
                    (seed, 0u64, true, Some(mnemonic.join(" ")))
                }
            }
        }
        WalletMode::Restore => {
            let (seed, height, phrase) = prompt_seed_restore(&mut stdout)?;
            (seed, height, false, phrase)
        }
    };

    let keys = wallet::derive_keys(&seed, network);

    writeln!(stdout)?;
    writeln!(stdout, "  📬 Address: {}", keys.address_string())?;
    writeln!(stdout)?;

    let password = prompt_password(&mut stdout)?;

    Ok(WizardResult {
        keys,
        password,
        scan_height,
        fresh,
        polyseed_phrase,
    })
}

/// Seed format for a newly created wallet.
enum SeedType {
    Standard,
    Polyseed,
}

/// Let the user pick between the classic 25-word seed and a 16-word
/// Polyseed when creating a wallet.
fn prompt_seed_type(stdout: &mut impl Write) -> color_eyre::Result<SeedType> {
    writeln!(stdout)?;
    writeln!(stdout, "  Seed format:")?;
    writeln!(
        stdout,
        "  [1] Standard Monero seed (25 words, works everywhere)"
    )?;
    writeln!(
        stdout,
        "  [2] Polyseed (16 words, embeds the wallet birthday)"
    )?;
    writeln!(stdout)?;
    write!(stdout, "  Choose (1/2): ")?;
    stdout.flush()?;

    loop {
        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('1') => {
                    writeln!(stdout, "1")?;
                    return Ok(SeedType::Standard);
                }
                KeyCode::Char('2') => {
                    writeln!(stdout, "2")?;
                    return Ok(SeedType::Polyseed);
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => abort(),
                _ => {}
            }
        }
    }
}

fn prompt_create_or_restore(stdout: &mut impl Write) -> color_eyre::Result<WalletMode> {
    writeln!(stdout, "  [1] Create new wallet")?;
    writeln!(stdout, "  [2] Restore from seed phrase")?;
    writeln!(stdout)?;
    write!(stdout, "  Choose (1/2): ")?;
    stdout.flush()?;

    loop {
        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('1') => {
                    writeln!(stdout, "1")?;
                    return Ok(WalletMode::Create);
                }
                KeyCode::Char('2') => {
                    writeln!(stdout, "2")?;
                    return Ok(WalletMode::Restore);
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => abort(),
                _ => {}
            }
        }
    }
}

/// Render the new seed phrase so the user can write it down.
///
/// SECURITY: this is the ONLY place the seed is ever rendered. The seed and
/// mnemonic must never be written to logs or any other console output —
/// no tracing/println macro anywhere in the codebase touches them (the
/// `WalletKeys` seed field is also zeroized on drop).
fn display_new_seed(stdout: &mut impl Write, mnemonic: &[String]) -> color_eyre::Result<()> {
    writeln!(stdout)?;
    writeln!(stdout, "  ⚠️  WRITE DOWN YOUR SEED PHRASE ⚠️")?;
    writeln!(stdout, "  This is the ONLY way to recover your wallet!")?;
    writeln!(stdout)?;

    for (i, chunk) in mnemonic.chunks(5).enumerate() {
        write!(stdout, "  ")?;
        for (j, word) in chunk.iter().enumerate() {
            let num = i * 5 + j + 1;
            write!(stdout, "{:>2}. {:<12}", num, word)?;
        }
        writeln!(stdout)?;
    }

    writeln!(stdout)?;
    write!(stdout, "  Press Enter when you've saved your seed...")?;
    stdout.flush()?;

    loop {
        if let Event::Key(key) = event::read()? {
            if key.code == KeyCode::Enter {
                writeln!(stdout)?;
                break;
            }
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                abort();
            }
        }
    }

    Ok(())
}

/// Unified seed restore: detects 25-word standard or 16-word polyseed.
/// Returns `(seed, scan_height, polyseed_phrase)`.
fn prompt_seed_restore(
    stdout: &mut impl Write,
) -> color_eyre::Result<([u8; 32], u64, Option<String>)> {
    writeln!(stdout)?;
    writeln!(stdout, "  Restore from seed phrase:")?;
    writeln!(stdout, "  [1] Standard Monero seed (25 words)")?;
    writeln!(stdout, "  [2] Polyseed (16 words)")?;
    writeln!(stdout)?;
    write!(stdout, "  Choose (1/2): ")?;
    stdout.flush()?;

    loop {
        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('1') => {
                    writeln!(stdout, "1")?;
                    let seed = prompt_seed_input(stdout)?;
                    let height = prompt_scan_height(stdout)?;
                    return Ok((seed, height, None));
                }
                KeyCode::Char('2') => {
                    writeln!(stdout, "2")?;
                    let (seed, birthday, phrase) = prompt_polyseed_input(stdout)?;
                    let height = wallet::birthday_to_height(birthday);
                    writeln!(stdout, "  📅 Birthday → scan height: {}", height)?;
                    return Ok((seed, height, Some(phrase)));
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => abort(),
                _ => {}
            }
        }
    }
}

fn prompt_seed_input(stdout: &mut impl Write) -> color_eyre::Result<[u8; 32]> {
    writeln!(stdout)?;
    writeln!(stdout, "  Enter your 25-word seed phrase.")?;
    writeln!(stdout, "  Type each word. Tab/Space to accept suggestion.")?;
    writeln!(
        stdout,
        "  Up/Down to navigate suggestions. Enter when done."
    )?;
    writeln!(stdout)?;

    let mut words: Vec<String> = Vec::new();
    let mut current_word = String::new();
    let mut suggestions: Vec<&'static str> = Vec::new();
    let mut suggestion_idx: usize = 0;

    loop {
        write!(stdout, "\r\x1b[K")?;
        write!(stdout, "  [{}/25] {}", words.len() + 1, words.join(" "))?;
        if !current_word.is_empty() {
            write!(stdout, " \x1b[4m{}\x1b[0m", current_word)?;
        } else if !suggestions.is_empty() && words.len() < 25 {
            write!(stdout, " \x1b[2m{}\x1b[0m", suggestions[suggestion_idx])?;
        }
        if !current_word.is_empty() && !suggestions.is_empty() {
            write!(stdout, "\n\r\x1b[K  Suggestions: ")?;
            for (i, s) in suggestions.iter().take(5).enumerate() {
                if i == suggestion_idx {
                    write!(stdout, "[{}] ", s)?;
                } else {
                    write!(stdout, "{} ", s)?;
                }
            }
            write!(stdout, "\x1b[A\r")?;
        }
        stdout.flush()?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Tab | KeyCode::Char(' ') => {
                    if !current_word.is_empty() {
                        if !suggestions.is_empty() {
                            words.push(suggestions[suggestion_idx].to_string());
                        } else if wallet::is_valid_word(&current_word) {
                            words.push(current_word.clone());
                        } else {
                            write!(stdout, "\r\x1b[K  ❌ Unknown: '{}'", current_word)?;
                            stdout.flush()?;
                            std::thread::sleep(std::time::Duration::from_millis(800));
                            continue;
                        }
                        current_word.clear();
                        suggestions.clear();
                        suggestion_idx = 0;
                    } else if !suggestions.is_empty() {
                        words.push(suggestions[suggestion_idx].to_string());
                        suggestions.clear();
                        suggestion_idx = 0;
                    }
                }
                KeyCode::Up => {
                    suggestion_idx = suggestion_idx.saturating_sub(1);
                }
                KeyCode::Down => {
                    if !suggestions.is_empty() && suggestion_idx < suggestions.len() - 1 {
                        suggestion_idx += 1;
                    }
                }
                KeyCode::Enter => {
                    handle_seed_enter(
                        stdout,
                        &mut words,
                        &mut current_word,
                        &mut suggestions,
                        &mut suggestion_idx,
                    )?;
                    if words.len() == 25 {
                        writeln!(stdout)?;
                        match wallet::mnemonic_to_seed(&words.join(" ")) {
                            Ok(seed) => {
                                writeln!(stdout, "  ✅ Valid seed phrase!")?;
                                return Ok(seed);
                            }
                            Err(e) => {
                                writeln!(stdout, "  ❌ Invalid seed: {}", e)?;
                                write!(stdout, "  Enter to retry, Esc to cancel...")?;
                                stdout.flush()?;
                                loop {
                                    if let Event::Key(k) = event::read()? {
                                        match k.code {
                                            KeyCode::Enter => {
                                                words.clear();
                                                break;
                                            }
                                            KeyCode::Esc => {
                                                color_eyre::eyre::bail!("Cancelled");
                                            }
                                            KeyCode::Char('c')
                                                if k.modifiers.contains(KeyModifiers::CONTROL) =>
                                            {
                                                abort();
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        writeln!(stdout)?;
                        writeln!(stdout, "  Need 25 words (have {}).", words.len())?;
                    }
                }
                KeyCode::Backspace => {
                    if !current_word.is_empty() {
                        current_word.pop();
                        suggestions = wallet::autocomplete(&current_word);
                        suggestion_idx = 0;
                    } else if !words.is_empty() {
                        current_word = words.pop().unwrap();
                        suggestions = wallet::autocomplete(&current_word);
                        suggestion_idx = 0;
                    }
                }
                KeyCode::Esc => {
                    color_eyre::eyre::bail!("Seed entry cancelled");
                }
                KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'c' => {
                    abort();
                }
                KeyCode::Char(c) => {
                    current_word.push(c);
                    suggestions = wallet::autocomplete(&current_word);
                    suggestion_idx = 0;
                }
                _ => {}
            }
        }
    }
}

fn handle_seed_enter(
    _stdout: &mut impl Write,
    words: &mut Vec<String>,
    current_word: &mut String,
    suggestions: &mut Vec<&'static str>,
    suggestion_idx: &mut usize,
) -> color_eyre::Result<()> {
    if !current_word.is_empty() {
        if !suggestions.is_empty() {
            words.push(suggestions[*suggestion_idx].to_string());
        } else if wallet::is_valid_word(current_word) {
            words.push(current_word.clone());
        }
        current_word.clear();
        suggestions.clear();
        *suggestion_idx = 0;
    }
    Ok(())
}

/// Prompt for a 16-word Polyseed with BIP39 autocomplete.
fn prompt_polyseed_input(stdout: &mut impl Write) -> color_eyre::Result<([u8; 32], u64, String)> {
    writeln!(stdout)?;
    writeln!(stdout, "  Enter your 16-word Polyseed phrase.")?;
    writeln!(stdout, "  Tab/Space to accept suggestion. Enter when done.")?;
    writeln!(stdout)?;

    let mut words: Vec<String> = Vec::new();
    let mut current_word = String::new();
    let mut suggestions: Vec<&'static str> = Vec::new();
    let mut suggestion_idx: usize = 0;

    loop {
        write!(stdout, "\r\x1b[K")?;
        write!(stdout, "  [{}/16] {}", words.len() + 1, words.join(" "))?;
        if !current_word.is_empty() {
            write!(stdout, " \x1b[4m{}\x1b[0m", current_word)?;
        } else if !suggestions.is_empty() && words.len() < 16 {
            write!(stdout, " \x1b[2m{}\x1b[0m", suggestions[suggestion_idx])?;
        }
        if !current_word.is_empty() && !suggestions.is_empty() {
            write!(stdout, "\n\r\x1b[K  Suggestions: ")?;
            for (i, s) in suggestions.iter().take(5).enumerate() {
                if i == suggestion_idx {
                    write!(stdout, "[{}] ", s)?;
                } else {
                    write!(stdout, "{} ", s)?;
                }
            }
            write!(stdout, "\x1b[A\r")?;
        }
        stdout.flush()?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Tab | KeyCode::Char(' ') => {
                    if !current_word.is_empty() {
                        if !suggestions.is_empty() {
                            words.push(suggestions[suggestion_idx].to_string());
                        } else if wallet::is_valid_bip39_word(&current_word) {
                            words.push(current_word.clone());
                        } else {
                            write!(stdout, "\r\x1b[K  ❌ Unknown: '{}'", current_word)?;
                            stdout.flush()?;
                            std::thread::sleep(std::time::Duration::from_millis(800));
                            continue;
                        }
                        current_word.clear();
                        suggestions.clear();
                        suggestion_idx = 0;
                    } else if !suggestions.is_empty() {
                        words.push(suggestions[suggestion_idx].to_string());
                        suggestions.clear();
                        suggestion_idx = 0;
                    }
                }
                KeyCode::Up => {
                    suggestion_idx = suggestion_idx.saturating_sub(1);
                }
                KeyCode::Down => {
                    if !suggestions.is_empty() && suggestion_idx < suggestions.len() - 1 {
                        suggestion_idx += 1;
                    }
                }
                KeyCode::Enter => {
                    if !current_word.is_empty() {
                        if !suggestions.is_empty() {
                            words.push(suggestions[suggestion_idx].to_string());
                        } else if wallet::is_valid_bip39_word(&current_word) {
                            words.push(current_word.clone());
                        }
                        current_word.clear();
                        suggestions.clear();
                    }
                    if words.len() == 16 {
                        writeln!(stdout)?;
                        let phrase = words.join(" ");
                        match wallet::polyseed_to_key(&phrase) {
                            Ok((seed, birthday)) => {
                                writeln!(stdout, "  ✅ Valid Polyseed!")?;
                                return Ok((seed, birthday, phrase));
                            }
                            Err(e) => {
                                writeln!(stdout, "  ❌ Invalid: {}", e)?;
                                write!(stdout, "  Enter to retry, Esc to cancel...")?;
                                stdout.flush()?;
                                loop {
                                    if let Event::Key(k) = event::read()? {
                                        match k.code {
                                            KeyCode::Enter => {
                                                words.clear();
                                                break;
                                            }
                                            KeyCode::Esc => {
                                                color_eyre::eyre::bail!("Cancelled");
                                            }
                                            KeyCode::Char('c')
                                                if k.modifiers.contains(KeyModifiers::CONTROL) =>
                                            {
                                                abort();
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        writeln!(stdout)?;
                        writeln!(stdout, "  Need 16 words (have {}).", words.len())?;
                    }
                }
                KeyCode::Backspace => {
                    if !current_word.is_empty() {
                        current_word.pop();
                        suggestions = wallet::polyseed_autocomplete(&current_word);
                        suggestion_idx = 0;
                    } else if !words.is_empty() {
                        current_word = words.pop().unwrap();
                        suggestions = wallet::polyseed_autocomplete(&current_word);
                        suggestion_idx = 0;
                    }
                }
                KeyCode::Esc => {
                    color_eyre::eyre::bail!("Seed entry cancelled");
                }
                KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'c' => {
                    abort();
                }
                KeyCode::Char(c) => {
                    current_word.push(c);
                    suggestions = wallet::polyseed_autocomplete(&current_word);
                    suggestion_idx = 0;
                }
                _ => {}
            }
        }
    }
}

fn prompt_scan_height(stdout: &mut impl Write) -> color_eyre::Result<u64> {
    writeln!(stdout)?;
    write!(stdout, "  Scan from height (0 = genesis): ")?;
    stdout.flush()?;

    let mut input = String::new();

    loop {
        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Enter => {
                    writeln!(stdout)?;
                    let height: u64 = input.trim().parse().unwrap_or(0);
                    writeln!(stdout, "  Scanning from height: {}", height)?;
                    return Ok(height);
                }
                KeyCode::Backspace => {
                    input.pop();
                    write!(
                        stdout,
                        "\r\x1b[K  Scan from height (0 = genesis): {}",
                        input
                    )?;
                    stdout.flush()?;
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => abort(),
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    input.push(c);
                    write!(stdout, "{}", c)?;
                    stdout.flush()?;
                }
                KeyCode::Esc => {
                    writeln!(stdout)?;
                    return Ok(0);
                }
                _ => {}
            }
        }
    }
}

fn prompt_password(_stdout: &mut impl Write) -> color_eyre::Result<Zeroizing<String>> {
    disable_raw_mode()?;

    let password = loop {
        let pw = rpassword::prompt_password("  🔒 Set wallet password: ")?;
        if pw.is_empty() {
            eprintln!("  Password cannot be empty.");
            continue;
        }
        let pw2 = rpassword::prompt_password("  🔒 Confirm password: ")?;
        if pw != pw2 {
            eprintln!("  Passwords do not match. Try again.");
            continue;
        }
        break pw;
    };

    enable_raw_mode()?;
    Ok(Zeroizing::new(password))
}
