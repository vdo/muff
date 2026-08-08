//! Single-file encrypted wallet database.
//!
//! The wallet (seed + sync state) lives in ONE file on disk:
//!
//! ```text
//! [ magic "MUFFWDB1" (8B) | argon2 salt (16B) | XChaCha20 nonce (24B) | ciphertext ]
//! ```
//!
//! The ciphertext is an XChaCha20-Poly1305-encrypted **SQLite database image**.
//! At runtime the database is deserialized into an in-memory SQLite connection;
//! plaintext SQLite bytes never touch the disk. The file therefore leaks nothing
//! except its (padded-by-sqlite) size: no table names, no row counts, no tx
//! hashes, no amounts.
//!
//! - KDF: Argon2id (19 MiB, t=2, p=1) — password stretching; wrong-password
//!   detection comes free from the Poly1305 authentication tag.
//! - Writes use a synced temp file followed by an atomic rename, preserving
//!   the previous wallet image if a save is interrupted before replacement.
//! - While the wallet is locked (auto-lock), this struct — and with it the
//!   in-memory database and the derived key — is dropped.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use color_eyre::eyre::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroizing;

use super::balance::{TransferDirection, TransferRecord};
use super::state::StoredOutput;

/// File magic identifying the encrypted-database format.
pub const MAGIC: &[u8; 8] = b"MUFFWDB1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
/// Argon2id memory cost in KiB (19 MiB, OWASP recommendation).
const ARGON_M_KIB: u32 = 19 * 1024;
const ARGON_T: u32 = 2;
const ARGON_P: u32 = 1;

/// Minimum length enforced when the UI creates or changes a password.
/// Existing shorter passwords remain unlockable for compatibility.
pub const MIN_NEW_PASSWORD_CHARS: usize = 12;

/// Primary address plus the initial four account-0 subaddresses. Additional
/// rows are allocated explicitly and persisted in wallet metadata.
pub const DEFAULT_RECEIVE_ADDRESS_COUNT: u32 = 5;

/// How many recent block hashes are kept for reorg detection.
const RECENT_HASH_WINDOW: u64 = 1024;

/// The encrypted, single-file wallet database.
pub struct WalletDb {
    conn: Mutex<Connection>,
    path: PathBuf,
    /// Serializes complete snapshot writes so an older serialization can
    /// never finish after and overwrite a newer one.
    save_lock: Mutex<()>,
    /// Encryption parameters (kept for saves; replaced on password change).
    /// The key is zeroized on drop.
    enc: Mutex<DbEncryption>,
}

/// Encryption parameters for the wallet file.
struct DbEncryption {
    /// Argon2id-derived XChaCha20-Poly1305 key.
    key: Zeroizing<[u8; 32]>,
    /// KDF salt stored in the file header.
    salt: [u8; SALT_LEN],
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| anyhow!("argon2 kdf: {e}"))?;
    Ok(key)
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| anyhow!("encryption failed: {e}"))?;
    Ok((nonce, ct))
}

fn decrypt(key: &[u8; 32], nonce: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| anyhow!("wrong password or corrupted wallet file"))?;
    Ok(Zeroizing::new(pt))
}

/// Write `bytes` to `path` with owner-only permissions (0600) so the
/// encrypted wallet image is never world-readable, even before the atomic
/// rename into place.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("write {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    // `mode` only applies when the file is created; force the permissions
    // too as a defense in depth measure.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", path.display()))?;
    // Atomic rename alone is not power-loss durability: flush both file data
    // and metadata before it becomes the live wallet image.
    file.sync_all()
        .with_context(|| format!("sync {}", path.display()))
}

/// Detect which on-disk wallet format a path holds.
pub fn detect_format(path: &Path) -> std::io::Result<WalletFileFormat> {
    match std::fs::read(path) {
        Ok(bytes) => {
            if bytes.starts_with(MAGIC) {
                Ok(WalletFileFormat::EncryptedDb)
            } else if bytes.first() == Some(&b'{') {
                Ok(WalletFileFormat::LegacyJson)
            } else {
                Ok(WalletFileFormat::Unknown)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(WalletFileFormat::Missing),
        Err(e) => Err(e),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletFileFormat {
    Missing,
    EncryptedDb,
    /// Pre-1.0 `wallet.enc` JSON (AES-GCM encrypted seed only).
    LegacyJson,
    Unknown,
}

/// Which seed encoding the wallet was created or restored from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedFormat {
    /// Standard 25-word Monero mnemonic (the default for existing wallets).
    Legacy,
    /// 16-word Polyseed; the original phrase is stored in `polyseed_phrase`
    /// meta so it can be re-displayed (it is not recoverable from the key).
    Polyseed,
}

/// A saved recipient in the address book.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressBookEntry {
    pub id: i64,
    pub label: String,
    pub address: String,
}

// ---------------------------------------------------------------------------
// WalletDb: open/create/save
// ---------------------------------------------------------------------------

impl WalletDb {
    /// Create a brand-new wallet database containing `seed`.
    pub fn create(
        path: &Path,
        password: &[u8],
        seed: &[u8; 32],
        network: &str,
        restore_height: u64,
    ) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        rand::Rng::fill(&mut rand::thread_rng(), &mut salt);
        let enc_key = Zeroizing::new(derive_key(password, &salt)?);
        let conn = Connection::open_in_memory().context("open in-memory sqlite")?;
        Self::init_schema(&conn)?;
        {
            let mut stmt = conn.prepare("INSERT INTO meta(key, value) VALUES(?1, ?2)")?;
            stmt.execute(params!["seed", seed.as_slice()])?;
            stmt.execute(params!["version", b"1".as_slice()])?;
            stmt.execute(params!["network", network.as_bytes()])?;
            stmt.execute(params![
                "restore_height",
                restore_height.to_string().as_bytes()
            ])?;
            stmt.execute(params![
                "scan_height",
                restore_height.to_string().as_bytes()
            ])?;
        }
        let db = Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
            save_lock: Mutex::new(()),
            enc: Mutex::new(DbEncryption { key: enc_key, salt }),
        };
        db.save()?;
        Ok(db)
    }

    /// Open and decrypt an existing wallet database.
    pub fn open(path: &Path, password: &[u8]) -> Result<Self> {
        let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        if raw.len() < MAGIC.len() + SALT_LEN + NONCE_LEN + 16 || !raw.starts_with(MAGIC) {
            bail!("not an encrypted wallet database: {}", path.display());
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[8..8 + SALT_LEN]);
        let nonce = &raw[8 + SALT_LEN..8 + SALT_LEN + NONCE_LEN];
        let ct = &raw[8 + SALT_LEN + NONCE_LEN..];

        let enc_key = Zeroizing::new(derive_key(password, &salt)?);
        let plaintext = decrypt(&enc_key, nonce, ct)?;

        let mut conn = Connection::open_in_memory().context("open in-memory sqlite")?;
        Self::deserialize_into(&mut conn, &plaintext)?;
        drop(plaintext); // zeroized
        // Migrate databases created by older versions: all schema statements
        // are idempotent (`CREATE TABLE/INDEX IF NOT EXISTS`).
        Self::init_schema(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
            save_lock: Mutex::new(()),
            enc: Mutex::new(DbEncryption { key: enc_key, salt }),
        })
    }

    /// Hand the decrypted image to SQLite via `sqlite3_deserialize`.
    /// The buffer must be allocated by `sqlite3_malloc` (SQLite takes ownership).
    fn deserialize_into(conn: &mut Connection, data: &[u8]) -> Result<()> {
        use rusqlite::DatabaseName;
        use rusqlite::serialize::OwnedData;
        use std::ptr::NonNull;
        unsafe {
            let ptr = libsqlite3_sys::sqlite3_malloc(data.len() as i32) as *mut u8;
            if ptr.is_null() {
                bail!("sqlite3_malloc failed");
            }
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
            let owned = OwnedData::from_raw_nonnull(
                NonNull::new(ptr).ok_or_else(|| anyhow!("null sqlite buffer"))?,
                data.len(),
            );
            conn.deserialize(DatabaseName::Main, owned, false)
                .context("sqlite deserialize")?;
        }
        Ok(())
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS outputs (
                key_hex TEXT PRIMARY KEY,
                wallet_output_hex TEXT NOT NULL,
                amount INTEGER NOT NULL,
                height INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                spent INTEGER NOT NULL DEFAULT 0,
                spent_tx TEXT
            );
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_hash TEXT NOT NULL,
                height INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                fee INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK(direction IN ('In','Out')),
                confirmed INTEGER NOT NULL DEFAULT 0,
                failed INTEGER NOT NULL DEFAULT 0,
                note TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS chain_hashes (
                height INTEGER PRIMARY KEY,
                hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS address_book (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                address TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS rings (
                key_image TEXT PRIMARY KEY,
                ring_blob BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pending_transactions (
                tx_hash TEXT PRIMARY KEY,
                tx_blob BLOB NOT NULL,
                relayed INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_outputs_spent ON outputs(spent);
            CREATE INDEX IF NOT EXISTS idx_history_hash ON history(tx_hash);
            ",
        )?;
        Ok(())
    }

    /// Encrypt and atomically persist the current database image.
    pub fn save(&self) -> Result<()> {
        let _save_guard = self.save_lock.lock().unwrap();
        let mut replaced = false;
        self.save_locked(&mut replaced)
    }

    /// Persist while the caller holds `save_lock`.
    fn save_locked(&self, replaced: &mut bool) -> Result<()> {
        // `serialize` borrows the connection; copy out so the lock is
        // released before the (slower) encryption step.
        let image: Zeroizing<Vec<u8>> = {
            let conn = self.conn.lock().unwrap();
            let data = conn
                .serialize(rusqlite::DatabaseName::Main)
                .context("sqlite serialize")?;
            let bytes: &[u8] = &data;
            Zeroizing::new(bytes.to_vec())
        };
        // Encrypt under the current parameters (a concurrent password change
        // is serialized by this lock) and drop the plaintext immediately.
        let (nonce, ct, salt) = {
            let enc = self.enc.lock().unwrap();
            let (nonce, ct) = encrypt(&enc.key, &image)?;
            (nonce, ct, enc.salt)
        };
        drop(image);

        let mut file_bytes = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ct.len());
        file_bytes.extend_from_slice(MAGIC);
        file_bytes.extend_from_slice(&salt);
        file_bytes.extend_from_slice(&nonce);
        file_bytes.extend_from_slice(&ct);

        let mut suffix = [0u8; 8];
        rand::Rng::fill(&mut rand::thread_rng(), &mut suffix);
        let file_name = self
            .path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("wallet"))
            .to_string_lossy();
        let tmp_name = format!(
            ".{file_name}.{}.{}.dbtmp",
            std::process::id(),
            hex::encode(suffix)
        );
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let tmp = parent.join(tmp_name);
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        let result = (|| -> Result<()> {
            write_owner_only(&tmp, &file_bytes)?;
            std::fs::rename(&tmp, &self.path)
                .with_context(|| format!("rename to {}", self.path.display()))?;
            *replaced = true;
            // Persist the directory entry update as well as the file itself.
            std::fs::File::open(parent)
                .and_then(|dir| dir.sync_all())
                .with_context(|| format!("sync directory {}", parent.display()))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Change the wallet password: re-derive the encryption key under a
    /// fresh salt and persist immediately. The file format is unchanged;
    /// the old password stops working as soon as the save succeeds.
    pub fn set_password(&self, new_password: &[u8]) -> Result<()> {
        let mut salt = [0u8; SALT_LEN];
        rand::Rng::fill(&mut rand::thread_rng(), &mut salt);
        let key = derive_key(new_password, &salt)?;
        let _save_guard = self.save_lock.lock().unwrap();
        let old = {
            let mut enc = self.enc.lock().unwrap();
            std::mem::replace(
                &mut *enc,
                DbEncryption {
                    key: Zeroizing::new(key),
                    salt,
                },
            )
        };
        let mut replaced = false;
        if let Err(e) = self.save_locked(&mut replaced) {
            if replaced {
                // The live file already uses the new password. Keep the
                // matching in-memory key and report success rather than make
                // the caller retain a password that can no longer unlock it.
                tracing::warn!("wallet password changed, but directory sync failed: {e:#}");
                return Ok(());
            }
            *self.enc.lock().unwrap() = old;
            return Err(e);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Seed / meta
    // ------------------------------------------------------------------

    pub fn seed(&self) -> Result<Zeroizing<[u8; 32]>> {
        let conn = self.conn.lock().unwrap();
        let bytes: Vec<u8> =
            conn.query_row("SELECT value FROM meta WHERE key='seed'", [], |r| r.get(0))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("corrupt seed length in wallet db"))?;
        Ok(Zeroizing::new(arr))
    }

    /// Which seed encoding the wallet was created/restored from.
    pub fn seed_format(&self) -> SeedFormat {
        match self.meta_string("seed_format").ok().flatten().as_deref() {
            Some("polyseed") => SeedFormat::Polyseed,
            _ => SeedFormat::Legacy,
        }
    }

    pub fn set_seed_format(&self, format: SeedFormat) -> Result<()> {
        self.set_meta_string(
            "seed_format",
            match format {
                SeedFormat::Legacy => "legacy",
                SeedFormat::Polyseed => "polyseed",
            },
        )
    }

    /// The original 16-word polyseed phrase (only stored for polyseed
    /// wallets, so the Config tab can re-display the phrase the user
    /// actually wrote down — the 150-bit secret is not recoverable from
    /// the derived 32-byte key).
    pub fn polyseed_phrase(&self) -> Result<Option<String>> {
        self.meta_string("polyseed_phrase")
    }

    pub fn set_polyseed_phrase(&self, phrase: &str) -> Result<()> {
        self.set_meta_string("polyseed_phrase", phrase)
    }

    pub fn scan_height(&self) -> Result<u64> {
        self.meta_u64("scan_height")
    }

    pub fn set_scan_height(&self, h: u64) -> Result<()> {
        self.set_meta_u64("scan_height", h)
    }

    pub fn restore_height(&self) -> Result<u64> {
        self.meta_u64("restore_height")
    }

    pub fn network(&self) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        let raw: Vec<u8> =
            conn.query_row("SELECT value FROM meta WHERE key='network'", [], |r| {
                r.get(0)
            })?;
        String::from_utf8(raw).context("corrupt network value in wallet db")
    }

    /// First account-0 minor index not yet observed on-chain. This is kept
    /// separately from the number of addresses the user has made visible:
    /// several allocated addresses may all still be unused.
    pub fn next_receive_minor(&self) -> Result<u32> {
        Ok(self
            .meta_u64("next_receive_minor")?
            .max(1)
            .min(u32::MAX as u64) as u32)
    }

    /// Move the receive cursor forward, never backward. This lets a restored
    /// wallet discover a used address and stop offering it again.
    pub fn advance_receive_minor(&self, next: u32) -> Result<()> {
        if next > self.next_receive_minor()? {
            self.set_meta_u64("next_receive_minor", u64::from(next))?;
        }
        Ok(())
    }

    /// Number of stable rows allocated on the Addresses screen, including
    /// the primary address at row/minor 0. The default is compatible with
    /// wallets created before this metadata existed.
    pub fn receive_address_count(&self) -> Result<u32> {
        Ok(self
            .meta_u64("receive_address_count")?
            .max(u64::from(DEFAULT_RECEIVE_ADDRESS_COUNT))
            .min(u64::from(u32::MAX)) as u32)
    }

    /// Allocate one more account-0 subaddress and return its minor index.
    pub fn allocate_receive_address(&self) -> Result<u32> {
        let count = self.receive_address_count()?;
        let next_count = count
            .checked_add(1)
            .ok_or_else(|| anyhow!("account-0 subaddress space is exhausted"))?;
        self.set_meta_u64("receive_address_count", u64::from(next_count))?;
        Ok(count)
    }

    /// Ensure an observed/restored subaddress remains visible. Returns true
    /// only when metadata changed, allowing callers to avoid redundant saves.
    pub fn ensure_receive_address_count(&self, count: u32) -> Result<bool> {
        let current = self.receive_address_count()?;
        if count > current {
            self.set_meta_u64("receive_address_count", u64::from(count))?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Full subaddress index whose outputs the send engine may consume.
    /// `selected_send_major` is absent in older wallets and therefore safely
    /// defaults to account 0.
    pub fn selected_send_subaddress(&self) -> Result<(u32, u32)> {
        let major = self
            .meta_u64("selected_send_major")?
            .min(u64::from(u32::MAX)) as u32;
        let mut minor = self
            .meta_u64("selected_send_minor")?
            .min(u64::from(u32::MAX)) as u32;
        if major == 0 {
            minor = minor.min(self.receive_address_count()?.saturating_sub(1));
        }
        Ok((major, minor))
    }

    pub fn set_selected_send_subaddress(&self, major: u32, minor: u32) -> Result<()> {
        if major == 0 && minor >= self.receive_address_count()? {
            bail!("send-source subaddress {minor} has not been allocated");
        }
        // Store the pair atomically: a concurrent periodic snapshot must not
        // persist a major index from one selection and a minor from another.
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        for (key, value) in [
            ("selected_send_major", u64::from(major)),
            ("selected_send_minor", u64::from(minor)),
        ] {
            tx.execute(
                "INSERT INTO meta(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value.to_string().as_bytes()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn meta_u64(&self, key: &str) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let raw: Option<Vec<u8>> = conn
            .query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .ok();
        let value = raw
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        Ok(value)
    }

    fn set_meta_u64(&self, key: &str, value: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value.to_string().as_bytes()],
        )?;
        Ok(())
    }

    fn meta_string(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let raw: Option<Vec<u8>> = conn
            .query_row("SELECT value FROM meta WHERE key=?1", params![key], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .ok();
        raw.map(|v| String::from_utf8(v).context("corrupt meta string"))
            .transpose()
    }

    fn set_meta_string(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value.as_bytes()],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Outputs & history
    // ------------------------------------------------------------------

    /// Insert a newly-discovered received output (+ history entry).
    /// Returns false when the output was already known (replay/burning dedup).
    pub fn insert_received_output(
        &self,
        output: &StoredOutput,
        tx_hash: &str,
        note: &str,
    ) -> Result<bool> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let n = tx.execute(
            "INSERT OR IGNORE INTO outputs
             (key_hex, wallet_output_hex, amount, height, timestamp, spent, spent_tx)
             VALUES(?1, ?2, ?3, ?4, ?5, 0, NULL)",
            params![
                output.key_hex,
                output.wallet_output_hex,
                output.amount as i64,
                output.height as i64,
                output.timestamp as i64,
            ],
        )?;
        if n == 0 {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO history
             (tx_hash, height, timestamp, amount, fee, direction, confirmed, failed, note)
             VALUES(?1, ?2, ?3, ?4, 0, 'In', 1, 0, ?5)",
            params![
                tx_hash,
                output.height as i64,
                output.timestamp as i64,
                output.amount as i64,
                note,
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Mark a broadcast outgoing transfer confirmed (also covers re-mined
    /// dropped transfers). Clears the `spent_tx` marker on its inputs.
    /// Returns true when a transfer record was updated.
    pub fn confirm_out_transfer(&self, txid: &str, height: u64, timestamp: u64) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE history SET confirmed=1, failed=0, height=?1, timestamp=?2
             WHERE tx_hash=?3 AND direction='Out' AND (confirmed=0 OR failed=1 OR height != ?1)",
            params![height as i64, timestamp as i64, txid],
        )?;
        if n > 0 {
            conn.execute(
                "UPDATE outputs SET spent_tx=NULL WHERE spent_tx=?1",
                params![txid],
            )?;
            conn.execute(
                "DELETE FROM pending_transactions WHERE tx_hash=?1",
                params![txid],
            )?;
        }
        Ok(n > 0)
    }

    /// tx hashes of outgoing transfers that are neither confirmed nor
    /// marked failed (i.e. believed to be in the transaction pool).
    pub fn pending_out_transfers(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT h.tx_hash FROM history h
             LEFT JOIN pending_transactions p ON p.tx_hash=h.tx_hash
             WHERE h.direction='Out' AND h.confirmed=0 AND h.failed=0
               AND (p.tx_hash IS NULL OR p.relayed=1)",
        )?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Outputs relevant for a key-image refresh: every output when `full`,
    /// otherwise unspent outputs plus outputs reserved by an unconfirmed
    /// (not failed) outgoing transfer.
    pub fn outputs_for_ki_check(&self, full: bool) -> Result<Vec<StoredOutput>> {
        let conn = self.conn.lock().unwrap();
        if full {
            let mut stmt = conn.prepare(
                "SELECT key_hex, wallet_output_hex, amount, height, timestamp, spent, spent_tx
                 FROM outputs",
            )?;
            let rows = stmt
                .query_map([], row_to_output)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            return Ok(rows);
        }
        let pending: std::collections::HashSet<String> = {
            let mut stmt = conn.prepare(
                "SELECT h.tx_hash FROM history h
                 LEFT JOIN pending_transactions p ON p.tx_hash=h.tx_hash
                 WHERE h.direction='Out' AND h.confirmed=0 AND h.failed=0
                   AND (p.tx_hash IS NULL OR p.relayed=1)",
            )?;
            stmt.query_map([], |r| r.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect()
        };
        let mut stmt = conn.prepare(
            "SELECT key_hex, wallet_output_hex, amount, height, timestamp, spent, spent_tx
             FROM outputs WHERE spent=0 OR (spent=1 AND spent_tx IS NOT NULL)",
        )?;
        let rows = stmt
            .query_map([], row_to_output)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .filter(|o| {
                !o.spent
                    || o.spent_tx
                        .as_ref()
                        .map(|t| pending.contains(t))
                        .unwrap_or(false)
            })
            .collect())
    }

    /// Mark an output spent (chain spend detected by key image).
    pub fn mark_spent(&self, key_hex: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE outputs SET spent=1 WHERE key_hex=?1",
            params![key_hex],
        )?;
        Ok(())
    }

    /// Release an output whose spending tx was dropped; flag the transfer as
    /// failed (dropped). Returns the released txid if any.
    pub fn release_output(&self, key_hex: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let txid: Option<String> = conn
            .query_row(
                "SELECT spent_tx FROM outputs WHERE key_hex=?1",
                params![key_hex],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        conn.execute(
            "UPDATE outputs SET spent=0, spent_tx=NULL WHERE key_hex=?1",
            params![key_hex],
        )?;
        if let Some(t) = &txid {
            conn.execute(
                "UPDATE history SET failed=1 WHERE tx_hash=?1 AND direction='Out'",
                params![t],
            )?;
            conn.execute(
                "DELETE FROM pending_transactions WHERE tx_hash=?1",
                params![t],
            )?;
        }
        Ok(txid)
    }

    /// All unspent outputs (candidates for spending).
    pub fn spendable_outputs(&self) -> Result<Vec<StoredOutput>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT key_hex, wallet_output_hex, amount, height, timestamp, spent, spent_tx
             FROM outputs WHERE spent=0 ORDER BY height ASC, timestamp ASC, rowid ASC",
        )?;
        let rows = stmt
            .query_map([], row_to_output)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Previously committed ring for a key image, if any. Ring data is kept
    /// after a failed or dropped transaction so reconstructing a spend cannot
    /// create a second, intersectable ring for the same true output.
    pub fn ring_for_key_image(&self, key_image: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT ring_blob FROM rings WHERE key_image=?1",
                params![key_image],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Atomically commit the signed transaction, its rings, input reservations
    /// and history record before the first network write.
    pub fn record_signed_transfer(
        &self,
        input_keys: &[String],
        rings: &[(String, Vec<u8>)],
        tx_blob: &[u8],
        record: &TransferRecord,
    ) -> Result<()> {
        if input_keys.is_empty() || input_keys.len() != rings.len() {
            bail!("signed transfer must have one committed ring per input");
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        for (key_image, ring_blob) in rings {
            let existing: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT ring_blob FROM rings WHERE key_image=?1",
                    params![key_image],
                    |row| row.get(0),
                )
                .optional()?;
            match existing {
                Some(existing) if existing != *ring_blob => {
                    // Never silently replace a committed ring. Two rings for
                    // one key image are intersectable and can identify the
                    // real output even if only one transaction is relayed.
                    bail!("attempted to replace the committed ring for key image {key_image}");
                }
                Some(_) => {}
                None => {
                    tx.execute(
                        "INSERT INTO rings(key_image, ring_blob) VALUES(?1, ?2)",
                        params![key_image, ring_blob],
                    )?;
                }
            }
        }
        for key_hex in input_keys {
            let changed = tx.execute(
                "UPDATE outputs SET spent=1, spent_tx=?1
                 WHERE key_hex=?2 AND spent=0 AND spent_tx IS NULL",
                params![record.tx_hash, key_hex],
            )?;
            if changed != 1 {
                bail!("signed input {key_hex} is missing or reserved by another transfer");
            }
        }
        tx.execute(
            "INSERT INTO history
             (tx_hash, height, timestamp, amount, fee, direction, confirmed, failed, note)
             VALUES(?1, ?2, ?3, ?4, ?5, 'Out', 0, 0, ?6)",
            params![
                record.tx_hash,
                record.height as i64,
                record.timestamp as i64,
                record.amount as i64,
                record.fee as i64,
                record.note,
            ],
        )?;
        tx.execute(
            "INSERT INTO pending_transactions(tx_hash, tx_blob, relayed, created_at)
             VALUES(?1, ?2, 0, ?3)",
            params![record.tx_hash, tx_blob, record.timestamp as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn mark_transaction_relayed(&self, tx_hash: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE pending_transactions SET relayed=1 WHERE tx_hash=?1",
            params![tx_hash],
        )?;
        Ok(())
    }

    /// Signed transactions whose first broadcast had an ambiguous result.
    /// The caller supplies a cutoff so a scanner cannot race the send task's
    /// immediate first relay; duplicate exact-byte submission is safe, but
    /// avoiding it keeps state and logs deterministic.
    pub fn unrelayed_transactions(&self, created_before: u64) -> Result<Vec<(String, Vec<u8>)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT tx_hash, tx_blob FROM pending_transactions
             WHERE relayed=0 AND created_at <= ?1 ORDER BY rowid",
        )?;
        let created_before = created_before.min(i64::MAX as u64) as i64;
        Ok(stmt
            .query_map(params![created_before], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Whether `tx_hash` is signed and reserved but not yet known relayed.
    pub fn transaction_awaiting_relay(&self, tx_hash: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT 1 FROM pending_transactions WHERE tx_hash=?1 AND relayed=0",
                params![tx_hash],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Outputs reserved by a particular signed outgoing transaction. Used to
    /// derive its key images when resolving an ambiguous relay without ever
    /// constructing a replacement transaction.
    pub fn outputs_reserved_by(&self, tx_hash: &str) -> Result<Vec<StoredOutput>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT key_hex, wallet_output_hex, amount, height, timestamp, spent, spent_tx
             FROM outputs WHERE spent=1 AND spent_tx=?1",
        )?;
        Ok(stmt
            .query_map(params![tx_hash], row_to_output)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// A definitive daemon rejection makes the signed transaction unusable.
    /// Release its inputs but deliberately retain its rings for any rebuild.
    pub fn reject_signed_transfer(&self, tx_hash: &str) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE outputs SET spent=0, spent_tx=NULL WHERE spent_tx=?1",
            params![tx_hash],
        )?;
        tx.execute(
            "UPDATE history SET failed=1 WHERE tx_hash=?1 AND direction='Out'",
            params![tx_hash],
        )?;
        tx.execute(
            "DELETE FROM pending_transactions WHERE tx_hash=?1",
            params![tx_hash],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Undo an in-memory reservation when the pre-relay encrypted snapshot
    /// could not be written. No network call has happened in this case, so the
    /// history entry must disappear rather than look like a failed payment.
    /// Rings are intentionally retained: reusing one is always safer than
    /// accidentally producing two rings for the same true output.
    pub fn rollback_unpersisted_transfer(&self, tx_hash: &str) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE outputs SET spent=0, spent_tx=NULL WHERE spent_tx=?1",
            params![tx_hash],
        )?;
        tx.execute("DELETE FROM history WHERE tx_hash=?1", params![tx_hash])?;
        tx.execute(
            "DELETE FROM pending_transactions WHERE tx_hash=?1",
            params![tx_hash],
        )?;
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    fn mark_spent_by(&self, key_hex: &str, txid: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE outputs SET spent=1, spent_tx=?1 WHERE key_hex=?2",
            params![txid, key_hex],
        )?;
        Ok(())
    }

    pub fn insert_history(&self, record: &TransferRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO history
             (tx_hash, height, timestamp, amount, fee, direction, confirmed, failed, note)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                record.tx_hash,
                record.height as i64,
                record.timestamp as i64,
                record.amount as i64,
                record.fee as i64,
                match record.direction {
                    TransferDirection::In => "In",
                    TransferDirection::Out => "Out",
                },
                record.confirmed as i64,
                record.failed as i64,
                record.note,
            ],
        )?;
        Ok(())
    }

    /// Everything the UI needs, oldest first.
    ///
    /// Outputs are ordered by block height; transfers chronologically by
    /// block height, with unconfirmed/failed transfers (height 0) — the
    /// newest activity — last. Insertion order is *not* chronological: an
    /// outgoing transfer is inserted at broadcast time (height 0) and
    /// updated in place when it eventually mines, while receives scanned
    /// in the meantime keep their earlier row ids.
    pub fn ui_snapshot(&self) -> Result<(Vec<StoredOutput>, Vec<TransferRecord>)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT key_hex, wallet_output_hex, amount, height, timestamp, spent, spent_tx
             FROM outputs ORDER BY height, key_hex",
        )?;
        let outputs = stmt
            .query_map([], row_to_output)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut stmt = conn.prepare(
            "SELECT tx_hash, height, timestamp, amount, fee, direction, confirmed, failed, note
             FROM history
             ORDER BY CASE WHEN height = 0 THEN 1 ELSE 0 END, height, id",
        )?;
        let history = stmt
            .query_map([], |r| {
                Ok(TransferRecord {
                    tx_hash: r.get(0)?,
                    height: r.get::<_, i64>(1)? as u64,
                    timestamp: r.get::<_, i64>(2)? as u64,
                    amount: r.get::<_, i64>(3)? as u64,
                    fee: r.get::<_, i64>(4)? as u64,
                    direction: match r.get::<_, String>(5)?.as_str() {
                        "In" => TransferDirection::In,
                        _ => TransferDirection::Out,
                    },
                    confirmed: r.get::<_, i64>(6)? != 0,
                    failed: r.get::<_, i64>(7)? != 0,
                    note: r.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((outputs, history))
    }

    // ------------------------------------------------------------------
    // Reorg detection & rollback
    // ------------------------------------------------------------------

    pub fn recorded_hash(&self, height: u64) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let hash = conn
            .query_row(
                "SELECT hash FROM chain_hashes WHERE height=?1",
                params![height as i64],
                |r| r.get(0),
            )
            .ok();
        Ok(hash)
    }

    /// Record a scanned block's hash, trimming the detection window.
    pub fn push_hash(&self, height: u64, hash: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO chain_hashes(height, hash) VALUES(?1, ?2)",
            params![height as i64, hash],
        )?;
        let trim_below = height.saturating_sub(RECENT_HASH_WINDOW);
        conn.execute(
            "DELETE FROM chain_hashes WHERE height <= ?1",
            params![trim_below as i64],
        )?;
        Ok(())
    }

    /// Recorded hashes within the detection window ending at `max_height`
    /// (inclusive), ascending by height.
    pub fn hash_window(&self, max_height: u64) -> Result<Vec<(u64, String)>> {
        let conn = self.conn.lock().unwrap();
        let from = max_height.saturating_sub(RECENT_HASH_WINDOW);
        let mut stmt = conn.prepare(
            "SELECT height, hash FROM chain_hashes
             WHERE height > ?1 AND height <= ?2 ORDER BY height ASC",
        )?;
        let rows = stmt
            .query_map(params![from as i64, max_height as i64], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// List all address book entries (alphabetical by label).
    pub fn address_book_entries(&self) -> Result<Vec<AddressBookEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, label, address FROM address_book ORDER BY label COLLATE NOCASE, id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(AddressBookEntry {
                    id: r.get(0)?,
                    label: r.get(1)?,
                    address: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Add an address book entry; returns its id.
    pub fn address_book_add(&self, label: &str, address: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        conn.execute(
            "INSERT INTO address_book(label, address, created_at) VALUES(?1, ?2, ?3)",
            params![label, address, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Remove an address book entry by id; returns whether one was deleted.
    pub fn address_book_remove(&self, id: i64) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute("DELETE FROM address_book WHERE id=?1", params![id])? > 0)
    }

    /// Roll back everything above `fork_height` (exclusive).
    /// Returns the number of removed outputs.
    pub fn rollback(&self, fork_height: u64) -> Result<usize> {
        let removed = {
            let conn = self.conn.lock().unwrap();
            let removed = conn.execute(
                "DELETE FROM outputs WHERE height > ?1",
                params![fork_height as i64],
            )?;
            conn.execute(
                "DELETE FROM history WHERE direction='In' AND height > ?1",
                params![fork_height as i64],
            )?;
            conn.execute(
                "UPDATE history SET confirmed=0, height=0
                 WHERE direction='Out' AND confirmed=1 AND height > ?1",
                params![fork_height as i64],
            )?;
            conn.execute(
                "DELETE FROM chain_hashes WHERE height > ?1",
                params![fork_height as i64],
            )?;
            removed
        };
        self.set_scan_height(fork_height + 1)?;
        Ok(removed)
    }
}

fn row_to_output(r: &rusqlite::Row) -> rusqlite::Result<StoredOutput> {
    Ok(StoredOutput {
        key_hex: r.get(0)?,
        wallet_output_hex: r.get(1)?,
        amount: r.get::<_, i64>(2)? as u64,
        height: r.get::<_, i64>(3)? as u64,
        timestamp: r.get::<_, i64>(4)? as u64,
        spent: r.get::<_, i64>(5)? != 0,
        spent_tx: r.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::balance::TransferDirection;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("muff-db-test-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn test_output(key: &str, amount: u64, height: u64) -> StoredOutput {
        StoredOutput {
            key_hex: key.to_string(),
            wallet_output_hex: format!("deadbeef-{key}"),
            amount,
            height,
            timestamp: 1_700_000_000 + height,
            spent: false,
            spent_tx: None,
        }
    }

    fn out_record(tx: &str, height: u64) -> TransferRecord {
        TransferRecord {
            tx_hash: tx.to_string(),
            height,
            timestamp: 1_700_000_000 + height,
            amount: 500,
            fee: 30,
            direction: TransferDirection::Out,
            confirmed: height > 0,
            failed: false,
            note: "To someone".to_string(),
        }
    }

    #[test]
    fn test_crypto_roundtrip() {
        let salt = [7u8; SALT_LEN];
        let key = derive_key(b"password", &salt).unwrap();
        let (nonce, ct) = encrypt(&key, b"hello wallet").unwrap();
        let pt = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(&*pt, b"hello wallet");

        // Wrong key fails authentication.
        let other = derive_key(b"wrong", &salt).unwrap();
        assert!(decrypt(&other, &nonce, &ct).is_err());

        // Tampered ciphertext fails authentication.
        let mut ct2 = ct.clone();
        let last = ct2.len() - 1;
        ct2[last] ^= 1;
        assert!(decrypt(&key, &nonce, &ct2).is_err());
    }

    #[test]
    fn test_create_save_open_roundtrip() {
        let path = temp_path("muff.wallet");
        let seed = [42u8; 32];
        {
            let db = WalletDb::create(&path, b"pw", &seed, "stagenet", 123).unwrap();
            db.set_scan_height(456).unwrap();
            db.insert_received_output(&test_output("k1", 1000, 10), "txin1", "Primary address")
                .unwrap();
            db.save().unwrap();
        }
        // File format is detected as the encrypted db.
        assert_eq!(detect_format(&path).unwrap(), WalletFileFormat::EncryptedDb);
        // Header leaks nothing about contents; no SQLite magic present.
        let raw = std::fs::read(&path).unwrap();
        assert!(raw.starts_with(MAGIC));
        assert!(
            !raw.windows(16).any(|w| w == b"SQLite format 3\0"),
            "plaintext SQLite header must never appear on disk"
        );

        let db = WalletDb::open(&path, b"pw").unwrap();
        assert_eq!(&*db.seed().unwrap(), &seed);
        assert_eq!(db.network().unwrap(), "stagenet");
        assert_eq!(db.restore_height().unwrap(), 123);
        assert_eq!(db.scan_height().unwrap(), 456);
        let (outputs, history) = db.ui_snapshot().unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].amount, 1000);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].tx_hash, "txin1");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[7u8; 32], "mainnet", 0).unwrap();
        db.save().unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "wallet file must not be world/group readable");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_wrong_password_rejected() {
        let path = temp_path("muff.wallet");
        WalletDb::create(&path, b"correct", &[1u8; 32], "mainnet", 0).unwrap();
        assert!(WalletDb::open(&path, b"wrong").is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_detect_format() {
        let path = temp_path("muff.wallet");
        assert_eq!(detect_format(&path).unwrap(), WalletFileFormat::Missing);
        std::fs::write(&path, b"{\"version\":1}").unwrap();
        assert_eq!(detect_format(&path).unwrap(), WalletFileFormat::LegacyJson);
        std::fs::write(&path, b"garbage-bytes").unwrap();
        assert_eq!(detect_format(&path).unwrap(), WalletFileFormat::Unknown);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_detect_format_does_not_treat_read_errors_as_missing() {
        let path = temp_path("wallet-directory");
        std::fs::create_dir_all(&path).unwrap();
        assert!(detect_format(&path).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_output_dedup_and_history() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[2u8; 32], "mainnet", 0).unwrap();

        let out = test_output("key-a", 700, 100);
        assert!(
            db.insert_received_output(&out, "txa", "Primary address")
                .unwrap()
        );
        // Same output key again (replay/burning bug): ignored.
        assert!(
            !db.insert_received_output(&out, "txa2", "Primary address")
                .unwrap()
        );

        let (outputs, history) = db.ui_snapshot().unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(history.len(), 1);

        // Outgoing spend: reserve, then confirm.
        db.mark_spent_by("key-a", "txout").unwrap();
        db.insert_history(&out_record("txout", 0)).unwrap();
        assert!(db.spendable_outputs().unwrap().is_empty());
        // Reserved-by-pending outputs are still key-image checked.
        let ki = db.outputs_for_ki_check(false).unwrap();
        assert_eq!(ki.len(), 1);
        assert!(
            db.confirm_out_transfer("txout", 150, 1_700_001_000)
                .unwrap()
        );
        let (outputs, history) = db.ui_snapshot().unwrap();
        assert!(outputs[0].spent);
        assert!(outputs[0].spent_tx.is_none());
        let rec = history.iter().find(|r| r.tx_hash == "txout").unwrap();
        assert!(rec.confirmed);
        assert_eq!(rec.height, 150);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_history_chronological_order() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[8u8; 32], "mainnet", 0).unwrap();

        // Receive at height 100.
        db.insert_received_output(&test_output("kc1", 100, 100), "txin100", "n")
            .unwrap();
        // Broadcast a send (pending: height 0) ...
        db.insert_history(&out_record("txsend", 0)).unwrap();
        // ... then a later-scanned receive at height 101 lands *after* the
        // pending send in insertion order ...
        db.insert_received_output(&test_output("kc2", 100, 101), "txin101", "n")
            .unwrap();
        // ... and the send finally mines at height 102, updated in place.
        assert!(
            db.confirm_out_transfer("txsend", 102, 1_700_000_102)
                .unwrap()
        );

        // Snapshot must be chronological by block height, not by row id.
        let (_, history) = db.ui_snapshot().unwrap();
        let order: Vec<&str> = history.iter().map(|r| r.tx_hash.as_str()).collect();
        assert_eq!(order, ["txin100", "txin101", "txsend"]);

        // A still-pending send is the newest activity: it sorts last.
        db.insert_history(&out_record("txpend", 0)).unwrap();
        let (_, history) = db.ui_snapshot().unwrap();
        assert_eq!(history.last().unwrap().tx_hash, "txpend");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_dropped_tx_releases_output() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[3u8; 32], "mainnet", 0).unwrap();
        db.insert_received_output(&test_output("kb", 900, 20), "txb", "note")
            .unwrap();
        db.mark_spent_by("kb", "txdrop").unwrap();
        db.insert_history(&out_record("txdrop", 0)).unwrap();

        let released = db.release_output("kb").unwrap();
        assert_eq!(released.as_deref(), Some("txdrop"));
        let (outputs, history) = db.ui_snapshot().unwrap();
        assert!(!outputs[0].spent);
        assert!(outputs[0].spent_tx.is_none());
        assert!(
            history
                .iter()
                .find(|r| r.tx_hash == "txdrop")
                .unwrap()
                .failed
        );
        assert_eq!(db.spendable_outputs().unwrap().len(), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_rollback_semantics() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[4u8; 32], "mainnet", 0).unwrap();
        for h in [100u64, 105, 110, 115] {
            db.push_hash(h, &format!("hash{h}")).unwrap();
        }
        db.insert_received_output(&test_output("ko1", 100, 100), "tx1", "n")
            .unwrap();
        db.insert_received_output(&test_output("ko2", 200, 112), "tx2", "n")
            .unwrap();
        let mut confirmed = out_record("txc", 114);
        db.insert_history(&confirmed).unwrap();
        confirmed = out_record("txold", 50);
        db.insert_history(&confirmed).unwrap();
        db.set_scan_height(116).unwrap();

        // Fork at 110: everything above 110 is unwound.
        let removed = db.rollback(110).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(db.scan_height().unwrap(), 111);
        assert_eq!(db.recorded_hash(110).unwrap().as_deref(), Some("hash110"));
        assert!(db.recorded_hash(115).unwrap().is_none());

        let (outputs, history) = db.ui_snapshot().unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].key_hex, "ko1");
        // Incoming above fork removed; outgoing above fork back to pending;
        // outgoing below fork untouched.
        assert!(!history.iter().any(|r| r.tx_hash == "tx2"));
        let txc = history.iter().find(|r| r.tx_hash == "txc").unwrap();
        assert!(!txc.confirmed);
        assert_eq!(txc.height, 0);
        assert!(
            history
                .iter()
                .find(|r| r.tx_hash == "txold")
                .unwrap()
                .confirmed
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_hash_window_bounded() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[5u8; 32], "mainnet", 0).unwrap();
        for h in 0..1100u64 {
            db.push_hash(h, &format!("h{h}")).unwrap();
        }
        // Oldest entries evicted beyond the window.
        assert!(db.recorded_hash(50).unwrap().is_none());
        assert_eq!(db.recorded_hash(1099).unwrap().as_deref(), Some("h1099"));
        let window = db.hash_window(1099).unwrap();
        assert_eq!(window.len(), RECENT_HASH_WINDOW as usize);
        assert_eq!(window[0].0, 1099 - RECENT_HASH_WINDOW + 1);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_set_password_roundtrip() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"old-pw", &[6u8; 32], "mainnet", 0).unwrap();
        db.set_password(b"new-pw").unwrap();
        drop(db);
        // The old password no longer opens the file...
        assert!(WalletDb::open(&path, b"old-pw").is_err());
        // ...and the new one does.
        let db = WalletDb::open(&path, b"new-pw").unwrap();
        assert_eq!(*db.seed().unwrap(), [6u8; 32]);
        // Saving after reopening still works.
        db.save().unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_address_book_crud() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[7u8; 32], "mainnet", 0).unwrap();
        assert!(db.address_book_entries().unwrap().is_empty());

        let id_b = db.address_book_add("Bob", "4bbb").unwrap();
        let id_a = db.address_book_add("alice", "4aaa").unwrap();
        let entries = db.address_book_entries().unwrap();
        // Sorted case-insensitively by label.
        assert_eq!(
            entries,
            vec![
                AddressBookEntry {
                    id: id_a,
                    label: "alice".into(),
                    address: "4aaa".into()
                },
                AddressBookEntry {
                    id: id_b,
                    label: "Bob".into(),
                    address: "4bbb".into()
                },
            ]
        );

        // Entries survive a save/open cycle (also covers the open-time
        // schema migration path for older databases).
        db.save().unwrap();
        drop(db);
        let db = WalletDb::open(&path, b"pw").unwrap();
        assert_eq!(db.address_book_entries().unwrap().len(), 2);

        assert!(db.address_book_remove(id_a).unwrap());
        assert!(!db.address_book_remove(id_a).unwrap());
        let remaining = db.address_book_entries().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].label, "Bob");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_pending_out_transfers() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[8u8; 32], "mainnet", 0).unwrap();
        assert!(db.pending_out_transfers().unwrap().is_empty());

        db.insert_history(&out_record("txpending", 0)).unwrap();
        db.insert_history(&out_record("txconfirmed", 0)).unwrap();
        db.confirm_out_transfer("txconfirmed", 100, 1_700_000_000)
            .unwrap();
        let mut pending = db.pending_out_transfers().unwrap();
        pending.sort();
        assert_eq!(pending, vec!["txpending".to_string()]);

        // A failed transfer is not pending either.
        db.insert_history(&out_record("txfailed", 0)).unwrap();
        {
            let conn = db.conn.lock().unwrap();
            conn.execute("UPDATE history SET failed=1 WHERE tx_hash='txfailed'", [])
                .unwrap();
        }
        let mut pending = db.pending_out_transfers().unwrap();
        pending.sort();
        assert_eq!(pending, vec!["txpending".to_string()]);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_seed_format_and_polyseed_phrase() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[9u8; 32], "mainnet", 0).unwrap();

        // Existing/plain wallets default to legacy with no stored phrase.
        assert_eq!(db.seed_format(), SeedFormat::Legacy);
        assert_eq!(db.polyseed_phrase().unwrap(), None);

        let phrase = "raven tail swear infant grief assist regular lamp \
                      duck valid someone little harsh puppy airport language";
        db.set_seed_format(SeedFormat::Polyseed).unwrap();
        db.set_polyseed_phrase(phrase).unwrap();
        assert_eq!(db.seed_format(), SeedFormat::Polyseed);

        // Survives a save/open cycle.
        db.save().unwrap();
        drop(db);
        let db = WalletDb::open(&path, b"pw").unwrap();
        assert_eq!(db.seed_format(), SeedFormat::Polyseed);
        assert_eq!(db.polyseed_phrase().unwrap().as_deref(), Some(phrase));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn test_failed_password_change_restores_old_encryption_key() {
        let path = temp_path("muff.wallet");
        let mut db = WalletDb::create(&path, b"old-pw", &[6u8; 32], "mainnet", 0).unwrap();

        // Renaming a temp file over an existing directory fails before the
        // wallet image is replaced, exercising password-change rollback.
        let invalid_target = path.parent().unwrap().join("existing-directory");
        std::fs::create_dir(&invalid_target).unwrap();
        db.path = invalid_target;
        assert!(db.set_password(b"new-pw").is_err());

        db.path = path.clone();
        db.save().unwrap();
        drop(db);
        assert!(WalletDb::open(&path, b"old-pw").is_ok());
        assert!(WalletDb::open(&path, b"new-pw").is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn signed_transfer_persists_exact_blob_and_immutable_ring() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[11u8; 32], "mainnet", 0).unwrap();
        db.insert_received_output(&test_output("input-a", 900, 10), "in-a", "n")
            .unwrap();

        let first = out_record("signed-a", 0);
        let ring = ("image-a".to_string(), vec![1, 2, 3]);
        db.record_signed_transfer(
            &["input-a".into()],
            std::slice::from_ref(&ring),
            &[9, 8, 7],
            &first,
        )
        .unwrap();
        assert_eq!(
            db.ring_for_key_image("image-a").unwrap(),
            Some(ring.1.clone())
        );
        assert_eq!(
            db.unrelayed_transactions(u64::MAX).unwrap(),
            vec![("signed-a".to_string(), vec![9, 8, 7])]
        );
        assert!(db.pending_out_transfers().unwrap().is_empty());
        assert!(db.transaction_awaiting_relay("signed-a").unwrap());

        db.reject_signed_transfer("signed-a").unwrap();
        assert!(
            db.spendable_outputs()
                .unwrap()
                .iter()
                .any(|o| o.key_hex == "input-a")
        );
        assert_eq!(
            db.ring_for_key_image("image-a").unwrap(),
            Some(ring.1.clone())
        );

        let replacement = out_record("signed-b", 0);
        assert!(
            db.record_signed_transfer(
                &["input-a".into()],
                &[("image-a".to_string(), vec![4, 5, 6])],
                &[6, 5, 4],
                &replacement,
            )
            .is_err(),
            "a replacement ring for the same key image must be refused"
        );
        db.record_signed_transfer(&["input-a".into()], &[ring], &[6, 5, 4], &replacement)
            .unwrap();
        db.mark_transaction_relayed("signed-b").unwrap();
        assert!(db.unrelayed_transactions(u64::MAX).unwrap().is_empty());
        assert_eq!(db.pending_out_transfers().unwrap(), vec!["signed-b"]);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn signed_transfer_reservation_is_atomic() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[13u8; 32], "mainnet", 0).unwrap();
        db.insert_received_output(&test_output("input-a", 400, 10), "in-a", "n")
            .unwrap();
        db.insert_received_output(&test_output("input-b", 600, 11), "in-b", "n")
            .unwrap();
        db.mark_spent_by("input-b", "another-transfer").unwrap();

        let record = out_record("signed-conflict", 0);
        assert!(
            db.record_signed_transfer(
                &["input-a".into(), "input-b".into()],
                &[("image-a".into(), vec![1]), ("image-b".into(), vec![2])],
                &[7, 7, 7],
                &record,
            )
            .is_err()
        );
        let (outputs, history) = db.ui_snapshot().unwrap();
        let input_a = outputs
            .iter()
            .find(|output| output.key_hex == "input-a")
            .unwrap();
        assert!(!input_a.spent);
        assert!(db.ring_for_key_image("image-a").unwrap().is_none());
        assert!(
            !history
                .iter()
                .any(|entry| entry.tx_hash == "signed-conflict")
        );
        assert!(db.unrelayed_transactions(u64::MAX).unwrap().is_empty());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn receive_subaddress_cursor_only_moves_forward() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[12u8; 32], "mainnet", 0).unwrap();
        assert_eq!(db.next_receive_minor().unwrap(), 1);
        db.advance_receive_minor(8).unwrap();
        db.advance_receive_minor(3).unwrap();
        assert_eq!(db.next_receive_minor().unwrap(), 8);
        db.save().unwrap();
        drop(db);
        let reopened = WalletDb::open(&path, b"pw").unwrap();
        assert_eq!(reopened.next_receive_minor().unwrap(), 8);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn address_allocation_and_send_source_are_persistent() {
        let path = temp_path("muff.wallet");
        let db = WalletDb::create(&path, b"pw", &[14u8; 32], "mainnet", 0).unwrap();
        assert_eq!(
            db.receive_address_count().unwrap(),
            DEFAULT_RECEIVE_ADDRESS_COUNT
        );

        let new_minor = db.allocate_receive_address().unwrap();
        assert_eq!(new_minor, DEFAULT_RECEIVE_ADDRESS_COUNT);
        assert_eq!(
            db.receive_address_count().unwrap(),
            DEFAULT_RECEIVE_ADDRESS_COUNT + 1
        );
        db.set_selected_send_subaddress(0, new_minor).unwrap();
        assert_eq!(db.selected_send_subaddress().unwrap(), (0, new_minor));
        assert!(
            db.set_selected_send_subaddress(0, new_minor.saturating_add(1))
                .is_err()
        );

        db.save().unwrap();
        drop(db);
        let reopened = WalletDb::open(&path, b"pw").unwrap();
        assert_eq!(
            reopened.receive_address_count().unwrap(),
            DEFAULT_RECEIVE_ADDRESS_COUNT + 1
        );
        assert_eq!(reopened.selected_send_subaddress().unwrap(), (0, new_minor));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
