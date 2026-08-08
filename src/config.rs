use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Application configuration loaded from TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Daemon RPC settings
    pub daemon: DaemonConfig,
    /// Wallet settings
    pub wallet: WalletConfig,
    /// UI settings
    pub ui: UiConfig,
    /// Security settings
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// URL of the Cuprate/monerod daemon RPC endpoint
    pub url: String,
    /// Optional proxy (e.g. socks5://127.0.0.1:9050 for Tor)
    pub proxy: Option<String>,
    /// Additional endpoints to fall back to when `url` stops responding,
    /// tried in order. Your own nodes: nothing here is contacted unless the
    /// primary fails.
    #[serde(default)]
    pub nodes: Vec<String>,
    /// Also fall back to the bundled list of third-party public nodes.
    ///
    /// Off by default, and deliberately so: a public node operator sees the
    /// IP address behind every request and can link it to the transactions
    /// you ask about. Enable it only if that trade is acceptable.
    #[serde(default)]
    pub use_public_nodes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Path to the encrypted wallet file
    pub path: PathBuf,
    /// Monero network
    pub network: NetworkKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkKind {
    Mainnet,
    Stagenet,
    Testnet,
}

impl NetworkKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Stagenet => "stagenet",
            Self::Testnet => "testnet",
        }
    }
}

impl From<NetworkKind> for monero::Network {
    fn from(n: NetworkKind) -> Self {
        match n {
            NetworkKind::Mainnet => monero::Network::Mainnet,
            NetworkKind::Stagenet => monero::Network::Stagenet,
            NetworkKind::Testnet => monero::Network::Testnet,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Target FPS for rendering
    pub tick_rate_ms: u64,
    /// Show amounts in atomic units instead of XMR
    pub show_atomic: bool,
}

/// Security settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Lock the wallet (wipe keys/password from memory, stop the scanner)
    /// after this many seconds without user input. `0` disables auto-lock.
    pub idle_timeout_secs: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: 300,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let wallet_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("muff");

        Self {
            daemon: DaemonConfig {
                url: "http://127.0.0.1:18081".to_string(),
                proxy: None,
                nodes: Vec::new(),
                use_public_nodes: false,
            },
            wallet: WalletConfig {
                path: wallet_dir.join("muff.wallet"),
                network: NetworkKind::Mainnet,
            },
            ui: UiConfig {
                tick_rate_ms: 100,
                show_atomic: false,
            },
            security: SecurityConfig::default(),
        }
    }
}

impl Config {
    /// Load config from a TOML file, falling back to defaults if not found.
    pub fn load(path: &std::path::Path) -> color_eyre::Result<Self> {
        if path.exists() {
            let contents = std::fs::read_to_string(path)?;
            let config: Config = toml::from_str(&contents)?;
            Ok(config)
        } else {
            let config = Config::default();
            // Write default config so user can edit it
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let toml_str = toml::to_string_pretty(&config)?;
            std::fs::write(path, toml_str)?;
            tracing::info!("Created default config at {}", path.display());
            Ok(config)
        }
    }

    /// Persist the current configuration as TOML (used by runtime edits,
    /// e.g. changing the daemon address from the config screen).
    pub fn save(&self, path: &std::path::Path) -> color_eyre::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let toml_str = toml::to_string_pretty(self)?;
        std::fs::write(path, toml_str)?;
        Ok(())
    }

    /// Ensure the wallet directory exists.
    pub fn ensure_wallet_dir(&self) -> color_eyre::Result<()> {
        if let Some(parent) = self.wallet.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Configs written before the failover fields existed must keep loading.
    #[test]
    fn older_configs_without_node_fields_still_parse() {
        let toml = r#"
[daemon]
url = "http://127.0.0.1:18081"

[wallet]
path = "/tmp/muff.wallet"
network = "stagenet"

[ui]
tick_rate_ms = 100
show_atomic = false
"#;
        let config: Config = toml::from_str(toml).expect("legacy config should parse");
        assert_eq!(config.daemon.url, "http://127.0.0.1:18081");
        assert!(config.daemon.nodes.is_empty());
        // Absent must mean "do not contact strangers".
        assert!(!config.daemon.use_public_nodes);
        assert_eq!(config.wallet.network, NetworkKind::Stagenet);
    }

    #[test]
    fn node_fields_round_trip_through_toml() {
        let mut config = Config::default();
        config.daemon.nodes = vec!["http://a:1".to_string()];
        config.daemon.use_public_nodes = true;

        let rendered = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&rendered).unwrap();
        assert_eq!(parsed.daemon.nodes, config.daemon.nodes);
        assert!(parsed.daemon.use_public_nodes);
    }

    #[test]
    fn the_shipped_example_config_parses() {
        let raw = include_str!("../config.toml");
        let config: Config = toml::from_str(raw).expect("config.toml should parse");
        // The example must not opt users into third-party nodes.
        assert!(!config.daemon.use_public_nodes);
    }
}
