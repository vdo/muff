//! Candidate daemon endpoints and the order to try them in.
//!
//! muff talks to one daemon at a time, but a single hard-coded URL means any
//! node restart or network blip strands a long-running TUI. This keeps an
//! ordered pool so [`crate::app::AppState`] can rotate to the next endpoint
//! when the active one stops answering.
//!
//! The pool is deliberately conservative about *which* nodes it will
//! consider:
//!
//! - The configured `daemon.url` is always first. Whatever else happens,
//!   muff prefers the node the user chose.
//! - `daemon.nodes` (their own fallbacks) come next.
//! - Feather's bundled list of third-party public nodes is used only when
//!   `daemon.use_public_nodes` is explicitly enabled. Using someone else's
//!   node hands them the ability to link your IP to your transactions, so
//!   that has to be a decision, not a default.
//! - `.onion`/`.i2p` endpoints are only offered when a proxy is configured,
//!   because without one they cannot resolve and would just burn a failover
//!   slot each rotation.

use crate::config::{Config, NetworkKind};
use crate::rpc::daemon::normalize_url;
use std::collections::HashSet;

/// Feather's public node list (see `assets/README.md` for provenance).
const BUNDLED_NODES: &str = include_str!("../../assets/nodes.json");

/// Where a candidate came from — surfaced in the UI so a third-party node is
/// never mistaken for one of the user's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeSource {
    /// The `daemon.url` the user is configured to use.
    Primary,
    /// An extra endpoint from `daemon.nodes`.
    Configured,
    /// A third-party public node from the bundled list.
    Public,
}

impl NodeSource {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Configured => "configured",
            Self::Public => "public (third-party)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCandidate {
    pub url: String,
    pub source: NodeSource,
}

/// Parse the bundled list into normalized URLs for `network`.
///
/// `allow_hidden` admits `.onion`/`.i2p` endpoints; pass the "a proxy is
/// configured" answer.
fn bundled_for(network: NetworkKind, allow_hidden: bool) -> Vec<String> {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(BUNDLED_NODES) else {
        tracing::warn!("bundled node list is not valid JSON; ignoring it");
        return Vec::new();
    };
    let Some(section) = parsed.get(network.as_str()) else {
        return Vec::new();
    };

    // Clearnet first: reachable without extra setup and typically faster.
    let mut groups = vec!["clearnet"];
    if allow_hidden {
        groups.extend(["tor", "i2p"]);
    }

    groups
        .into_iter()
        .filter_map(|group| section.get(group)?.as_array())
        .flatten()
        .filter_map(|entry| entry.as_str())
        .filter(|entry| !entry.trim().is_empty())
        .map(normalize_url)
        .collect()
}

/// True for endpoints that only resolve through a proxy.
fn is_hidden_service(url: &str) -> bool {
    let host = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = host.split(['/', ':']).next().unwrap_or(host);
    host.ends_with(".onion") || host.ends_with(".i2p")
}

/// An ordered set of daemon endpoints with a cursor on the active one.
#[derive(Debug, Clone)]
pub struct NodePool {
    candidates: Vec<NodeCandidate>,
    active: usize,
}

impl NodePool {
    pub fn new(config: &Config) -> Self {
        let has_proxy = config.daemon.proxy.is_some();
        let mut candidates: Vec<NodeCandidate> = Vec::new();
        // Endpoints can legitimately repeat across the three sources; the
        // pool must not offer the same dead node twice per rotation.
        let mut seen: HashSet<String> = HashSet::new();

        let mut push = |url: String, source: NodeSource, candidates: &mut Vec<NodeCandidate>| {
            if url.is_empty() || !seen.insert(url.clone()) {
                return;
            }
            if is_hidden_service(&url) && !has_proxy {
                tracing::debug!("skipping {url}: hidden service with no proxy configured");
                return;
            }
            candidates.push(NodeCandidate { url, source });
        };

        push(
            normalize_url(&config.daemon.url),
            NodeSource::Primary,
            &mut candidates,
        );
        for url in &config.daemon.nodes {
            push(normalize_url(url), NodeSource::Configured, &mut candidates);
        }
        if config.daemon.use_public_nodes {
            for url in bundled_for(config.wallet.network, has_proxy) {
                push(url, NodeSource::Public, &mut candidates);
            }
        }

        Self {
            candidates,
            active: 0,
        }
    }

    pub fn candidates(&self) -> &[NodeCandidate] {
        &self.candidates
    }

    pub fn active_index(&self) -> usize {
        self.active
    }

    pub fn active(&self) -> Option<&NodeCandidate> {
        self.candidates.get(self.active)
    }

    /// Whether rotating would actually reach a different endpoint.
    pub fn can_fail_over(&self) -> bool {
        self.candidates.len() > 1
    }

    /// Move the cursor to the next candidate, wrapping around, and return it.
    ///
    /// Wrapping means a pool whose nodes are all down keeps retrying the
    /// whole list rather than getting stuck on the last one — the outage may
    /// be local, in which case the primary is the one we want back.
    pub fn advance(&mut self) -> Option<&NodeCandidate> {
        if self.candidates.is_empty() {
            return None;
        }
        self.active = (self.active + 1) % self.candidates.len();
        self.active()
    }

    /// Point the cursor at `url` if the pool knows it, otherwise insert it as
    /// the new primary. Keeps the pool in step with a manual daemon change.
    pub fn select(&mut self, url: &str) {
        let normalized = normalize_url(url);
        match self.candidates.iter().position(|c| c.url == normalized) {
            Some(idx) => self.active = idx,
            None => {
                self.candidates.insert(
                    0,
                    NodeCandidate {
                        url: normalized,
                        source: NodeSource::Primary,
                    },
                );
                self.active = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn config(network: NetworkKind) -> Config {
        let mut c = Config::default();
        c.wallet.network = network;
        c.wallet.path = PathBuf::from("/tmp/muff-test.wallet");
        c
    }

    #[test]
    fn bundled_list_parses_for_every_network() {
        // Guards against a refreshed nodes.json changing shape underneath us.
        for network in [
            NetworkKind::Mainnet,
            NetworkKind::Stagenet,
            NetworkKind::Testnet,
        ] {
            let clearnet = bundled_for(network, false);
            assert!(
                !clearnet.is_empty(),
                "{network:?} has no bundled clearnet nodes"
            );
            for url in &clearnet {
                assert!(url.starts_with("http"), "{url} was not normalized");
                assert!(
                    !is_hidden_service(url),
                    "{url} leaked into the clearnet set"
                );
            }
        }
    }

    #[test]
    fn hidden_services_appear_only_with_a_proxy() {
        let without = bundled_for(NetworkKind::Mainnet, false);
        let with = bundled_for(NetworkKind::Mainnet, true);
        assert!(with.len() > without.len());
        assert!(with.iter().any(|u| is_hidden_service(u)));
    }

    #[test]
    fn detects_hidden_service_hosts() {
        assert!(is_hidden_service("http://abcd.onion:18081"));
        assert!(is_hidden_service("http://abcd.i2p"));
        assert!(!is_hidden_service("http://127.0.0.1:18081"));
        assert!(!is_hidden_service("http://node.onion.example.com:18081"));
    }

    /// The default config must not reach out to strangers.
    #[test]
    fn public_nodes_are_opt_in() {
        let pool = NodePool::new(&config(NetworkKind::Mainnet));
        assert_eq!(pool.candidates().len(), 1);
        assert_eq!(pool.active().unwrap().source, NodeSource::Primary);
        assert!(!pool.can_fail_over());
    }

    #[test]
    fn opting_in_adds_public_nodes_after_configured_ones() {
        let mut c = config(NetworkKind::Mainnet);
        c.daemon.nodes = vec!["node.example:18081".to_string()];
        c.daemon.use_public_nodes = true;
        let pool = NodePool::new(&c);

        assert_eq!(pool.candidates()[0].source, NodeSource::Primary);
        assert_eq!(pool.candidates()[1].source, NodeSource::Configured);
        assert_eq!(pool.candidates()[1].url, "http://node.example:18081");
        assert!(
            pool.candidates()[2..]
                .iter()
                .all(|c| c.source == NodeSource::Public)
        );
        assert!(pool.can_fail_over());
    }

    #[test]
    fn hidden_services_are_dropped_without_a_proxy() {
        let mut c = config(NetworkKind::Mainnet);
        c.daemon.use_public_nodes = true;
        c.daemon.nodes = vec!["somewhere.onion:18081".to_string()];

        let no_proxy = NodePool::new(&c);
        assert!(
            !no_proxy
                .candidates()
                .iter()
                .any(|n| is_hidden_service(&n.url))
        );

        c.daemon.proxy = Some("socks5://127.0.0.1:9050".to_string());
        let with_proxy = NodePool::new(&c);
        assert!(
            with_proxy
                .candidates()
                .iter()
                .any(|n| n.url == "http://somewhere.onion:18081")
        );
    }

    #[test]
    fn duplicates_collapse_to_one_slot() {
        let mut c = config(NetworkKind::Mainnet);
        c.daemon.url = "http://127.0.0.1:18081".to_string();
        // Same endpoint written three ways.
        c.daemon.nodes = vec![
            "127.0.0.1:18081".to_string(),
            "http://127.0.0.1:18081/".to_string(),
        ];
        let pool = NodePool::new(&c);
        assert_eq!(pool.candidates().len(), 1);
    }

    #[test]
    fn advance_wraps_around_the_pool() {
        let mut c = config(NetworkKind::Mainnet);
        c.daemon.url = "http://a:1".to_string();
        c.daemon.nodes = vec!["http://b:2".to_string(), "http://c:3".to_string()];
        let mut pool = NodePool::new(&c);

        assert_eq!(pool.active().unwrap().url, "http://a:1");
        assert_eq!(pool.advance().unwrap().url, "http://b:2");
        assert_eq!(pool.advance().unwrap().url, "http://c:3");
        // Wrapping back to the primary matters: the outage may be local.
        assert_eq!(pool.advance().unwrap().url, "http://a:1");
    }

    #[test]
    fn select_tracks_known_and_unknown_urls() {
        let mut c = config(NetworkKind::Mainnet);
        c.daemon.url = "http://a:1".to_string();
        c.daemon.nodes = vec!["http://b:2".to_string()];
        let mut pool = NodePool::new(&c);

        pool.select("b:2");
        assert_eq!(pool.active_index(), 1);
        assert_eq!(pool.active().unwrap().url, "http://b:2");

        // An endpoint typed by hand becomes the new primary.
        pool.select("http://fresh:9");
        assert_eq!(pool.active_index(), 0);
        assert_eq!(pool.active().unwrap().url, "http://fresh:9");
        assert_eq!(pool.candidates().len(), 3);
    }

    #[test]
    fn a_single_node_pool_never_reports_failover() {
        let mut pool = NodePool::new(&config(NetworkKind::Mainnet));
        let before = pool.active().unwrap().url.clone();
        assert!(!pool.can_fail_over());
        // Advancing a one-node pool is a no-op rather than an error.
        assert_eq!(pool.advance().unwrap().url, before);
    }
}
