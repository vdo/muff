# 🧁 muff - TUI Monero Wallet

> **⚠️ Disclaimer**
>
> This wallet has been coded with AI (Kimi K3) and is **experimental
> software**. It has not been audited and may contain bugs that could lead
> to **loss of funds**. Use it for **testnet/stagenet XMR or small amounts
> of mainnet XMR only**. There is no warranty of any kind — you are solely
> responsible for your funds. Always write down your seed phrase and keep a
> backup before putting anything of value into this wallet.

A Monero wallet with a terminal UI (TUI), written in Rust. It talks to a
local node or any monerod-compatible daemon RPC endpoint and stores everything
in a single encrypted wallet file.

## Features

- Encrypted wallet file (`muff.wallet`): ChaCha20-Poly1305 encryption with
  an Argon2-derived key.
- Polyseed (16-word) and legacy 25-word mnemonic support, optionally seeded
  from your own dice rolls or coin flips
- First-run wizard: create a new wallet or restore from seed, entering either
  a block height or just the date the wallet was created
- Daemon failover: extra nodes are tried in order when the primary goes
  quiet, with an optional bundled list of public nodes
- Tabs: **Dashboard** (balance, node status, recent activity, logs),
  **Send** (fee priority tiers, sweep-all, address book), **Addresses**
  (per-address balances, send-source selection, QR codes), **History**
  (chronological transfers with details, CSV export), **Config**
  (password-gated seed/key reveal, change password, change daemon,
  switch node)
- Outgoing transactions tracked through broadcast → mined → dropped states
- Mouse support (clickable tabs, rows, buttons)
- Passwords and keys zeroized in memory when no longer needed

## Building

```sh
cargo build --release
```

The binary is at `target/release/muff`.

## Running

You need a reachable Monero daemon RPC endpoint — ideally your own local
[Cuprate](https://github.com/Cuprate/cuprate) node or `monerod`.

If the primary node stops answering for ~15 seconds, muff moves to the next
endpoint in `daemon.nodes` and keeps syncing; the Node panel says which one is
in use whenever it is not your configured primary. Setting
`daemon.use_public_nodes = true` adds a bundled list of third-party public
nodes to the end of that rotation. It is off by default on purpose — a public
node sees your IP address and the transactions you ask about. `.onion`/`.i2p`
endpoints are only offered when `daemon.proxy` is set, since they cannot
resolve otherwise.

```sh
./target/release/muff
```

On first run a wizard walks you through creating or restoring a wallet.
Settings are read from `config.toml` (in the current directory by
default); the wallet file defaults to the platform data dir
(e.g. `~/Library/Application Support/muff/muff.wallet` on macOS).

Useful flags (see `muff --help`):

```
-c, --config <PATH>      Path to configuration file (default: config.toml)
-d, --daemon-url <URL>   Daemon RPC URL (overrides config)
-n, --network <NET>      mainnet, stagenet, or testnet
-w, --wallet <PATH>      Wallet file path (overrides config)
    --password <PW>      Wallet password (otherwise prompted interactively)
```

Example against a local stagenet node:

```sh
./target/release/muff --daemon-url http://127.0.0.1:38081 --network stagenet
```

## Security notes

- The wallet file is encrypted at rest and written with `0600`
  permissions; daemon-reported fee rates are sanity-capped.
- New seeds are 32 bytes (256 bits) of entropy from the OS CSPRNG
  (`rand::thread_rng` → ChaCha12, seeded by `getrandom`) — the same class
  of randomness used by other software wallets; as safe as your machine is.
- If you would rather not take the CSPRNG's word for it, option [3] in the
  wizard builds a Polyseed from dice rolls or coin flips. The rolls are
  *mixed with* system entropy rather than replacing it, so a biased die or a
  miscount cannot make the seed weaker than a normal one.
- That said, again, this is young, AI-written code: prefer running it against
  your **own** node, on **stagenet/testnet**, or with **small mainnet amounts**
  you can afford to lose.

### Monero `wallet2` privacy alignment

Muff aims for statistical compatibility with the transaction policies in
Monero `wallet2` v0.18.5.1. It follows the reference wallet's input
relatedness and preferred-input rules, fee priorities, 16-member rings,
Gamma-distributed decoy ages, transaction-wide ring sanity checks, persistent
ring reuse, and subaddress lookahead. Exact signed transaction bytes are also
retained when relay is uncertain so retrying cannot create an intersecting
replacement ring.

Decoy sampling and transaction signing remain delegated to
`monero-wallet` 0.2.0. This provides the same statistical decoy model, but is
not an exact reimplementation of `wallet2`: it requests candidates from the
daemon differently, excludes the identity point as a decoy key, has no
`wallet2` blackball database, and uses an independent Gamma sampler and CSPRNG.
Consequently, privacy-policy alignment should not be read as a guarantee that
Muff transactions or daemon traffic are perfectly indistinguishable from
those produced by the reference wallet.

## Acknowledgements

The restore-height checkpoint tables and the public node list in `assets/`
are vendored from [Feather](https://github.com/feather-wallet/feather)
(BSD-3-Clause; see `assets/README.md` and `assets/LICENSE.feather`). The
dice-entropy scheme follows Feather's `SeedDiceDialog`, so the same rolls
produce the same seed in both wallets.

Built on the Monero ecosystem's Rust crates:

- [`monero`](https://github.com/monero-rs/monero-rs) — core consensus types
  (addresses, blocks, networks, subaddress derivation, key types)
- [`monero-rpc`](https://github.com/monero-rs/monero-rpc-rs) — typed daemon
  RPC client
- [`monero-wallet`](https://github.com/monero-oxide/monero-oxide)
  (monero-oxide) — blockchain scanner, transaction building and signing,
  decoy selection, fee handling
- [`curve25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek)
  — the Ed25519/curve arithmetic behind key derivation and one-time key
  recovery

## License

MIT
