# Vendored assets

These data files come from [Feather](https://github.com/feather-wallet/feather)
(`src/assets/`), which is BSD-3-Clause licensed by The Monero Project. The
license text is kept alongside them in `LICENSE.feather`; muff itself is MIT.

| File | Origin | Used by |
| --- | --- | --- |
| `restore_heights_monero_mainnet.txt` | Feather `src/assets/` | `src/wallet/restore_height.rs` |
| `restore_heights_monero_stagenet.txt` | Feather `src/assets/` | `src/wallet/restore_height.rs` |
| `nodes.json` | Feather `src/assets/` | `src/rpc/nodes.rs` |

## Refreshing

Both are periodic snapshots, not live data — they go stale silently rather
than loudly, which is the failure mode to watch for.

`restore_heights_*.txt` is `unix_timestamp:height`, one checkpoint per line,
ascending. Past the final checkpoint the lookup extrapolates at 120 s/block,
so a stale table degrades gracefully into a slightly worse estimate; the
5-day clearance in `date_to_height` absorbs the drift. Re-copying the file
from Feather is the only maintenance needed.

`nodes.json` is a list of *third-party* public nodes, and staleness here is
more consequential: a node that changes hands still resolves. The list is a
convenience for users without their own node, never the default — muff ships
pointing at `127.0.0.1`. Anyone using these is trusting the operator not to
log their IP against their transactions, which is why the node picker labels
them as third-party.

To refresh either file:

```sh
curl -sO https://raw.githubusercontent.com/feather-wallet/feather/master/src/assets/nodes.json
```
