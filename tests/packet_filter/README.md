# packet_filter test suite

Black-box regression for the three impairment packet filters that were
previously only exercised in passing (delay had its own suite; `corrupt`,
`frequency_drop` and `packet_loss` had no direct coverage). Each drives
ubridge's hypervisor protocol over a 2-NIO UDP bridge and counts / inspects
what exits the peer NIO.

## Prerequisites

Just the in-repo binary (these filters are pure user-space):

```bash
make            # builds ./ubridge
```

No `sudo make install`, no CAP_NET_ADMIN.

## Running

```bash
cd tests/packet_filter

# one suite
python3 test_frequency_drop.py

# everything
python3 run_all.py
```

`run_all.py` exits non-zero if any suite fails, so it can gate CI.

## Suites

| Suite | What it covers |
|-------|----------------|
| `test_frequency_drop.py` | Deterministic 1-in-N drop: N>0 drops every Nth, N=0 passes all, N=-1 blackholes, identical runs are bit-for-bit repeatable, missing-value rejected (206). |
| `test_packet_loss.py` | Random %-based drop: 100% drops all, 50% ~halves (statistical band), 0% passes ~all (documents the `<=` off-by-one), monotonic in percentage, out-of-range rejected (206). |
| `test_corrupt.py` | Random %-based bit damage: at 100% every frame arrives changed with leading/trailing bytes intact and the middle slice XORed, corrupt never drops at any %, out-of-range rejected (206). |

## Conventions

- Re-uses the delay suite's `build_bridge` / `send_burst` / `recv_count` /
  `bound_udp` via `helpers.py` (loaded by file path, no shared package).
- Topology and the connected-NIO injection model are the same as the delay
  suite — see `tests/delay/test_latency.py` for the diagram.
