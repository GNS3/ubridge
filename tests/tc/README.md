# tc test suite

Black-box tests for the `tc` hypervisor module (kernel netem link
impairment: delay/jitter/loss/dup/corrupt, qdisc reset).

## Prerequisites

- `CAP_NET_ADMIN` — run under sudo (or `unshare -Urn`).
- The **`tc` and `ip` command-line tools** — used by the *tests* to verify
  kernel-side state (`tc qdisc show`, `ip link`). This is a test-only
  dependency: ubridge itself talks netlink directly and needs no iproute2
  tools at runtime.
- `tc` ships with the `iproute2` package on all major distros, but lives in
  `/usr/sbin` on several of them — a non-root `PATH` (and the `PATH` inherited
  into `unshare`) may not include it. The suite falls back to `/usr/sbin/tc`
  and `/sbin/tc` and only skips when the tool is truly absent (a vacuous
  pass — CI, which installs iproute2, is the real gate).

The tests run ubridge themselves (control socket /tmp/ubridge-test-13040.sock)
and tear it down when done. They drive the **in-repo** `./ubridge` (run `make`
first) — the installed `/usr/local/bin/ubridge` may be older than the tree
(same convention as the marker suite).

## Running

```bash
cd tests/tc

# one suite
sudo python3 test_basic.py

# everything
sudo python3 run_all.py
```

`run_all.py` exits non-zero if any suite fails, so it can gate CI.

## Suites

| Suite | What it covers |
|-------|----------------|
| `test_basic.py` | netem set with all five parameters (delay, jitter, loss, dup, corrupt — kernel-verified via `tc qdisc show`), REPLACE semantics on re-set, reset (idempotent: no qdisc → 100), param validation (203/204), missing iface (206/207). |
