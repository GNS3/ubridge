# tc test suite

Black-box tests for the `tc` hypervisor module (kernel netem link
impairment: delay/jitter/loss/dup/corrupt, qdisc reset).

## Prerequisites

- `CAP_NET_ADMIN` — run under sudo (or `unshare -Urn`).
- The **`tc` and `ip` command-line tools** — used by the *tests* to verify
  kernel-side state (`tc qdisc show`, `ip link`). This is a test-only
  dependency: ubridge itself talks netlink directly and needs no iproute2
  tools at runtime.
  - Debian/Ubuntu: `iproute2` (the `tc` binary is included)
  - openSUSE/Fedora: `iproute2` + `iproute2-tc` (tc is a separate package)
- If `tc` is missing the suite prints `[SKIP]` and exits 0 — a vacuous pass,
  so CI (which installs iproute2 explicitly) is the real gate for it.

The tests run ubridge themselves (control socket /tmp/ubridge-test-13040.sock)
and tear it down when done.

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
