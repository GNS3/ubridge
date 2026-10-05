# tc test suite

Black-box tests for the `tc` hypervisor module (kernel netem link
impairment, the P6a keyword extensions, the P6c `bpf_drop` classic-BPF
filters, the P6b eBPF stateful modes, and `tc capabilities`).

## Prerequisites

- `CAP_NET_ADMIN` — run under sudo (or `unshare -Urn`).
- The **`tc` and `ip` command-line tools** — used by the *tests* to verify
  kernel-side state (`tc qdisc show`, `ip link`). This is a test-only
  dependency: ubridge itself talks netlink directly and needs no iproute2
  tools at runtime.
- `tc` ships with the `iproute2` package on all major distros, but lives in
  `/usr/sbin` on several of them — a non-root `PATH` (and the `PATH`
  inherited into `unshare`) may not include it. The suites fall back to
  `/usr/sbin/tc` and `/sbin/tc` and only skip when the tool is truly absent
  (a vacuous pass — CI, which installs iproute2, is the real gate).
- The `seed` keyword is newer than some distros' `tc` (iproute2 6.1 — what
  Ubuntu 24.04 ships — lacks it): `test_netem_ext` probes for it once and
  skips the two `seed+limit` byte-compare checks when the CLI cannot
  express it. The kernel-side effect of the seed is still covered —
  `test_precision`'s determinism check needs no CLI.

The tests run ubridge themselves (control socket /tmp/ubridge-test-*.sock)
and tear it down when done. They drive the **in-repo** `./ubridge` (run `make`
first) — the installed `/usr/local/bin/ubridge` may be older than the tree
(same convention as the marker suite).

## Running

```bash
cd tests/tc

# one suite
sudo python3 test_basic.py        # or: unshare -Urn python3 test_basic.py

# everything
sudo python3 run_all.py
```

`run_all.py` exits non-zero if any suite fails, so it can gate CI.

## Suites

| Suite | What it covers |
|-------|----------------|
| `test_basic.py` | P5 surface: netem set with the five base parameters (delay, jitter, loss, dup, corrupt — kernel-verified via `tc qdisc show`), REPLACE semantics on re-set, reset (idempotent: no qdisc → 100), param validation (203/204), missing iface (207). |
| `test_netem_ext.py` | P6a extensions: `rate` (bit/kbit/mbit/gbit + bps-family bytes/s units, RATE64 path), `reorder` (+correl, gap, requires-delay), `loss gemodel` (p/r/1-h), `distribution` (embedded tables, uniform = no table), `seed`, `limit`, `correl` suffixes, `tc capabilities`. Verified by **byte-comparing the kernel's TCA_OPTIONS dump against what the real `tc` CLI produces for the same parameters**, plus `tc qdisc show` state, the full 203/204 error contract, and behavioral checks on a veth pair (delay lower bound, limit overflow, gemodel extremes) using raw AF_PACKET injection. |
| `test_bpf_drop.py` | P6c: `bpf_drop add` (prio 10-99, pcap expression) / `flush` / full-restore `reset` / capabilities `cbpf=1`. Byte-compare oracle: the kernel's TCA_BPF_OPS must equal an **independent libpcap compile** (ctypes) and dump identically to the real `tc` CLI's `bpf bytecode '<insns>' action drop`; action must be gact/TC_ACT_SHOT (RTM_GETTFILTER dump). Error contract (203/204/207/209), flush removes only ubridge-tracked prios (a foreign CLI filter survives), netem coexistence, veth behavioral (match dropped / non-match passes / multi-prio OR / flush restores). |
| `test_ebpf.py` | P6b stateful modes (`nth_drop`/`quota_drop`/`window_drop`/`flow_drop`, one eBPF program at clsact egress prio 1). Always (no `tc`, no capability): static checks of the committed instruction array — **no backward jumps** (a loop is rejected by the verifier's non-root path, which is what production uses), the `WIN_CATCHUP_STEPS` unrolling in sync and small, array length matching the header. That rejection is invisible from a root run, so it cannot be caught behaviorally here (see the "Verifier constraint" section of `doc/tc.md`). Without CAP_BPF (plain `unshare -Urn`, `unprivileged_bpf_disabled=2`): validation contract (204 before any load), argc/207, idempotent `off`, the **exact 210 no-CAP_BPF string** for every enable, and the capabilities shape — `ebpf_modes` must be listed even with `ebpf=0` (it is a build fact, not a runtime probe). With CAP_BPF: prio-1 attach/teardown (last-off, reset), single shared program, and veth behavioral — nth exact pattern via payload sequence numbers, counter reset on re-set, quota threshold at pct extremes, window active/future/**expired-pass** plus **recurring period** (drops in two cycles, passes in the gap) and **jitter** (both dropped and passed bursts), flow-hash determinism against a Python mirror of the program's Jenkins fold. |
| `test_precision.py` | F-precision tier, the statistical assertions: gemodel loss within ±5pp (steady-state rate = (1-h)·p/(p+r) from the kernel's Markov chain — p=43 r=100 1-h=100 targets 30.07%), rate within ±10% measured as received byte throughput (span between first and last arrival so burst credit cannot skew), delay+jitter+reorder observability (median inside delay±jitter, delay mdev, arrival inversions — received CONCURRENTLY with the paced injection, else timestamps measure reads not arrivals), and netem seed determinism (identical drop bitmaps across reset + re-set with the same seed). Slowest suite (~15 s), runs last. |

`test_bpf_drop.py` also needs **libpcap loadable by ctypes** (`libpcap.so.1`,
already a ubridge build dependency) — it self-skips if the library cannot be
loaded.

The `test_ebpf.py` behavioral section only runs when the ubridge binary can
actually load BPF (root, or `setcap cap_bpf,...` on a kernel allowing it) —
same invocation as the other kernel suites: `sudo python3 test_ebpf.py`.

**Root is not the deployed path.** gns3-server launches ubridge non-root
with file capabilities, and the verifier takes a stricter path there (it
cannot bound loops at all — see `doc/tc.md`), so a green `sudo` run says
nothing about it. After `make install`, probe the installed binary as the
ordinary user (the `Ubridge` helper defaults to `/usr/local/bin/ubridge`):

```bash
python3 -c "
import sys; sys.path.insert(0, 'tests/brctl'); from common import Ubridge
with Ubridge(port=13188) as ub: print(ub.connect().send('tc capabilities'))"
# must print ...;ebpf=1;cbpf=1;ebpf_modes=nth,quota,window,flow
```

### Behavioral-test notes

- The behavioral cases disable IPv6 on the test veth first: the kernel's
  Router Solicitations otherwise traverse the egress qdisc under test (they
  fill a small `limit` and shift the gemodel state machine).
- netem **loss/gemodel drops are silent** at the sender (send succeeds, the
  frame vanishes); only `limit` overflow surfaces as `ENOBUFS` on send.
  The tests distinguish the two.
- Inside `unshare -Urn`, `lo` starts down — `tests/marker/test_kernel.py`
  brings it up because its marker sink is 127.0.0.1 UDP (the tc suites don't
  need it).

### Known environment quirks (`unshare -Urn`, this machine)

Frames flow across a veth and netem behaves (delay/limit/loss/rate/statistics
verified — including the precision tier), but anything needing the kernel IP
stack (ping/ARP) does not work — hence raw injection instead of the spec's
`nsenter ping` (equivalent observable, deterministic sender).

### Netlink dump quirks (RTM_GETTFILTER, kernel 7.2)

- The dump terminator is an **`NLMSG_ERROR(err=0)`** ack, not `NLMSG_DONE`
  (same as the qdisc dump).
- Each filter dumps as **two messages**: the filter itself (with
  `TCA_OPTIONS`) and a stats continuation (without) — keep only messages
  carrying `TCA_OPTIONS` when collecting by prio. `tc filter show` mirrors
  this: two LINES per filter (header + handle detail) — count "chain 0
  handle" lines when counting filters.
- Inside `TCA_ACT_OPTIONS`, `TCA_GACT_PARMS` is attr **2** (`UNSPEC=0,
  TM=1, PARMS=2`) — easy to mis-number.
