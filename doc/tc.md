# tc module — kernel netem link impairment + bpf_drop classifiers

The `tc` hypervisor module attaches and removes a **netem** qdisc at the root
of an interface (kernel-side link impairment) and installs **classic-BPF match
drop filters** (`bpf_drop`) on the egress classifier. It is exposed over the
hypervisor text protocol as `tc <command> [args...]`.

It exists for the **kernel data plane**: once frames flow `TAP → kernel bridge
(brctl) → TAP`, they never reach ubridge's user-space NIO relay, so the
`bridge` module's user-space packet filters (`delay` / `packet_loss` / `corrupt`
/ `bpf`) no longer see the traffic. The impairment has to live in the kernel
qdisc instead. `tc` is that kernel-side replacement for the user-space filters
(delay/jitter/loss/dup/corrupt and beyond, plus `bpf` → `bpf_drop`).

## Transport

Same text protocol as the other modules: newline-terminated commands, first
token is the module (`tc`), second is the command, rest are arguments. Replies
are `NNN-...` (final line).

## Privileges

Requires `CAP_NET_ADMIN` (attaching a qdisc). In practice ubridge is granted
capabilities on install:

```bash
sudo make install       # sets cap_net_admin,cap_net_raw=ep on the binary
getcap $(which ubridge) # verify
```

## Commands

### `tc netem set <if> [options]`

Attach/replace a netem qdisc at the root of `<if>` (`RTM_NEWQDISC`,
`NLM_F_CREATE|REPLACE`). At least one option must be given. Keyword/value
pairs, any order; `correl`/`gap` bind to the keyword they follow:

```
tc netem set <if>
   [delay <ms>] [jitter <ms>]
   [distribution uniform|normal|pareto|paretonormal]
   [loss <pct> [correl <pct>] | loss gemodel <p> [<r> [<1-h>]]]
   [dup <pct> [correl <pct>]] [corrupt <pct>]
   [reorder <pct> [correl <pct>] [gap <n>]]     # requires delay
   [rate <bw>]                                   # e.g. 10mbit, 512kbps
   [limit <pkts>] [seed <u32>]
```

| Option | Unit / range | Notes |
|--------|--------------|-------|
| `delay <ms>` | milliseconds (may be fractional) | added latency |
| `jitter <ms>` | milliseconds | latency variation; also the scale for `distribution` |
| `distribution <name>` | one of the four | jitter distribution; `normal`/`pareto`/`paretonormal` embed the same tables iproute2 ships as `*.dist`, `uniform` (default) sends no table. Only has an effect together with `jitter` > 0 |
| `loss <pct>` | 0–100 | random packet loss |
| `loss … correl <pct>` | 0–100 | loss correlation, directly after `loss` |
| `loss gemodel <p> [<r> [<1-h>]]` | each 0–100 | Gilbert-Elliott loss model; defaults `r=0`, `1-h=0`. `p` = P(good→bad), `r` = P(bad→good), `1-h` = drop probability while bad (so `loss gemodel 100 0 100` drops everything after the first packet). Mutually exclusive with plain `loss` |
| `dup <pct>` | 0–100 | random duplication |
| `corrupt <pct>` | 0–100 | random corruption |
| `reorder <pct>` | 0–100 | reordering probability; **requires `delay`** (nothing is visibly reordered without latency) |
| `reorder … correl <pct>` / `gap <n>` | 0–100 / 1–1000 | reorder correlation; reordering gap (defaults to 1) |
| `rate <bw>` | `bit\|kbit\|mbit\|gbit` (bits/s, decimal) or `bps\|kbps\|mbps` (bytes/s) | bandwidth limit, max 100gbit. Internally tc's wire unit is bytes/s — `rate 10mbit` and `rate 1250kbps` are the same |
| `limit <pkts>` | 1–1000000 | queue limit in packets (default 1000) |
| `seed <u32>` | 0–4294967295 | netem PRNG seed — makes random draws (loss/dup/corrupt/reorder/jitter) reproducible for tests. Omitted: the kernel picks one at random |

```
tc netem set tap-gns3-e0 delay 100 jitter 10 loss 5
100-netem set on tap-gns3-e0

tc netem set tap-gns3-e0 delay 50 reorder 25 gap 5 rate 10mbit seed 42
100-netem set on tap-gns3-e0
```

Verify in the kernel with `tc qdisc show dev <if>`:
```
qdisc netem 8002: root refcnt 2 limit 1000 delay 100.0ms  10.0ms loss 5% ...
```
(`tc` prints jitter as a bare second time value after delay, not the word
"jitter"; `gap` prints at the end of the line; an unpinned seed shows the
kernel-chosen random value. The distribution table is not printable — but
`tc -s qdisc show` shows the drop/delay counters.)

**Re-set semantics (kernel `netem_change`)**: options carried in the raw qopt
prefix (`delay`, `jitter`, `loss`, `dup`, `limit`, `gap`) are **reset** on every
set; attribute-carried options (`correl`, `reorder`, `corrupt`, `rate`,
`distribution`, `seed`) **persist** when their keyword is absent — the kernel
merges, exactly like `tc qdisc replace` on a same-kind qdisc (the gemodel is
cleared when no `loss` is sent). To start from a clean slate use
`tc reset` first. The controller always sends the full desired parameter set
per apply, so this only matters when *removing* an attr-carried option while
keeping others.

Bad value / unknown keyword → `204`. Bad number of params (>32 tokens) /
dangling value → `203`. `reorder` without `delay` → `204-reorder requires
delay`. Netlink/kernel failure (incl. missing interface) →
`207-Could not set netem on <if>: <strerror>`.

### `tc bpf_drop add <if> <prio> "<expression>"`

The kernel-side replacement for the user-space `bpf` packet filter: compile
the pcap/libpcap expression against Ethernet (`DLT_EN10MB`, snaplen 65535,
optimized — same shape as the relay's `bpf` filter, so one expression serves
both datapaths) and install it as a **cls_bpf classifier on the clsact
qdisc's egress side**, with a `gact` `TC_ACT_SHOT` action: a match drops the
frame, a non-match falls through to the next filter (any match drops — OR
semantics across filters).

```
tc bpf_drop add tap-gns3-e0 10 "icmp[icmptype] == 8"
100-bpf_drop filter added on tap-gns3-e0 (prio 10)
```

- `<prio>` is 10–99 (server-assigned; prio 1 is reserved for the future eBPF
  impairment filter). Egress classifiers run by ascending priority, *before*
  the root netem qdisc — dropped frames never reach netem **nor the AF_PACKET
  tap points** (capture/markers will not observe cls_bpf-dropped frames).
- clsact is created on first use and **coexists with the netem root qdisc**
  (never replaces the root).
- Re-adding at the same prio **replaces** (the prio node is cleared first) —
  the normal update path is `flush` + re-`add` (mirrors `netem set`), which
  this makes safe even after a ubridge restart.
- Errors: `204-invalid prio value '<v>' (10-99)`; `209-Cannot compile filter
  '<expr>': <pcap error>` (the controller keys on that exact prefix — same
  shape as the relay's compile error, so one regex serves both datapaths);
  `207` on netlink/kernel failure (incl. missing interface).

### `tc bpf_drop flush <if>`

Delete every bpf_drop filter **uBridge added** on `<if>` (prios are tracked
in-process; a flush after a ubridge restart is a no-op that still returns
`100`). Does **not** touch the clsact qdisc itself, the netem root qdisc, or
any filter ubridge does not own (e.g. a future eBPF impairment filter at
prio 1, or a classifier someone else attached).

```
tc bpf_drop flush tap-gns3-e0
100-bpf_drop filters flushed on tap-gns3-e0
```

Idempotent; per-filter `ENOENT` tolerated. Missing interface → `207`.

### `tc reset <if>`

**Full restore** of the interface: 1. remove every bpf_drop filter ubridge
added (clsact egress side), 2. delete the clsact qdisc, 3. remove the root
qdisc (`RTM_DELQDISC` — whatever root qdisc is attached, netem or the
default; the kernel re-creates a default qdisc).

```
tc reset tap-gns3-e0
100-qdisc reset on tap-gns3-e0
```

**Idempotent**: the semantics are "ensure nothing is attached", so a reset
on an untouched interface is not an error — the target state already holds:

```
tc reset tap-gns3-e0
100-no qdisc on tap-gns3-e0
```

Missing interface → `207/ENODEV`.

### `tc capabilities`

Report what this build supports, so the controller can hide filter types the
local ubridge/kernel cannot run (and stay on the relay datapath for them —
an old ubridge without this command gets the same treatment):

```
tc capabilities
100-netem=delay,jitter,loss,dup,corrupt,rate,reorder,gemodel,dist,seed,limit;ebpf=0;cbpf=1
```

`cbpf` is **probed for real** (cached): ubridge creates a throwaway dummy
link, attaches clsact plus a one-instruction never-matching cBPF filter, and
deletes the dummy again; any step failing (no `CAP_NET_ADMIN`, kernel
without `cls_bpf`) reports `cbpf=0`. `ebpf` flips to 1 when the stateful
eBPF classifier (spec part B) lands; until then the controller must keep
`frequency_drop` on the relay datapath.

## Status codes

| Code | Meaning |
|------|---------|
| `100` | OK |
| `203` | Bad number of parameters (netem takes 4–32; bpf_drop add 4, flush 2) / dangling value |
| `204` | Invalid value; `reorder requires delay`; `unknown distribution '<v>'`; duplicate `loss`; bpf_drop prio/verb errors |
| `207` | Netlink/kernel failure (`Could not set netem / add bpf_drop / reset qdisc on <if>: <strerror>`; ENODEV; a missing qdisc on reset is `100`, not an error) |
| `209` | `Cannot compile filter '<expr>': <pcap error>` — bpf_drop expression failed to compile |

## Implementation notes

- **netem ABI** (per `net/sched/sch_netem.c` `netem_change`): `TCA_OPTIONS` is a
  nested attribute whose payload begins with a raw `struct tc_netem_qopt`
  (mandatory; carries `limit`, `loss`, `gap`, `duplicate`), optionally
  followed by nested `TCA_NETEM_*` attributes — emitted in the same order
  the iproute2 `tc` CLI sends them (LATENCY64, JITTER64, CORR, REORDER,
  CORRUPT, LOSS-gemodel, RATE64+RATE, PRNG_SEED, DELAY_DIST).
- **delay/jitter** are sent as `TCA_NETEM_LATENCY64` / `TCA_NETEM_JITTER64`
  (s64 nanoseconds), which override the legacy u32 struct fields and avoid the
  `PSCHED_TICKS` unit ambiguity. **loss / duplicate / gap** go in the qopt
  prefix (probability × 2³²). **corrupt** is the fixed-size
  `TCA_NETEM_CORRUPT` nested attr.
- **rate** is bytes/s on the wire (tc's internal unit — `get_rate64`
  divides by 8): `< 2³²` sends only the legacy `TCA_NETEM_RATE` u32 field;
  `≥ 2³²` also sends `TCA_NETEM_RATE64` (u64) with the legacy field
  saturated, and the kernel takes the max of the two.
- **gemodel** rides in `TCA_NETEM_LOSS` (nested) under kind `NETEM_LOSS_GE`;
  the third parameter is `1-h` and is stored complemented
  (`h = ~percent`, mirroring iproute2), `k1` stays 0.
- **distribution** tables (normal / pareto / paretonormal) are embedded in
  `src/tc_netem_dist.c`, byte-identical to the `*.dist` files iproute2 ships
  (4096 s16 samples, `NETEM_DIST_SCALE` 8192), sent verbatim as
  `TCA_NETEM_DELAY_DIST`. `uniform` sends no table (kernel default).
- **seed** goes out as `TCA_NETEM_PRNG_SEED` (u64; kernel ≥ 5.1).
- The netem netlink message is allocated larger than `NLMSG_GOOD_SIZE`
  because a distribution table adds 8 KiB.
- One deliberate divergence from the `tc` CLI: **`dup … correl` alone is not
  silently dropped**. iproute2 forgets to mark the CORR attribute present in
  that case, losing the setting; ubridge always sends it.
- **bpf_drop ABI** (per `net/sched/cls_bpf.c` `cls_bpf_change()`): clsact is
  created at parent `TC_H_CLSACT` (handle `TC_H_MAKE(TC_H_CLSACT, 0)`,
  `EEXIST` tolerated); filters are attached with `RTM_NEWTFILTER`
  (`CREATE|EXCL`) at parent `TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)`,
  `tcm_info = (prio << 16) | htons(ETH_P_ALL)`, and `TCA_OPTIONS` =
  `TCA_BPF_ACT` (nested: action slot 1 → `TCA_ACT_KIND "gact"` →
  `TCA_ACT_OPTIONS` → `TCA_GACT_PARMS` with `action = TC_ACT_SHOT`) followed
  by `TCA_BPF_OPS_LEN` (u16) + `TCA_BPF_OPS` (the `sock_filter` array —
  `struct bpf_insn` is layout-identical). The kernel migrates classic
  bytecode to eBPF internally (`bpf_prog_create`), so **no `CAP_BPF` is
  needed** — only the netlink `CAP_NET_ADMIN` this module already requires.
- **flush/reset delete** whole prio nodes: `RTM_DELTFILTER` with the prio in
  `tcm_info` and handle 0 removes every filter at that priority (`ENOENT` =
  nothing there). Deleting clsact requests handle 0 rather than
  `TC_H_MAKE(TC_H_CLSACT, 0)` so an absent clsact uniformly returns `ENOENT`
  (with the handle set, the kernel compares against the ingress queue's
  noop qdisc and returns `EINVAL` — the "Invalid handle" `tc qdisc del …
  clsact` prints on a second delete).
- bpf_drop prios are tracked per-ifindex in-process (a linked list only
  touched from command handlers, which the dispatcher serialises under
  `global_lock`). Kernel state remains the source of truth; the list exists
  so flush/reset remove exactly our filters.
- Uses ubridge's netlink library (`src/netlink/nl.c`); helpers return a
  **negative errno**; command handlers report `strerror(-err)`.

## Relationship to user-space packet filters

| user-space filter (`bridge add_packet_filter`) | kernel equivalent |
|------------------------------------------------|-------------------|
| `delay`(+`jitter`) | `tc netem delay/jitter` (+`distribution`) |
| `packet_loss` | `tc netem loss` (+`correl`, `loss gemodel`) |
| `corrupt` | `tc netem corrupt` |
| (none) | `tc netem dup`, `tc netem reorder`, `tc netem rate`, `tc netem limit`, `tc netem seed` (no user-space equivalents) |
| `frequency_drop` (exact every-Nth) | none — netem loss is stochastic; exact needs eBPF (`ebpf=0` so far) |
| `bpf` (cBPF drop filter) | `tc bpf_drop add` — same pcap expression, compiled against the same DLT_EN10MB (`cbpf=1`) |

## Testing

`tests/tc/` attaches netem to throwaway interfaces and verifies kernel state:

- `test_basic.py` — the P5 surface regression (delay/jitter/loss/dup/corrupt,
  REPLACE semantics, reset idempotency, validation errors), read back with
  `tc qdisc show`.
- `test_netem_ext.py` — the P6a extensions. The strongest check is a
  **byte-compare**: the same parameters set through ubridge and through the
  real `tc` CLI must produce byte-identical `TCA_OPTIONS` in the kernel
  (RTM_GETQDISC dump; the kernel's own re-serialization, so identical bytes
  mean identical state — only the random seed the kernel invents when
  unpinned is stripped). Plus readable-state checks via `tc qdisc show`, the
  full 204/203 validation contract, `tc capabilities`, and behavioral checks
  on a veth pair with raw AF_PACKET injection (delay lower bound, limit
  overflow, gemodel extremes — with IPv6 disabled on the test veth, because
  the kernel's Router Solicitations otherwise traverse the qdisc under test).
- `test_bpf_drop.py` — the P6c bpf_drop surface. Oracles, strongest first:
  the installed bytecode must be **byte-identical to an independent libpcap
  compile** (ctypes driving the same library), and must dump identically to
  the same bytecode installed through the real `tc` CLI (`bpf bytecode
  '<insns>' action drop`); the action must be gact/`TC_ACT_SHOT` (RTM_GETTFILTER
  dump). Plus the 203/204/207/209 error contract, flush semantics (only
  ubridge-tracked prios — a foreign CLI-installed filter at prio 50 must
  survive), the full-restore reset, `tc capabilities` (`cbpf=1`), and
  behavioral checks on a veth pair (match dropped / non-match passes /
  multi-prio OR / flush restores traffic) with raw AF_PACKET injection.

Requires `CAP_NET_ADMIN` — run under sudo (CI kernel job) or `unshare -Urn`.
The **`tc`/`ip` CLI tools are a test-only dependency** (kernel-state
verification); ubridge itself talks netlink directly and needs no iproute2
tools at runtime. `tc` ships with the `iproute2` package on all major distros
(in `/usr/sbin` on several, so the suite also probes absolute paths — a
non-root `PATH` may not include it) and self-skips only when it is truly
absent (see `tests/tc/README.md`). `test_bpf_drop.py` additionally drives
**libpcap via ctypes** as its independent compile oracle (skips if the
library cannot be loaded).

```bash
make
cd tests/tc
sudo python3 run_all.py          # or: unshare -Urn python3 run_all.py
# test_basic 18/18, test_netem_ext 64/64, test_bpf_drop 32/32
```

Not covered locally (needs real traffic + a time budget, CI-root tier):
jitter `distribution` shape statistics, rate within ±10% measured throughput,
seed-identical drop patterns across runs.
