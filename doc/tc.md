# tc module — kernel netem link impairment + clsact classifiers

The `tc` hypervisor module attaches and removes a **netem** qdisc at the root
of an interface (kernel-side link impairment), installs **classic-BPF match
drop filters** (`bpf_drop`) on the egress classifier, and runs a **stateful
eBPF impairment program** (`nth_drop` / `quota_drop` / `window_drop` /
`flow_drop`) there. It is exposed over the hypervisor text protocol as
`tc <command> [args...]`.

It exists for the **kernel data plane**: once frames flow `TAP → kernel bridge
(brctl) → TAP`, they never reach ubridge's user-space NIO relay, so the
`bridge` module's user-space packet filters (`delay` / `packet_loss` /
`corrupt` / `bpf` / `frequency_drop`) no longer see the traffic. The
impairment has to live in the kernel instead. `tc` is that kernel-side
replacement — netem for delay/jitter/loss/dup/corrupt and beyond,
`bpf_drop` for `bpf`, `nth_drop` for `frequency_drop`.

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
| `loss gemodel <p> [<r> [<1-h>]]` | each 0–100 | Gilbert-Elliott loss model; defaults `r=0`, `1-h=0`. `p` = P(good→bad), `r` = P(bad→good), `1-h` = drop probability while bad (so `loss gemodel 100 0 100` drops everything after the first packet). Long-run loss rate = `(1-h)·p/(p+r)` — the GOOD→BAD transition packet itself passes. Mutually exclusive with plain `loss` |
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
any filter ubridge does not own (e.g. the eBPF impairment filter at prio 1,
or a classifier someone else attached).

```
tc bpf_drop flush tap-gns3-e0
100-bpf_drop filters flushed on tap-gns3-e0
```

Idempotent; per-filter `ENOENT` tolerated. Missing interface → `207`.

### eBPF stateful impairment: `tc nth_drop` / `quota_drop` / `window_drop` / `flow_drop`

Kernel-side replacements for the user-space `frequency_drop` filter and
three stateful modes netem cannot express. **One** SCHED_CLS eBPF program
per interface (`tc_impair`, source `src/tc_impair.bpf.c`), loaded once on
the first enable and attached at **clsact egress prio 1** (below
`bpf_drop`'s 10–99 — classifiers run by ascending priority, so stateful
drops happen before expression drops and before netem). All four modes are
pure map state — enabling or changing one never reloads the program.

```
tc nth_drop    <if> <n | off>              # drop every Nth packet (exact)
tc quota_drop  <if> <bytes> <pct> | off    # after <bytes> of traffic, drop pct%
tc window_drop <if> <start_ms> <outage_ms> <pct> [<period_ms> [<jitter_ms>]] | off
tc flow_drop   <if> <mask> <target> | off  # flow-hash select (hash % target == 0 drops)
```

Semantics (evaluation order fixed: **nth → quota → window → flow**, first
drop wins):

- `nth_drop <n>`: the Nth, 2Nth, … packet is dropped — exact across CPUs
  (atomic counter), unlike netem's stochastic loss. This is the kernel-side
  `frequency_drop`.
- `quota_drop <bytes> <pct>`: bytes are counted from the last quota enable
  (only traffic that survived nth); once the running total reaches
  `<bytes>`, each further packet drops with probability `pct` (100 =
  hard cutoff after the quota).
- `window_drop <start_ms> <outage_ms> <pct> [<period_ms> [<jitter_ms>]]`:
  without `period`, a **single** `[start, start+outage)` outage on the
  monotonic clock (opening `start_ms` from the command) — packets pass
  before *and after* it. With `period` (≥ `outage`), outages recur every
  cycle: inside the outage drop with `pct`, in the rest of the cycle pass
  — deterministic link flap. With `jitter` (> 0, ≤ 1000000000 ms), each
  new cycle's outage and period are re-drawn uniformly in nominal ±
  `jitter` (whole-ms grid, clamped so a cycle never overlaps its
  successor; `jitter 0` draws nothing and is exactly the fixed schedule)
  — randomized flap that cannot let protocols sync to a beat. The program
  advances whole cycles in a few straight-line steps (up to
  `WIN_CATCHUP_STEPS` = 16 cycles per packet, the walk resumable by each
  further packet), so traffic pausing across many cycles still lands in
  the right one.
- `flow_drop <mask> <target>`: `<mask>` is the decimal bitmask of header
  fields feeding a Jenkins one-at-a-time hash — `1`=source MAC, `2`=dest
  MAC, `4`=L4 source port, `8`=L4 dest port, `16`=IPv4 protocol (ports only
  for TCP/UDP over IPv4 with IHL=20 — the program uses fixed-offset packet
  access only, because variable-offset packet-pointer arithmetic is
  rejected by the verifier for non-root; non-IP frames contribute their
  MAC fields). Packets whose hash modulo `<target>` is 0 are dropped —
  per-flow select, roughly 1/`target` of flows (a filter cannot delay;
  delay stays netem's job).

Each `off` resets that mode's counters; when the last mode goes off the
prio-1 filter is removed and the program/map fds closed. Re-`set`ting a
mode also restarts its counters. Percentage draws use the same 2³²
probability encoding as netem (PRNG state in the counters map, seeded at
load). `tc reset` tears the whole thing down with everything else.

**Capability requirement**: `BPF_PROG_LOAD(SCHED_CLS)` needs
**CAP_BPF** (or CAP_SYS_ADMIN) on kernels ≥ 5.8 — installation sets it
(`setcap cap_bpf,cap_net_admin,cap_net_raw=ep`, with a fallback to the old
set on kernels/filesystems without it; note the binary must live on a
filesystem mounted **suid** — a `nosuid` mount silently drops file caps at
exec). The program deliberately uses only fixed-offset packet access,
because variable-offset packet-pointer arithmetic is rejected by the
verifier for non-root processes even when they hold CAP_BPF. When loading
is refused — missing CAP_BPF (EPERM) or a verifier/kernel restriction for
this process (EACCES) — every enable replies exactly:

```
210-uBridge lacks CAP_BPF (setcap cap_bpf,cap_net_admin,cap_net_raw=ep) and the kernel requires it for stateful filters
```

and `tc capabilities` reports `ebpf=0` (probed by loading the real program
once, cached) — the controller keeps these filter types on the relay
datapath. Value validation (204) happens before any load attempt; `off` on
an interface with nothing loaded is a plain `100`.

### `tc reset <if>`

**Full restore** of the interface: 0. remove the eBPF impairment filter
(prio 1) and close its program/map fds, 1. remove every bpf_drop filter
ubridge added (clsact egress side), 2. delete the clsact qdisc, 3. remove
the root qdisc (`RTM_DELQDISC` — whatever root qdisc is attached, netem or
the default; the kernel re-creates a default qdisc).

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
100-netem=delay,jitter,loss,dup,corrupt,rate,reorder,gemodel,dist,seed,limit;ebpf=1;cbpf=1
```

Both classifier capabilities are **probed for real** (cached):
`ebpf` loads the actual `tc_impair` program (maps + verifier acceptance)
and throws it away — any failure (no CAP_BPF, kernel the program does not
verify on) reports `0`; `cbpf` creates a throwaway dummy link, attaches
clsact plus a one-instruction never-matching cBPF filter, and deletes the
dummy again. The controller hides the corresponding filter types per
capability and keeps them on the relay datapath.

## Status codes

| Code | Meaning |
|------|---------|
| `100` | OK |
| `203` | Bad number of parameters (netem takes 4–32; bpf_drop add 4, flush 2; ebpf modes 2–6 per verb — `window_drop` takes 4–6 to set) / dangling value |
| `204` | Invalid value; `reorder requires delay`; `unknown distribution '<v>'`; duplicate `loss`; bpf_drop prio/verb errors; ebpf mode value errors (`window period` must be ≥ outage length, `window jitter` ≤ 1000000000) |
| `207` | Netlink/kernel failure (`Could not set netem / add bpf_drop / set <mode> / reset qdisc on <if>: <strerror>`; ENODEV; a missing qdisc on reset is `100`, not an error) |
| `209` | `Cannot compile filter '<expr>': <pcap error>` — bpf_drop expression failed to compile |
| `210` | `uBridge lacks CAP_BPF (...)` — the kernel requires CAP_BPF for stateful filters and this ubridge does not have it |

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
- **eBPF program** (`src/tc_impair.bpf.c`): freestanding C compiled with
  `clang -target bpf -O2` (no CO-RE, no BTF-typed pointers, plain packet
  access). The committed object's instructions are embedded as a plain
  array (`src/tc_ebpf_insns.c`, regenerated by `tools/gen_tc_impair.py`
  via `make bpf`) — the normal build needs neither clang nor libbpf. The
  loader (`src/tc_ebpf.c`, its own TU because `<linux/bpf.h>` and libpcap
  both define `struct bpf_insn`) is raw syscalls: two `BPF_MAP_CREATE`s
  (ARRAY, 1 entry: CFG + CNT), patching the two `BPF_PSEUDO_MAP_FD` loads
  the generator located, one `BPF_PROG_LOAD` of type SCHED_CLS. Attaching
  is the usual `RTM_NEWTFILTER` at prio 1 with `TCA_BPF_FD` +
  `TCA_BPF_FLAGS = TCA_BPF_FLAG_ACT_DIRECT` (direct-action — the program's
  `TC_ACT_SHOT/OK` return IS the verdict, no gact).
- The program is verifier-friendly by construction — and the constraint is
  stricter than it looks: **no loops at all**. Production ubridge carries
  `CAP_BPF` and never runs as root, and the verifier's non-root path does
  not keep a loop counter's constant bound (it records the register as a
  wide scalar — see "Verifier constraint" below), so it
  unrolls the loop as if unbounded and piles up unexplored branch states
  until `push_stack()` exceeds `BPF_COMPLEXITY_LIMIT_JMP_SEQ` (8192) and
  rejects the **whole** program with `E2BIG` — *The sequence of N jumps is
  too complex*, where N counts pending states, not jumps. All four modes go
  down with it, since they share this one program, and **the same binary
  run as root verifies fine** — which is why a `sudo`-only test run cannot
  catch it. The window cycle catch-up is therefore a fixed number
  (`WIN_CATCHUP_STEPS` = 16) of hand-unrolled `win_step()` calls under a
  guard that keeps the hot path at one comparison; a bigger count buys
  nothing because the walk is resumable (a pause of any length re-syncs a
  packet at a time), and re-issuing `window_drop` re-anchors the phase if a
  pause was pathological. `tests/tc/test_ebpf.py` asserts both statically
  (no backward jumps; steps in sync and small) — without a capability, and
  therefore on every run. Every packet access is bounds-checked, L4 ports only for TCP/UDP
  over IPv4 with the header verified present, 32-bit modulo only (BPF has
  no native 64-bit mod). Every helper is force-inlined
  (`always_inline`): an outlined one would emit an intra-program call
  relocation (`R_BPF_64_32`) the committed-insn pipeline does not carry —
  `tools/gen_tc_impair.py` refuses the object loudly in that case.
  Counters (`packets`/`bytes`/`nth_state`) use atomic adds, so the
  every-Nth count is exact across CPUs; the PRNG state rides in the
  counters map (seeded at load, never zero), and the jittered window
  draws go through the same stream (`lo + (rnd·span) >> 32` on the
  whole-ms grid — multiply-shift, no 64-bit modulo). `struct __sk_buff`
  is hand-written minimally in the program — its `data`/`data_end`
  offsets are compile-time-asserted against the uapi from the native side.
- Uses ubridge's netlink library (`src/netlink/nl.c`); helpers return a
  **negative errno**; command handlers report `strerror(-err)`.

### Verifier constraint: why the eBPF program has no loops

Everything above is loaded by a process that is **not root** — gns3-server
spawns ubridge with `setcap cap_bpf,cap_net_admin,cap_net_raw=ep`, and the
BPF verifier takes a *different, stricter path* for such callers than it
does for root (`env->allow_ptr_leaks` / Spectre-v1 bypass are gated on
CAP_PERFMON/CAP_SYS_ADMIN, not CAP_BPF — the same gate that forces the
constant-offset packet access in `flow_hash`).

Observed on this project (same binary, same kernel):

| caller | loop counter `R4` at the loop head | verdict |
|---|---|---|
| root | exact constant (127 → 126 → …) | accepted |
| non-root + `CAP_BPF` | `scalar(smax=umax32=0xfffff086)` — bound lost | `E2BIG` |

With the bound gone the verifier cannot prove the loop bounded, unfolds it
as if unbounded and queues states until `push_stack()` trips
`BPF_COMPLEXITY_LIMIT_JMP_SEQ` (8192): `The sequence of 8193 jumps is too
complex.` — that N counts *pending states*, not jumps or trips. `E2BIG`
from `BPF_PROG_LOAD` therefore means "too much un-pruned exploration", and
in this program it takes all four modes down (they share one program).

Consequences, all of them load-bearing:

* **No loops anywhere**, not even trip-capped ones (`tests/tc/test_ebpf.py`
  asserts zero backward jumps in the committed array). The window catch-up
  is `WIN_CATCHUP_STEPS` hand-unrolled `win_step()` calls.
* **`sudo` runs prove nothing about the deployed path.** The test suite's
  behavioral section runs as root; the non-root path is checked by probing
  the *installed* binary as the invoking user (`tc capabilities` must say
  `ebpf=1`).
* Any future change to the program must be re-probed that way — a green
  root-only run is not evidence.

## Relationship to user-space packet filters

| user-space filter (`bridge add_packet_filter`) | kernel equivalent |
|------------------------------------------------|-------------------|
| `delay`(+`jitter`) | `tc netem delay/jitter` (+`distribution`) |
| `packet_loss` | `tc netem loss` (+`correl`, `loss gemodel`) |
| `corrupt` | `tc netem corrupt` |
| `frequency_drop` (exact every-Nth) | `tc nth_drop` (exact, atomic) — needs `ebpf=1` |
| `bpf` (cBPF drop filter) | `tc bpf_drop add` — same pcap expression, compiled against the same DLT_EN10MB (`cbpf=1`) |
| (none) | `tc quota_drop`, `tc window_drop`, `tc flow_drop` (stateful selects, `ebpf=1`); `tc netem dup/reorder/rate/limit/seed` (no user-space equivalents) |

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
- `test_ebpf.py` — the P6b stateful modes, split by capability.
  **Unconditionally** (no `tc`, no capability): static checks of the
  committed instruction array — no backward jumps at all, the
  `WIN_CATCHUP_STEPS` unrolling in sync and small, array length matching
  the header — because a loop rejection only shows on the non-root
  verifier path (see "Verifier constraint" above). Without
  CAP_BPF (e.g. `unshare -Urn`): the validation contract (204s before any
  load), argc/207 errors, idempotent `off`, and the **exact 210 string**
  for every enable. With CAP_BPF (real sudo): prio-1 attachment, one
  program shared across modes, teardown on last off / reset, and behavioral
  checks on a veth — **nth exact pattern** (payload sequence numbers:
  survivors are exactly seq % n ≠ 0), counter reset on re-set, byte-quota
  threshold at pct 0/100 extremes, **window semantics** (single window
  drops while active and *passes after expiry*; recurring period drops
  in two cycles and passes in the gap between them, anchored on the
  monotonic clock; a jittered schedule produces both dropped and passed
  bursts), and flow-hash determinism against a **Python mirror of the
  program's Jenkins fold** (src MACs picked to hash ≡ 0 / ≢ 0 mod target).
- `test_precision.py` — the F precision tier, the statistical assertions
  (the slowest suite, ~15 s, runs last): gemodel loss within ±5pp of the
  Markov steady state ((1-h)·p/(p+r) — drops only happen in the BAD state,
  the transition packet itself passes), rate within ±10% measured as
  received byte throughput (span between first and last arrival so startup
  burst credit cannot skew), delay+jitter+reorder observability (median
  delay inside delay±jitter, delay mdev, arrival inversions), and netem
  `seed` determinism — identical drop bitmaps across a reset + re-set with
  the same seed.

Requires `CAP_NET_ADMIN` — run under sudo (CI kernel job) or `unshare -Urn`.
The **`tc`/`ip` CLI tools are a test-only dependency** (kernel-state
verification); ubridge itself talks netlink directly and needs no iproute2
tools at runtime. `tc` ships with the `iproute2` package on all major distros
(in `/usr/sbin` on several, so the suite also probes absolute paths — a
non-root `PATH` may not include it) and self-skips only when it is truly
absent (see `tests/tc/README.md`). `test_bpf_drop.py` additionally drives
**libpcap via ctypes** as its independent compile oracle (skips if the
library cannot be loaded). `test_ebpf.py`'s behavioral section needs the
binary to actually hold **CAP_BPF** (`sudo make install` sets it; a plain
`unshare -Urn` cannot load BPF on this machine —
`kernel.unprivileged_bpf_disabled=2`), which is also why its degraded
no-CAP_BPF path is fully asserted instead.

```bash
make
cd tests/tc
sudo python3 run_all.py          # or: unshare -Urn python3 run_all.py
# test_basic 18/18, test_netem_ext 64/64, test_bpf_drop 32/32,
# test_ebpf 47/47 (38/38 degraded without CAP_BPF), test_precision 10/10
```

Not covered locally (needs real traffic + a time budget, CI-root tier):
jitter `distribution` shape statistics, rate within ±10% measured throughput,
seed-identical drop patterns across runs.
