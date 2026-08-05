# packet filter module — user-space link impairment

The `packet_filter` module applies per-packet transformations (delay / jitter /
loss / corruption / BPF drops) inside uBridge's bridge loops. Unlike the `tc`
module — which attaches a kernel `netem` qdisc to a real network interface — the
packet filter runs inside the user-space bridge that connects NIO endpoints
(UDP tunnels, TAP, Ethernet, IOL instances). It works on **every backing NIO
type** including the UDP-connected NIOs that have no kernel interface to attach
a qdisc to.

## Filter types

| Type               | Syntax                                      | Semantics                                                              |
|--------------------|---------------------------------------------|------------------------------------------------------------------------|
| `delay`            | `delay <latency_ms> [jitter_ms]`            | hold each packet for latency ± jitter, then release in time order      |
| `packet_loss`      | `packet_loss <percent>`                     | randomly drop `percent` of packets (0–100)                             |
| `frequency_drop`   | `frequency_drop <N>`                        | deterministically drop every `N`-th packet                             |
| `corrupt`          | `corrupt <percent>`                         | randomly corrupt a portion of each packet byte (0–100). Never drops.   |
| `bpf`              | `bpf <expression> [link_type]`              | drop packets matching a Berkeley Packet Filter expression              |
| `mark`             | `mark <expression> [tag <id>] [link <id>] [pcap <path>]` | passive tap: emit a marker signal on match (Linux only)     |

Multiple filters on one link **compose in order**: each filter passes the packet
to the next. If the first filter drops the packet, no subsequent filter sees it.

> [!WARNING]
> `delay` used to block the bridge thread with `nanosleep()` inside
> `delay_handler`, serializing each direction to ~`1000/latency_ms` pps. Under
> offered load above that rate, the kernel UDP buffer filled up and the link
> collapsed (latency ballooned, then packet loss / `destination host
> unreachable`). Since `v1.1.2` the `delay` filter uses a **real delay line**
> with a dedicated release thread, so the receive loop never blocks and
> per-packet latency stays bounded regardless of offered load.

### `delay` filter details

The delay line mirrors the Linux kernel **netem** qdisc (`net/sched/sch_netem.c`):

- **Time-stamping**: `time_to_send = now + delay`, where `delay` is drawn from
  a **Gaussian (normal) distribution** with mean `latency_ms` and standard
  deviation `jitter_ms` (the inverse-CDF table is generated once at start-up).
  Clamped at 0 — negative draws become instant release.
- **Time-ordered queue**: packets are inserted into a release-ordered queue
  (O(1) tail append in the common in-order case, sorted insert for jitter
  reordering). A dedicated **release thread** (the netem watchdog equivalent)
  sends each packet when its `time_to_send` arrives.
- **Depth-bound (tail-drop)**: the per-direction queue holds at most **1000
  packets** (`NETEM_LIMIT_DEFAULT`). When full, the newest packet is dropped
  so that memory stays bounded and excess load is shed rather than buffered
  without limit. Override without recompiling:

  ```bash
  UBRIDGE_DELAY_LIMIT=2000 ubridge -H 127.0.0.1:21000
  ```

- **Jitter distribution**: default is **Gaussian** (`distribution normal`),
  matching `tc netem delay Xms Yms`. The uniform fallback (netem's `dist==NULL`
  path) is available internally.

### Relationship to `tc` / netem

| | `tc` (kernel netem) | `delay` packet filter |
|---|---|---|
| Requires a kernel network interface | yes | no — runs on any NIO |
| UDP-tunnel bridges (UDP NIOs) | not applicable | the primary target |
| Kernel-linked bridges (TAP, Ethernet) | preferable (kernel-grade, zero-copy) | works, but use `tc` if the interface supports it |
| Gaussian jitter | yes | yes |
| Queue limit / tail-drop | yes (netem `limit`) | yes (`UBRIDGE_DELAY_LIMIT`) |

For a link with a kernel interface at one end (TAP, raw), prefer `tc netem` on
that interface over the user-space `delay` filter — it runs at the qdisc level
and has lower overhead. The `delay` packet filter exists for the case where
**both ends of the bridge are NIO types without a kernel interface** (most
commonly two UDP NIOs or an IOL bridge).

## Bidirectional model (shared filter chain)

A crucial design property: **each bridge stores ONE filter chain**, shared by
**both** directions. A packet crossing the link in either direction passes
through the same filter chain independently.

For a **ping round-trip**, a filter that drops `R`% of packets yields
**effective round-trip survival of `(1 - R)²`**, because the request and the
reply each traverse the chain once:

| `packet_loss` rate | direction survival | round-trip survival | **observed loss** |
|---|---|---|---|
| 10% | 90% | 81% | ~19% |
| 50% | 50% | 25% | ~75% |
| 80% | 20% | 4% | ~96% |

This is **not a bug** — it is the intended semantics of a shared filter list,
and it matches netem qdiscs (which also act on all traffic through the
interface). It is especially important at high `packet_loss` or `corrupt` rates,
where the squaring effect can also block ARP resolution, making connectivity
appear worse than the filter alone.  Use static ARP entries for tests with
drop rates above ~50%.

> [!NOTE]
> In a star topology (central switch connecting multiple links), a ping between
> two nodes traverses **two links** (source->switch + switch->target). If both
> links carry filters the effects **multiply**, easily producing 100% effective
> loss at moderate rates. Isolate the target link before testing.

## IOL bridges

`delay`, `packet_loss`, `frequency_drop`, `corrupt`, and `bpf` are fully
supported on IOL bridges via `iol_bridge add_packet_filter`. Each direction
(NIO → IOL instance and IOL instance → NIO) gets its own delay line.

## Runtime filter management

Filters can be **added, deleted, and reset** on a running bridge:

```text
bridge add_packet_filter     <bridge> <name> <type> [args…]
bridge delete_packet_filter  <bridge> <name>
bridge reset_packet_filters  <bridge>
iol_bridge add_packet_filter     <name> <bay> <unit> <filter_name> <type> [args…]
iol_bridge delete_packet_filter  <name> <bay> <unit> <filter_name>
iol_bridge reset_packet_filters  <name> <bay> <unit>
```

The delay line is **re-synced on each packet** — if a delay filter appears,
changes its latency/jitter, or disappears at runtime, the per-direction delay
line is lazily (re)created or destroyed.  No restart is required.
