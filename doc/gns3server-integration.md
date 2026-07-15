# ubridge ↔ gns3server integration contract

This document describes what ubridge exposes to gns3server for the **kernel
data plane** and **packet-match signaling** work. gns3server drives ubridge over
the existing hypervisor text protocol; ubridge is inert until commanded.

> Per-module details live in [`tap.md`](tap.md), [`brctl.md`](brctl.md),
> [`tc.md`](tc.md), [`capture.md`](capture.md), [`marker.md`](marker.md).
> This file is the cross-cutting contract for the gns3server side.

---

## 0. Protocol basics (recap)

- One TCP control connection per ubridge (already used by gns3server). Line-based
  text: `<module> <command> [args...]`, newline-terminated.
- Replies: `NNN<sep>message` where `<sep>` is `-` for the final line, space for
  intermediate lines.
- Status codes:

  | Code | Meaning |
  |------|---------|
  | `100` | OK |
  | `101` | Info message (intermediate) |
  | `203` | Bad number of parameters |
  | `204` | Invalid parameter value |
  | `206` | Unable to create object |
  | `207` | Unable to delete object |
  | `208` | Object not found (`ENODEV`) |
  | `209` | Object already running (`EALREADY`) |

- **Linux only.** The new modules (`tap`/`tc`/`capture`/`marker`) plus
  `brctl`/`link` require ubridge installed with capabilities:
  ```bash
  sudo make install     # sets cap_net_admin,cap_net_raw=ep
  ```

---

## 1. The kernel data plane (context)

New model: frames flow `persistent TAP → kernel bridge (brctl) → TAP` **in
kernel**, bypassing ubridge's user-space NIO relay. ubridge becomes a control
daemon; data-plane impairment/capture must therefore also live in the kernel.

| Concern | Module | Notes |
|---------|--------|-------|
| Persistent TAP endpoints | `tap` | per-node NIC; survives fd close so unpriv QEMU can open it |
| Kernel bridge plumbing | `brctl` | per-link bridge; runtime add/del port = re-link |
| Link impairment | `tc` | netem qdisc (delay/jitter/loss/dup/corrupt) |
| Kernel capture | `capture` | AF_PACKET on an interface |
| Match signaling + filtered capture | `marker` + `mark` filter | the focus of §3 |

---

## 2. Module contracts (commands gns3server issues)

### tap — persistent TAP lifecycle
| When | Command |
|------|---------|
| Node start | `tap create <name>` then `tap set_owner <name> <qemu_uid>` → launch QEMU with `-netdev tap,ifname=<name>,script=no` |
| Node stop | `tap delete <name>` |

`set_owner` is **required** so an unprivileged QEMU can open the persistent TAP.

### brctl — kernel bridge (link plumbing)
| When | Commands |
|------|----------|
| Link create | `brctl create <br>`; `brctl addif <br> <tapA>`; `brctl addif <br> <tapB>` (auto-UP) |
| Runtime re-link | `brctl delif <br> <tap>` then `brctl addif <newbr> <tap>` |
| Link delete | `brctl delif` on both ends, then `brctl delete <br>` |

(Full STP/VLAN/port-param set in `brctl.md`.)

### tc — netem impairment
```
tc netem set <if> [delay <ms>] [jitter <ms>] [loss <%>] [dup <%>] [corrupt <%>]
tc reset <if>
```
Replaces the user-space `delay`/`packet_loss`/`corrupt` filters on the kernel
path. Keyword/value pairs, any order; at least one required.

### capture — kernel AF_PACKET capture
```
capture start_kernel <if> <pcap> [dlt]     # dlt defaults to EN10MB
capture stop_kernel                          # idempotent
```
Singleton (one active kernel capture per ubridge). Standard pcap output,
identical writer to `bridge start_capture`.

---

## 3. marker — match signaling + filtered capture (main contract)

A `mark` packet filter is a **passive tap**: on BPF match it (a) pushes a UDP
signal to a configured sink and/or (b) appends the packet to a pcap file. It
**never drops** (use the separate `bpf` filter type to drop).

### 3.1 Opt-in, per-link, user-driven

Nothing happens unless gns3server configures it (typically after the user sets a
BPF expression in the web UI). ubridge is otherwise inert (`marker_emit` is a
no-op with no sink; no `mark` filter = no work).

### 3.2 Configuration

**Real-time mode** — at ubridge launch, inject (zero extra round-trips):
```bash
UBRIDGE_MARKER_SINK=<gns3server_ip>:<port>  UBRIDGE_MARKER_NODE=<node_id>  ubridge -H ...
```
or, equivalently, after launch:
```
marker sink <host> <port>
marker node <node_id>
```
gns3server picks the UDP `<port>` (opens one listener for all ubridges) and a
unique `<node_id>` per ubridge. (`marker off` clears the sink; `marker status`
reports `enabled/sink/node/emitted`.)

**Per-link filter** — when the user configures BPF on a link:
```
bridge add_packet_filter <bridge> <name> mark <bpf_expr> [tag <id>] [link <id>] [pcap <path>]
```
- `<bridge>`: the ubridge bridge for this GNS3 link.
- `<name>`: filter name (gns3server-chosen; echoed in signals, used as pcap identity).
- `<bpf_expr>`: libpcap cBPF syntax (same as the `bpf` filter type).
- `tag <id>`: optional correlation id echoed in the signal.
- `link <id>`: optional link id echoed in the signal, for per-link attribution.
  Needed when one ubridge bridge serves several GNS3 links (e.g. IOU's per-node
  bridge): there `bridge` and `filter` are identical across links, so `link` is
  the only way to tell signals — and pcap files — apart.
- `pcap <path>`: optional; if given, every matched packet is appended to that
  pcap (standard, `EN10MB`). **gns3server should name it to encode identity**,
  keyed on `link` (not `bridge`+`filter`, which collide when one bridge serves
  several links), e.g. `<project>/markers/<node_id>_<link>_<filter>.pcap`.
- `tag`/`link`/`pcap` keyword pairs may appear in any order; each is normally given
  once (a repeat silently overwrites the earlier value — last one wins).

**Disable / change** — `bridge delete_packet_filter <bridge> <name>` (closes and
flushes the pcap; file persists). To change the BPF, delete then re-add.

### 3.3 What gns3server receives (real-time)

One UDP datagram per match, line-based ASCII:
```
MARK <sec.usec> node=<id> filter=<name> link=<link> tag=<tag> len=<n>\n
```
| Field | Meaning | When unset |
|-------|---------|------------|
| `MARK` | line-type marker | — |
| `<sec.usec>` | Unix epoch, `gettimeofday`, microsecond | — |
| `node=<id>` | the ubridge/node (`UBRIDGE_MARKER_NODE`) | `node=-` |
| `filter=<name>` | the matched filter's name | `filter=-` |
| `link=<link>` | the link id from `mark … link <id>` | `link=-` |
| `tag=<tag>` | the tag id from `mark … tag <id>` | `tag=-` |
| `len=<n>` | matched packet length in bytes | — |

Parse (Python):
```python
ts = float(data.split()[1])
kv = dict(t.split(b"=",1) for t in data.split() if b"=" in t)
# {'node':.., 'filter':.., 'link':.., 'tag':.., 'len':..}
```
> The signal carries **metadata only** — no packet bytes. `len` is the size; the
> bytes go to the `pcap` file (if configured).

### 3.4 What gns3server reads (replay)

Each `pcap <path>` is a **standard pcap (`EN10MB`)** containing that filter's
matched packets in match order, each timestamped. Read with tcpdump / tshark /
Wireshark / PyShark natively. **The link identity is the file path** (pcap records
carry no per-packet metadata) — gns3server tracks `path ↔ (node, link, filter)`.

### 3.5 Mode matrix

| Want | Configure |
|------|-----------|
| Real-time coloring only | set sink; `mark <bpf> [tag] [link]` (no `pcap`) |
| Offline replay only | `mark <bpf> [pcap <path>]` (no sink needed) |
| Both | `mark <bpf> link <id> tag <id> pcap <path>` + sink set |

---

## 4. Conventions gns3server must honor

- **`node_id` unique per ubridge** — it is the only way to identify the source of
  a signal (one UDP port serves all ubridges; source UDP port is ephemeral).
- **pcap path encodes `(node, link, filter)`** — the only link identity for replay.
- **Timestamps** are `gettimeofday` wall-clock; comparable across ubridges on the
  **same host**. For distributed GNS3 (ubridges on different hosts), sync clocks
  (NTP/PTP) for a correct global timeline.
- **`mark` is passive** — it never drops or alters traffic. To drop on match, use
  the existing `bpf` filter type instead.
- **One UDP listener** on gns3server for all ubridges; disambiguate by `node=`.

---

## 5. End-to-end flows

### Real-time (web UI coloring)
```
user sets BPF on a link → gns3server: add_packet_filter … mark <bpf> [tag]
match → ubridge sends MARK signal → gns3server UDP listener
      → WebSocket → web UI colors the packet by link (node/filter)
```

### Offline replay (web UI timeline)
```
during run:  ubridge appends matched packets to per-link pcaps
replay:      gns3server reads the pcaps, tags each packet with (node,link,filter),
             sorts globally by ts → exposes timeline + per-packet APIs to web UI
web UI:      scrubs timeline (cached index), fetches bytes/dissection on demand
```
A unified timeline across links is built by gns3server merging per-link pcaps by
timestamp (each packet tagged with its source link). Do **not** physically merge
into one pcap (classic pcap would lose per-packet link identity).

---

## 6. Lifecycle / teardown

- `bridge delete_packet_filter` or bridge stop → the filter's pcap is closed and
  flushed; the file persists on disk for replay.
- `marker off` → stops signals (pcap capture, if any, continues until the filter
  is deleted).
- ubridge exit → all pcaps closed.

---

## 7. Quick reference — new commands

```
# tap
tap create <name>                  tap set_owner <name> <uid>        tap delete <name>
# brctl (link plumbing)
brctl create <br>                  brctl addif <br> <tap>            brctl delif <br> <tap>        brctl delete <br>
# tc
tc netem set <if> [delay <ms>] [jitter <ms>] [loss <%>] [dup <%>] [corrupt <%>]
tc reset <if>
# capture
capture start_kernel <if> <pcap> [dlt]                               capture stop_kernel
# marker
marker sink <host> <port>          marker node <id>                  marker off                     marker status
# mark filter (under bridge)
bridge add_packet_filter <br> <name> mark <bpf> [tag <id>] [link <id>] [pcap <path>]
bridge delete_packet_filter <br> <name>
```
