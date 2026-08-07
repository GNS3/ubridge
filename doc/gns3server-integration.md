# ubridge ↔ gns3server integration contract

This document describes what ubridge exposes to gns3server for the **kernel
data plane** and **packet-match signaling** work. gns3server drives ubridge over
the existing hypervisor text protocol; ubridge is inert until commanded.

> Per-module details live in [`tap.md`](tap.md), [`brctl.md`](brctl.md),
> [`tc.md`](tc.md), [`capture.md`](capture.md), [`marker.md`](marker.md).
> This file is the cross-cutting contract for the gns3server side.

---

## 0. Protocol basics (recap)

- One control connection per ubridge — **AF_UNIX** (`-U`, recommended) or TCP
  (`-H`); see *Control channel: AF_UNIX + SO_PEERCRED* below. Line-based text:
  `<module> <command> [args...]`, newline-terminated.
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

- The kernel-data-plane modules (`tap`/`tc`/`capture`/`marker`) plus
  `brctl`/`link` require ubridge installed with capabilities:
  ```bash
  sudo make install     # sets cap_net_admin,cap_net_raw=ep
  ```

---

## Control channel: AF_UNIX + SO_PEERCRED

The control channel gains a secure **AF_UNIX** transport (`-U <socket_path>`)
authenticated by the kernel via `SO_PEERCRED`. The TCP listener (`-H`) is
**retained** for backward compatibility, remote use, and non-Linux builds — but
now **defaults to loopback** (`127.0.0.1`) instead of all interfaces, so a bare
`-H <port>` is reachable only locally. gns3server should move to `-U` on Linux;
`-H` keeps working during the transition.

**Why.** The old TCP control port listened (by default on `0.0.0.0`) with no
authentication. Any process that could reach it could issue bridge/NIO commands
and, given ubridge's `CAP_NET_ADMIN/CAP_NET_RAW`, take kernel L2 control of the
host. AF_UNIX lets the kernel authenticate the peer: `SO_PEERCRED` exposes the
connector's UID, and ubridge accepts only its own UID. gns3server's compute
process spawns ubridge locally and shares its UID, so the legitimate controller
always matches; any other local user is rejected. **No token, no handshake, no
protocol change.** The TCP path keeps the same remote exposure closed by its
loopback default rather than by removing TCP entirely.

**To adopt the secure `-U` transport** (recommended on Linux; `-H` remains
available, so this can land gradually) — all inside the existing connection
encapsulation; framing is untouched:

| # | Where | Change |
|---|-------|--------|
| 1 | `Hypervisor._build_command` | `-H host:port` → `-U socket_path` |
| 2 | `UBridgeHypervisor.connect()` | `open_connection` → `open_unix_connection` |
| 3 | `Hypervisor.__init__` | allocate a socket path instead of a TCP port |
| 4 | `host`/`port` across the class chain | two constructors + properties (see details) |
| 5 | `{host}:{port}` log strings | ubridge_hypervisor.py **and** base_node.py (see details) |
| 6 | node stop / project close | unlink the socket file (ubridge also unlinks on exit) |

Details for the trickier rows:

- **#1 location.** `_build_command` is on the `Hypervisor` class (hypervisor.py,
  ~L246-256; the `-H`/`host:port` line at ~L252-253) — **not** on `base_node`.
  base_node.py has no such method.
- **#3 socket naming + timing.** The ubridge PID is **not** known in `__init__`
  — ubridge is forked later in `start()` (hypervisor.py ~L167), so a name built
  from the ubridge pid can't be constructed in `__init__`. Allocate the path in
  `__init__` using **compute-pid + seq** (or just `<seq>`). Note
  `Hypervisor._instance_count` (~L51) exists but is **not** auto-incremented —
  add `Hypervisor._instance_count += 1`. Stale/residual protection comes from
  ubridge unlinking on start + `SO_PEERCRED`, not from encoding the ubridge pid
  in the name.
- **#4 two-layer.** `host`/`port` live in **two** constructors and their
  properties: parent `UBridgeHypervisor.__init__(host, port, …)` (~L43) with
  `host`/`port` properties (~L135-173), and child
  `Hypervisor.__init__(…, host, port=None)` (~L53). `send()`'s error paths
  (~L208) read `self._host`/`self._port`; after the switch those fields'
  semantics change, so the properties must return the path or be removed — don't
  treat them as dead code to delete blindly.
- **#5 log lines.** Beyond `ubridge_hypervisor.py` (~L80/82/208/235/247/258),
  `base_node.py` (~L931, L935) also logs `self._ubridge_hypervisor.host:port` —
  point those at the socket path too.

**Do not change / watch out for:**

- **Framing is unchanged.** `send()` (`command + "\n"`, read until `100-`/`2xx-`)
  works as-is; `open_unix_connection` returns the same `(reader, writer)`.
- **No authentication code needed.** `SO_PEERCRED` is implicit — compute forks
  ubridge, same UID, auto-pass. Do **not** add an `auth` command or shared secret.
- **Leave `port_manager` alone.** It allocates console/aux/wrap ports and the
  **UDP data-plane** tunnels. Only the control channel moves to a socket.
- **Keep the socket path short.** `sun_path` is at most 107 bytes;
  `<project working_dir>/<uuid>/<node_uuid>.sock` will overflow and `bind` fails
  silently. Use a short sequence under a private runtime dir, e.g.
  `/run/user/<uid>/gns3/ubridge-<seq>.sock` (see #3 for the pid/timing caveat).
- **Use a 0700 owner-private directory** for the socket. The 0600 socket file +
  directory perms are a filesystem-level second gate on top of `SO_PEERCRED`.
- **Keep `Server.host` config.** It's still used for data-plane UDP binding and
  controller reporting; only the control-connection `host` goes away.

**Deployment:**

- **Not breaking for `-H` users.** TCP still works; the only behavior change is
  that `ubridge -H <port>` now binds `127.0.0.1` instead of `0.0.0.0` (pass
  `0.0.0.0:<port>` explicitly to restore the old bind). Switching gns3server to
  `-U` can land gradually; to detect `-U` support, reuse the `hypervisor version`
  reply that `connect()` already sends (ubridge_hypervisor.py ~L86) — no new
  protocol.
- Run against the **new** ubridge build (`sudo make install` refreshes
  `/usr/local/bin/ubridge`); the old binary does not understand `-U`.
- The gns3server Linux-only fork may drop the TCP path entirely (send only `-U`,
  `open_unix_connection` only). Do **not** push that aggressive stance to
  upstream gns3server, which stays cross-platform.

See `tests/verify_unix_socket_auth.sh` for an end-to-end check (same-UID accept,
cross-UID reject, the `-U` instance exposes no TCP listener, and TCP `-H` binds
loopback).

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

(Full STP/VLAN/port-param set in [`brctl.md`](brctl.md); its [§ Limitations](brctl.md#limitations) note the default-PVID-1 cleanup step, QinQ scope (outer-tag only; standard EtherTypes 0x8100/0x88a8 only), and the absence of FDB read/flush.)

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
UBRIDGE_MARKER_SINK=<gns3server_ip>:<port>  UBRIDGE_MARKER_NODE=<node_id>  ubridge -U <socket_path>
```
or, equivalently, after launch:
```
marker sink <host> <port>
marker node <node_id>
marker pause | resume
```
gns3server picks the UDP `<port>` (opens one listener for all ubridges) and a
unique `<node_id>` per ubridge. `marker off` clears the sink (closes the UDP
socket); `marker pause` / `marker resume` flip a global gate that
suppresses / re-enables **all** signal emission while keeping the sink open
(resume is instant; sink + `emitted` retained). `marker status` reports
`enabled/paused/sink/node/emitted`.

**Per-link filter** — when the user configures BPF on a link:
```
bridge add_packet_filter <bridge> <name> mark <bpf_expr> [linktype <dlt>] [tag <id>] [link <id>] [dir <tx|rx>] [pcap <path>]
```
- `<bridge>`: the ubridge bridge for this GNS3 link.
- `<name>`: filter name (gns3server-chosen; echoed in signals, used as pcap identity).
- `<bpf_expr>`: libpcap cBPF syntax (same as the `bpf` filter type).
- `linktype <dlt>`: optional data-link type for the BPF compile **and** the pcap
  header; defaults to `EN10MB`. **Pass it for serial links** (Frame Relay / PPP
  / HDLC), whose header layout differs from Ethernet — otherwise the BPF matches
  at wrong offsets and Wireshark mis-parses the pcap. gns3server should pass the
  serial port's `data_link_types` value with the `DLT_` prefix stripped — they
  are exactly what ubridge accepts: Cisco HDLC→`C_HDLC`, Cisco PPP→`PPP_SERIAL`
  (DLT 50, HDLC-framed — **not** `PPP`/DLT 9, which is raw/unframed), Frame
  Relay→`FRELAY`; Ethernet links omit it. See [`marker.md`](marker.md) for the
  accepted names and the DLT/LINKTYPE caveat.
- `tag <id>`: optional correlation id echoed in the signal.
- `link <id>`: optional link id echoed in the signal, for per-link attribution.
  Needed when one ubridge bridge serves several GNS3 links (e.g. IOU's per-node
  bridge): there `bridge` and `filter` are identical across links, so `link` is
  the only way to tell signals — and pcap files — apart.
- `pcap <path>`: optional; if given, every matched packet is appended to that
  pcap (standard pcap; header linktype follows `linktype`, default `EN10MB`).
  **gns3server should name it to encode identity**,
  keyed on `link` (not `bridge`+`filter`, which collide when one bridge serves
  several links), e.g. `<project>/markers/<node_id>_<link>_<filter>.pcap`.
- `dir <tx|rx>`: optional direction filter. `tx` = only signal/capture on
  device-side ingress (capture node sending); `rx` = only on link-side ingress
  (receiving). Omit = both directions. Echoed in the signal as `dir=`.
- `linktype`/`tag`/`link`/`dir`/`pcap` keyword pairs may appear in any order; each is normally
  given once (a repeat silently overwrites the earlier value — last one wins).

**Disable / change** — `bridge delete_packet_filter <bridge> <name>` (closes and
flushes the pcap; file persists). To change the BPF, delete then re-add.
`bridge reset_packet_filters` does NOT remove `mark` filters — it drops only
impairment filters (drop/loss/delay/corrupt/bpf), so a marker's pcap stays open
across impairment reapply. Only an explicit `delete_packet_filter` (or bridge
stop/delete) closes a `mark` pcap.

**Pause / resume** — two independent levers (no delete/re-add needed):
- *Per filter*: `bridge enable_packet_filter <bridge> <name> on|off` (IOL per
  port: `iol_bridge enable_packet_filter <bridge> <bay> <unit> <name> on|off`).
  A paused (`off`) filter is bypassed — no signal, no pcap — but traffic is
  still relayed (a paused `mark` is a no-op tap, not a drop). Works for any
  filter type. **This is what gns3server drives from the marker spec's `enabled`
  field** (issue `off` right after `add_packet_filter` when `enabled=false`).
- *Global*: `marker pause` / `marker resume` (§3.2) suppresses all signals
  regardless of per-filter state — use for a project-wide "mute markers" toggle.

### 3.3 What gns3server receives (real-time)

One UDP datagram per match, line-based ASCII:
```
MARK <sec.usec> node=<id> filter=<name> link=<link> tag=<tag> len=<n> dir=<tx|rx>\n
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
| `dir=<tx\|rx>` | ingress direction relative to the capture node | `dir=-` |

Parse (Python):
```python
ts = float(data.split()[1])
kv = dict(t.split(b"=",1) for t in data.split() if b"=" in t)
# {'node':.., 'filter':.., 'link':.., 'tag':.., 'len':..}
```
> The signal carries **metadata only** — no packet bytes. `len` is the size; the
> bytes go to the `pcap` file (if configured).

### 3.4 What gns3server reads (replay)

Each `pcap <path>` is a **standard pcap** (header linktype = the filter's `linktype`, default `EN10MB`) containing that filter's
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
  flushed; the file persists on disk for replay. `bridge reset_packet_filters`
  does NOT close a `mark` pcap — it preserves `mark` (drops only impairment
  filters), so an impairment reapply never interrupts the capture.
- `marker off` → stops signals and closes the sink socket (pcap capture, if any,
  continues until the filter is deleted). `marker pause` is the lighter mute: it
  stops signals but keeps the sink, so `marker resume` is instant — prefer it for
  transient UI toggles.
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
marker pause                      marker resume
# mark filter (under bridge)
bridge add_packet_filter <br> <name> mark <bpf> [linktype <dlt>] [tag <id>] [link <id>] [dir <tx|rx>] [pcap <path>]
bridge delete_packet_filter <br> <name>
bridge enable_packet_filter <br> <name> on|off          # pause/resume one filter (any type)
```
