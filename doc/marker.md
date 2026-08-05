# marker — packet-filter match signals

The `mark` packet filter (under the `bridge` module) and the `marker` module
together let the controller **react to / assert on specific traffic**: a
matching packet emits a one-line **marker signal** pushed as a UDP datagram to a
configured sink (gns3server). The filter is a **passive tap** — it signals but
does not drop.

## Why

For traffic-driven automation: "when DHCP Discover is seen, notify my test",
"assert packet X appeared", sync a test on a flow event. Signals are pushed out
of band (UDP), so the controller doesn't have to poll.

## Architecture

```
per-node ubridge (mark filter, on match)  ──UDP──▶  gns3server:port (consumer)
```

Each per-node ubridge is a pure **UDP client**: on match, one `sendto` to the
configured sink. No listener, no thread, no per-node server. `marker_emit` is a
no-op when no sink is set, so `mark` filters are cheap when unused.

## The `mark` packet filter

Registered under the `bridge` module like the other filter types:

```
bridge add_packet_filter <bridge> <name> mark <bpf_expr> [tag <id>] [link <id>] [dir <tx|rx>] [pcap <path>]
```

- Matches via libpcap cBPF (`pcap_offline_filter`), exactly like the `bpf`
  filter type.
- On match → emits a marker signal (if a sink is set) **and**, if `pcap <path>`
  is given, appends the packet to that pcap file. **Always returns PASS** (the
  packet continues; to drop on match use the separate `bpf` filter type).
- `tag <id>` is an optional id echoed in the signal, for correlation.
- `link <id>` is an optional id echoed in the signal, for **topology link
  attribution**. Distinct from `tag` (free-form correlation): when one ubridge
  bridge carries several links — notably IOU's per-node `IOL-BRIDGE`, where
  every link shares the same bridge — `bridge` and `filter` are identical
  across those links, so the controller needs `link` to tell their signals (and
  pcap paths) apart. ubridge treats it as opaque and echoes it verbatim.
- `dir <tx|rx>` is an optional direction filter. `tx` = only emit signal and
  pcap on device-side ingress (capture node sending); `rx` = only on link-side
  ingress (capture node receiving). When omitted (default) the filter fires on
  both directions — backward compatible.
- `pcap <path>` is an optional path to a pcap file (standard, `EN10MB`) that
  **accumulates every matched packet** for this filter (open once on setup,
  append one record per match, closed when the filter is deleted). This is a
  BPF-filtered capture: only matches land in the file. gns3server names the
  path per link (e.g. `<project>/markers/<node>_<link>_<filter>.pcap`), keyed
  on `link` — `bridge`+`filter` collide when one bridge serves several links
  (IOU) — and reads it back for offline replay/analysis with
  tcpdump/Wireshark/PyShark.
- Keyword pairs (`tag`, `link`, `dir`, `pcap`) may appear in any order.

```
bridge add_packet_filter br0 dhcp_probe mark "udp port 67" tag 11
100-Filter 'dhcp_probe' configured in position 1

# per-link attribution (e.g. one port of a shared IOU bridge):
bridge add_packet_filter br0 icmp_l3 mark "icmp" link 3 pcap /tmp/icmp_l3.pcap
100-Filter 'icmp_l3' configured in position 2

# all at once (real-time signal + per-link + on-disk capture):
bridge add_packet_filter br0 dhcp mark "udp port 67" tag 11 link 3 pcap /tmp/dhcp.pcap
```

> The `pcap` option writes a **standard pcap** (same writer as
> `bridge start_capture` / `capture start_kernel`), so any pcap tool reads it
> with no conversion. Which link a file came from is encoded in its **path**
> (gns3server's naming) — classic pcap records carry no per-packet metadata, so
> the link identity lives at the file level, not inside the pcap.

## The `marker` module

```
marker sink <host> <port>   # set the UDP sink (gns3server)
marker node <id>            # node id echoed in signals
marker off                  # clear the sink (closes the UDP socket)
marker pause                # suppress all signals, keep the sink open
marker resume               # re-enable emission after `marker pause`
marker status               # enabled / paused / sink / node / emitted count
```

Configuration can also be injected at launch via environment variables (so the
controller doesn't need extra round-trips):

- `UBRIDGE_MARKER_SINK=host:port`
- `UBRIDGE_MARKER_NODE=<id>`

```
marker sink 127.0.0.1 9000
100-marker sink set to 127.0.0.1:9000
marker node qemu-r1
100-marker node set to qemu-r1
marker status
101 enabled=1 paused=0 sink=127.0.0.1:9000 node=qemu-r1 emitted=3
100-OK
```

## Pause / resume

There are two independent levers for stopping signal emission:

- **Per-filter** (`bridge` module) — pause or resume one filter:
  ```
  bridge enable_packet_filter <bridge> <name> on|off
  ```
  A paused (`off`) filter is **bypassed by the relay loop**: no `marker` signal
  and no pcap record for it, but the packet is still relayed (a paused `mark`
  filter is a no-op tap, not a drop). IOL bridges use the per-port form
  `iol_bridge enable_packet_filter <bridge> <bay> <unit> <name> on|off`.
  Works for any filter type, not just `mark`.

- **Global** (`marker` module) — `marker pause` / `marker resume` flip a gate
  inside `marker_emit()` that suppresses **all** signals, regardless of
  per-filter state. Unlike `marker off`, the sink socket stays open, so resume
  is instant and `emitted`/sink config are retained. Global pause overrides
  per-filter: a paused marker emits nothing even if every filter is enabled.

State of both levers is reported by `marker status` (`paused=`) and the
per-filter flag lives on the filter itself.

## Signal format

One UDP datagram per match, line-based:

```
MARK <sec.usec> node=<id> filter=<name> link=<link> tag=<tag> len=<n> dir=<tx|rx>
```

`node`/`link`/`tag` are `-` when unset. `dir` is the packet direction relative
to the capture node (`node`):

- `tx` — the packet entered on the **device-side NIO** (the capture node is
  *sending*): generic bridge = `source_nio`, IOL = the IOL instance side.
- `rx` — the packet entered on the **link-side NIO** (the capture node is
  *receiving*): generic bridge = `destination_nio`, IOL = the NIO side.

The controller pairs `node` + `dir` to draw an arrow on the topology link
(`tx` → capture→far, `rx` → far→capture). `dir` is **additive**: the line is
still parsed as space-separated `key=value` tokens, so an older controller that
ignores `dir` degrades to direction-less highlighting without error.

## Status codes

| Code | Meaning |
|------|---------|
| `100` | OK |
| `204` | Invalid sink port / bad value |
| `206` | Could not resolve / set sink |

## Consumer side (gns3server)

Out of ubridge's scope, but ~10 lines of Python: open a UDP socket, `recvfrom`,
split the `MARK` line into key/values, dispatch by `node`/`link`/`tag` (or
expose a `wait_for(tag, timeout)` helper for test synchronization).

```python
s = socket.socket(socket.AF_UNIX if False else socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 9000))
while True:
    data, _ = s.recvfrom(4096)
    kv = dict(t.split(b"=",1) for t in data.split() if b"=" in t)
    # {'filter': b'dhcp_probe', 'tag': b'11', 'node': b'qemu-r1', 'len': b'342', 'dir': b'tx'}
```

## Implementation notes

- **`mark` filter** (`src/packet_filter.c`): mirrors the
  `bpf` filter type. The filter name is captured at create time
  (`create_mark_filter` runs after `add_packet_filter` has `strdup`'d the name),
  because the handler only ever receives `filter->data`, not the name.
- **`marker` engine** (`src/marker.h`, `src/hypervisor_marker.c`): `marker_emit`
  formats the line and `sendto`'s a cached UDP socket under a mutex; the socket
  is (re)opened when a sink is set. UDP `sendto` is atomic for small datagrams,
  so no per-event buffering/thread is needed.
- **Direction (`dir=tx|rx`)**: only the relay loop knows which NIO a packet
  came in on, so `bridge_nios()` / the IOL listeners pass an ingress direction
  (`PKT_DIR_TX`/`PKT_DIR_RX`) to each `filter->handler`. The `mark` handler
  maps it to `"tx"`/`"rx"` and hands the string to `marker_emit`, which — like
  `tag`/`link` — just echoes it. Generic bridge: ingress on `source_nio` ⇒ `tx`,
  `destination_nio` ⇒ `rx`; IOL: from the IOL instance ⇒ `tx`, from the port
  NIO ⇒ `rx`.

## Testing

`tests/marker/` stands up a UDP listener as the sink, injects an IP frame into
a UDP-NIO bridge with a `mark "ip" tag 7` filter, and asserts the signal arrives
with the right node/filter/tag/len, that the frame was still relayed (passive),
and that `marker off` stops the signals.

> Note: ubridge's UDP NIO `connect()`s to the configured remote, so it only
> accepts packets whose source is that remote — the test binds the injector to
> the NIO's remote port so the injected frame is accepted.

**Pure user-space (UDP + libpcap cBPF) — no `CAP_NET_ADMIN` needed, no sudo:**

```bash
cd tests/marker && python3 run_all.py   # 13/13 PASS
```
