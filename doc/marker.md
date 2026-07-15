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
bridge add_packet_filter <bridge> <name> mark <bpf_expr> [tag <id>] [link <id>] [pcap <path>]
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
- `pcap <path>` is an optional path to a pcap file (standard, `EN10MB`) that
  **accumulates every matched packet** for this filter (open once on setup,
  append one record per match, closed when the filter is deleted). This is a
  BPF-filtered capture: only matches land in the file. gns3server names the
  path per link (e.g. `<project>/markers/<node>_<link>_<filter>.pcap`), keyed
  on `link` — `bridge`+`filter` collide when one bridge serves several links
  (IOU) — and reads it back for offline replay/analysis with
  tcpdump/Wireshark/PyShark.
- Keyword pairs (`tag`, `link`, `pcap`) may appear in any order.

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
marker off                  # clear the sink
marker status               # enabled / sink / node / emitted count
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
101 enabled=1 sink=127.0.0.1:9000 node=qemu-r1 emitted=3
100-OK
```

## Signal format

One UDP datagram per match, line-based:

```
MARK <sec.usec> node=<id> filter=<name> link=<link> tag=<tag> len=<n>
```

`node`/`link`/`tag` are `-` when unset. The controller parses the line and
dispatches by `node` / `link` / `filter` / `tag` (`link` disambiguates signals
that share a bridge+filter across multiple links).

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
    # {'filter': b'dhcp_probe', 'tag': b'11', 'node': b'qemu-r1', 'len': b'342'}
```

## Implementation notes

- **`mark` filter** (`src/packet_filter.c`, `#ifdef __linux__`): mirrors the
  `bpf` filter type. The filter name is captured at create time
  (`create_mark_filter` runs after `add_packet_filter` has `strdup`'d the name),
  because the handler only ever receives `filter->data`, not the name.
- **`marker` engine** (`src/marker.h`, `src/hypervisor_marker.c`): `marker_emit`
  formats the line and `sendto`'s a cached UDP socket under a mutex; the socket
  is (re)opened when a sink is set. UDP `sendto` is atomic for small datagrams,
  so no per-event buffering/thread is needed.
- Linux-only (`#ifdef __linux__` + Makefile Linux block), consistent with
  tap/tc/capture.

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
cd tests/marker && python3 run_all.py   # 8/8 PASS
```
