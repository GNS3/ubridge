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
bridge add_packet_filter <bridge> <name> mark <bpf_expr> [tag <id>]
```

- Matches via libpcap cBPF (`pcap_offline_filter`), exactly like the `bpf`
  filter type.
- On match → emits a marker signal. **Always returns PASS** (the packet
  continues; to drop on match use the separate `bpf` filter type).
- `<id>` is an optional tag echoed in the signal, for correlation.

```
bridge add_packet_filter br0 dhcp_probe mark "udp port 67" tag 11
100-Filter 'dhcp_probe' configured in position 1
```

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
101-enabled=1 sink=127.0.0.1:9000 node=qemu-r1 emitted=3
100-OK
```

## Signal format

One UDP datagram per match, line-based:

```
MARK <sec.usec> node=<id> filter=<name> tag=<tag> len=<n>
```

`node`/`tag` are `-` when unset. The controller parses the line and dispatches
by `node` / `filter` / `tag`.

## Status codes

| Code | Meaning |
|------|---------|
| `100` | OK |
| `204` | Invalid sink port / bad value |
| `206` | Could not resolve / set sink |

## Consumer side (gns3server)

Out of ubridge's scope, but ~10 lines of Python: open a UDP socket, `recvfrom`,
split the `MARK` line into key/values, dispatch by tag (or expose a
`wait_for(tag, timeout)` helper for test synchronization).

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
