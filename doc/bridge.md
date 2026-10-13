# bridge module — the user-space NIO relay

The `bridge` hypervisor module is ubridge's **user-space NIO relay** — one of
the two data paths, alongside the kernel data plane (whose kernel-bridge half
is the separate [`brctl`](brctl.md) module). A bridge relays frames between
**exactly two NIOs** (one listener thread per direction), with one
packet-filter chain shared by both directions and an optional per-bridge pcap
capture. It is exposed via the hypervisor text protocol as
`bridge <command> [args...]`.

It is not superseded by the kernel data plane: any link with a UDP-tunnel,
UNIX-socket or IOU-fabric leg traverses the relay, and the user-space packet
filters (`delay`, `packet_loss`, …, `mark`) live here. Where both ends are
kernel interfaces, the kernel data plane ([`tap`](tap.md),
[`brctl`](brctl.md), [`vxlan`](vxlan.md)) takes over — see
[`gns3server-integration.md`](gns3server-integration.md) for how the two
compose. Typical relay deployments: UDP-tunnel links between emulated nodes,
the Docker port bridge (`add_nio_unix` container leg + a swappable topology
leg), and TAP ↔ UDP relays.

## Transport

Same text protocol as the other modules: newline-terminated commands, first
token is the module (`bridge`), second is the command, rest are arguments.
Replies are `NNN-...` (final line) or `NNN ...` (intermediate).

| Code | Meaning |
|------|---------|
| `100` | OK |
| `203` | Bad number of parameters |
| `204` | Invalid parameter value |
| `206` | Unable to create object (e.g. both NIO slots full) |
| `209` | Unable to start (fewer than 2 NIOs, already running, capture active) |
| `210` | Unable to stop (not running) |
| `213` | Unable to rename (name in use) |
| `214` | Not found — bridge/NIO missing, or a running-bridge refusal |

## Privileges

`udp`/`unix` NIOs and every command need no capability. `tap`, `ethernet`
and `linux_raw` NIOs open kernel interfaces and need `CAP_NET_ADMIN`
(`CAP_NET_RAW` for the raw ones); `sudo make install` grants both.

## Lifecycle

- **bridge create** *\<bridge_name\>*: Create a new (not running) bridge.

``` {.bash}
bridge create br0
100-bridge 'br0' created
```

- **bridge list**: List all existing bridges with their NIO count.

``` {.bash}
bridge list
101 br0 (NIOs = 0)
100-OK
```

- **bridge delete** *\<bridge_name\>*: Stop it if running, then free its
    NIOs, filters and capture.

``` {.bash}
bridge delete br0
100-bridge 'br0' deleted
```

- **bridge start** *\<bridge_name\>*: Start relaying. A bridge must have
    **2 NIOs** to start.

``` {.bash}
bridge start br0
100-bridge 'br0' started
```

- **bridge stop** *\<bridge_name\>*: Stop the listener threads. **Every NIO
    is kept** (and the capture), so `start` resumes the same configuration —
    this is what preserves a unix-socket NIO's binding across a swap window.

- **bridge rename** *\<old_name\>* *\<new_name\>*

- **bridge show** *\<bridge_name\>*: Running state, configured filters (in
    chain order) and NIO descriptions.

``` {.bash}
bridge show br0
101 bridge 'br0' is running
101 Source NIO: 20000:127.0.0.1:30000
101 Destination NIO: eth0
100-OK
```

- **bridge get_stats** / **bridge reset_stats** *\<bridge_name\>*: Per-NIO
    packet/byte counters.

``` {.bash}
bridge get_stats br0
101 Source NIO:      IN: 5 packets (90 bytes) OUT: 15 packets (410 bytes)
101 Destination NIO: IN: 15 packets (410 bytes) OUT: 5 packets (90 bytes)
100-OK
```

## NIOs

Each add command fills one slot — the first NIO added is the *source*, the
second the *destination*; both slots full → further adds are refused
(`206`). A **running** bridge refuses NIO deletion (`214`): the relay threads
hold the NIO pointers for their whole life, so freeing under them is a
use-after-free. The swap sequence is:

```
bridge stop → delete_nio_* → add_nio_* → bridge start
```

- **bridge add_nio_udp** *\<bridge\>* *\<local_port\>* *\<remote_host\>*
    *\<remote_port\>*: A connected UDP tunnel. `delete_nio_udp` removes the
    matching NIO; `remove_nio_udp` is the legacy alias.

``` {.bash}
bridge add_nio_udp br0 20000 127.0.0.1 30000
100-NIO UDP added to bridge 'br0'
bridge delete_nio_udp br0 20000 127.0.0.1 30000
100-NIO UDP removed from bridge 'br0'
```

- **bridge add_nio_unix** *\<bridge\>* *\<local\>* *\<remote\>*: An AF_UNIX
    datagram socket bound to `local`, sending to `remote` (the container leg
    of the Docker port bridge).

``` {.bash}
bridge add_nio_unix br0 "/tmp/local" "/tmp/remote"
100-NIO UNIX added to bridge 'br0'
```

- **bridge add_nio_tap** *\<bridge\>* *\<tap_device\>* *[on|off]*: Open a TAP
    as an NIO. **Create-if-missing**: a name that does not exist is created
    as a transient TAP (dies with the fd); a TAP born this way is hardened
    L2-only, like every creator's. The optional argument sets the initial
    carrier (default `on`); `set_nio_tap_carrier` flips carrier at runtime
    (plug/unplug emulation).

``` {.bash}
bridge add_nio_tap br0 tap0
100-NIO TAP added to bridge 'br0'
bridge set_nio_tap_carrier br0 off
100-TAP carrier set off on bridge 'br0'
```

- **bridge delete_nio_tap** *\<bridge\>* *\<tap_device\>*: Release the TAP
    NIO — the fd closes, **the interface itself survives** (persistent
    anchors are deleted with the [`tap`](tap.md) module). The NIO is matched
    by the kernel-resolved interface name, so a name the kernel truncated to
    15 chars cannot fail to match its own NIO. Refused (`214`) while the
    bridge is running; swap as above.

- **bridge add_nio_ethernet** *\<bridge\>* *\<eth_device\>*: A generic
    Ethernet NIO using libpcap (promiscuous; `CAP_NET_ADMIN` required).

- **bridge add_nio_linux_raw** *\<bridge\>* *\<eth_device\>*: A Linux RAW
    (AF_PACKET) NIO — a bit faster than the libpcap path; VLAN tags are
    reconstructed from the socket's auxdata.

## Capture

- **bridge start_capture** *\<bridge\>* *\<pcap_file\>* *[linktype]*: Start
    a pcap capture of the relayed frames; the link type defaults to
    `EN10MB`.
- **bridge stop_capture** *\<bridge\>*
- **bridge set_pcap_filter** *\<bridge\>* *[filter]*: Set — or reset, with
    no filter argument — a libpcap capture filter on the bridge's Ethernet
    NIO. Requires at least one Ethernet NIO on the bridge.

Kernel-data-plane traffic never enters the relay; capture it with
[`capture`](capture.md) instead.

## Packet filters

One chain per bridge, traversed by both directions (which is why a filter
that drops `R`% yields an effective round-trip survival of `(1-R)²` — see
[`packet_filter.md`](packet_filter.md)). The chain is managed at runtime:

- **bridge add_packet_filter** *\<bridge\>* *\<name\>* *\<type\>* *[args...]*:
    Append a filter. Names are unique per bridge; chain order is the order
    of adds.
- **bridge delete_packet_filter** *\<bridge\>* *\<name\>*
- **bridge enable_packet_filter** *\<bridge\>* *\<name\>* *on|off*: Pause or
    resume a filter without deleting it. A paused filter is bypassed by the
    relay loop — no drop, no signal, no capture — but traffic still flows.
- **bridge reset_packet_filters** *\<bridge\>*: Drop every impairment filter
    (drop / loss / delay / corrupt / bpf). `mark` filters are preserved —
    they are passive taps holding an open pcap that must survive an
    impairment reapply. Bridge stop / delete still tears down `mark`.

| Type | Args | Semantics |
|------|------|-----------|
| `frequency_drop` | `<frequency>` | `-1` drops everything, `N` drops every Nth packet, `0` drops nothing |
| `packet_loss` | `<percentage>` | random drop (0–100%) |
| `delay` | `<latency_ms> [jitter_ms]` | real delay line (netem-like); see [`packet_filter.md`](packet_filter.md) |
| `corrupt` | `<percentage>` | randomly corrupt bytes (never drops) |
| `bpf` | `<expression> [linktype]` | drop on match (libpcap cBPF) |
| `mark` | `<expression> [tag <id>] [link <id>] [pcap <path>] [dir <tx\|rx>] [linktype <name>]` | passive tap: marker signal + optional pcap; see [`marker.md`](marker.md) |

``` {.bash}
bridge add_nio_udp br0 20000 127.0.0.1 30000
bridge add_nio_udp br0 20001 127.0.0.1 30001
bridge add_packet_filter br0 "my_filter1" "delay" 50 10
bridge add_packet_filter br0 "my_filter2" "frequency_drop" 5
bridge add_packet_filter br0 "my_filter5" "bpf" "icmp[icmptype] == 8"
bridge show br0
101 bridge 'br0' is not running
101 Filter 'my_filter1' configured in position 1
101 Filter 'my_filter2' configured in position 2
101 Filter 'my_filter5' configured in position 3
101 Source NIO: 20000:127.0.0.1:30000
101 Destination NIO: 20001:127.0.0.1:30001
100-OK
```

## Testing

`tests/bridge/` (stdlib only, no third-party dependencies):

| Suite | Covers |
|-------|--------|
| `test_zero_length.py` | A zero-length read is skipped, not forwarded or counted — the `nio_recv` 0→-1 regression |
| `test_swap.py` | `delete_nio_tap` semantics: validation codes, the running refusal, udp↔tap swaps, the unix binding surviving the swap window |
| `test_relay.py` | unix↔tap relay in both directions; an admin-DOWN anchor as a steady state |

```bash
cd tests/bridge && python3 run_all.py   # tap suites self-skip unprivileged
```
