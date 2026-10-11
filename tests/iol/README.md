# iol test suite

Black-box regression for the IOL bridge (`src/hypervisor_iol_bridge.c`, the
2nd-largest module). The delay suite already exercises delay-on-IOL timing
both ways (`tests/delay/test_iol.py`); this suite covers the IOL-specific
control surface and dataplane that it doesn't:

  * command validation / lifecycle error codes
  * payload fidelity and header stripping (IOL -> NIO)
  * per-port routing by `pkt[DST_PORT]` (not a hub flood)
  * the exact IOL header ubridge builds and prepends (NIO -> IOL)

## How it talks to IOL (no IOL image needed)

ubridge's IOL bridge binds `/tmp/netio{uid}/{app_id}`; a real IOL instance
would live at `/tmp/netio{uid}/{iol_id}`. We bind that path ourselves as an
AF_UNIX datagram socket and speak the 8-byte IOL frame header:

```
 [0..1] DST_IDS   [2..3] SRC_IDS   [4] DST_PORT   [5] SRC_PORT
 [6] MSG_TYPE     [7] CHANNEL      then payload
```

`add_nio_udp <bridge> <iol_id> <bay> <unit> <lport> <rhost> <rport>` attaches a
UDP destination NIO at port_key = bay + unit*16. The bridge routes IOL->NIO by
`pkt[DST_PORT]`; for NIO->IOL it builds dst=iol_id, src=app_id, ports=port_key.

## Prerequisites

Just the in-repo binary (AF_UNIX + high UDP, no caps):

```bash
make
```

No `sudo make install`, no CAP_NET_ADMIN for the lifecycle/relay suites.
`test_tap_anchor.py` creates taps, a veth pair and a bridge, so it needs
CAP_NET_ADMIN — run that one under sudo or `unshare -Urn` (it self-skips
otherwise, which keeps `run_all.py` green in an unprivileged CI job).

## Running

```bash
cd tests/iol
python3 test_lifecycle.py                       # one suite
sudo python3 test_tap_anchor.py                 # the one needing caps
unshare -Urn python3 run_all.py                 # everything, no sudo
```

`run_all.py` exits non-zero if any suite fails, so it can gate CI.

### Crafted frames and `br_netfilter`

Frames that have to cross a kernel bridge (only `test_tap_anchor.py` does)
must not claim to be IP unless they really are: with `br_netfilter` loaded —
`bridge-nf-call-iptables=1`, the usual state on a host running firewalld or
docker — a bridge port runs the netfilter hooks and the bridge's own
validation drops a frame whose ethertype says IPv4 but whose header is not a
well-formed IP header. Measured on a tap→bridge→tap chain: `0x0800` + ASCII
payload → dropped, `0x0800` + valid IPv4 header → forwarded, `0x88B5` (non-IP)
→ forwarded. The suites therefore craft probe frames with `PROBE_ET` (0x88B5).

## Suites

| Suite | What it covers |
|-------|----------------|
| `test_lifecycle.py` | create/duplicate, start/stop missing & already-running & not-running, rename collision, list/get_stats/reset_stats, add_nio_udp validation (iol_id==app_id, port>MAX_PORTS, missing bridge), delete missing. |
| `test_relay.py` | IOL->NIO payload intact; dst_port routes to the right NIO (and no hub flood); NIO->IOL prepends the exact header (dst=iol_id, src=app_id, ports=port_key); 5000-byte jumbo frames cross intact both ways (MAX_MTU is no longer 0x1000). |
| `test_tap_anchor.py` | TAP anchor ports (`add_nio_tap`/`delete_nio_tap`): both-direction relay, absent/too-long/unknown names, delete keeps the persistent device, UDP<->TAP swaps with no fd or thread leak, DOWN-anchor resilience (100 frames -> ubridge stays alive, all dropped with EIO), kernel-bridge interop (anchor + veth peer on one bridge), and the stopped-delete fd release. Needs `CAP_NET_ADMIN` (taps, veth, bridge) — self-skips without it. |

## Conventions

- Re-uses the delay suite's Ubridge/Client/Results via `helpers.py` (file-path
  import, no shared package). Same connected-NIO injection model as the delay
  suite.
