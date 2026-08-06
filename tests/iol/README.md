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

No `sudo make install`, no CAP_NET_ADMIN.

## Running

```bash
cd tests/iol
python3 test_lifecycle.py    # one suite
python3 run_all.py           # everything
```

`run_all.py` exits non-zero if any suite fails, so it can gate CI.

## Suites

| Suite | What it covers |
|-------|----------------|
| `test_lifecycle.py` | create/duplicate, start/stop missing & already-running & not-running, rename collision, list/get_stats/reset_stats, add_nio_udp validation (iol_id==app_id, port>MAX_PORTS, missing bridge), delete missing. |
| `test_relay.py` | IOL->NIO payload intact; dst_port routes to the right NIO (and no hub flood); NIO->IOL prepends the exact header (dst=iol_id, src=app_id, ports=port_key). |

## Conventions

- Re-uses the delay suite's Ubridge/Client/Results via `helpers.py` (file-path
  import, no shared package). Same connected-NIO injection model as the delay
  suite.
