# nio_raw test suite

Black-box regression for the two raw-L2 NIO backends, both of which attach to an
**existing** interface (unlike `nio_tap`, which creates a TUN/TAP device):

  * `nio_ethernet`  — libpcap (`pcap_open_live`, promisc) on a named interface
  * `nio_linux_raw` — `AF_PACKET SOCK_RAW` (`PACKET_MR_PROMISC` + `PACKET_AUXDATA`)

## How it works (the veth "wire")

We create a veth pair and treat it as a point-to-point Ethernet link:

```
  ubridge binds vnio0 (nio_ethernet / nio_linux_raw)  <-->  test on vnio1 (AF_PACKET)
                  bridge also has a nio_udp  <-->  test UDP socket
```

A veth pair is a true point-to-point link: frames sent on one end egress on the
other and never loop back, so ubridge's sends on vnio0 are seen only by the
test socket on vnio1 (no echo/capture loops). The test injects/sniffs L2 frames
on vnio1 via a stdlib `AF_PACKET SOCK_RAW` socket.

## Prerequisites

```bash
make            # ./ubridge
sudo make install   # cap_net_admin,cap_net_raw (or just run under sudo)
```

The test creates the veth pair itself (`ip link add`) and opens raw sockets, so
it needs CAP_NET_ADMIN + CAP_NET_RAW — run under `sudo python3 run_all.py`, or
locally without host sudo via `unshare -Urn python3 run_all.py` (a fresh user +
network namespace where the caller is root).

## Running

```bash
cd tests/nio_raw
sudo python3 run_all.py          # or: unshare -Urn python3 run_all.py
```

`run_all.py` exits non-zero if any suite fails, so it gates CI.

## Suites

| Suite | What it covers |
|-------|----------------|
| `test_ethernet.py` | nio_ethernet (pcap): L2 frame round-trips intact both directions; missing bridge -> 214; nonexistent iface -> 206. |
| `test_linux_raw.py` | nio_linux_raw (AF_PACKET): same relay both ways; a tagged (802.1Q) frame passes through uncorrupted; missing bridge -> 214; bad iface -> 206; device name >= NIO_DEV_MAXLEN(64) -> 206. |

## Caveats / known gaps

- **Stray traffic**: an UP veth gets kernel IPv6 ND/MLD frames that pcap/AF_PACKET
  capture and the bridge relays. Receivers use `recv_match()` to scan for *our*
  frame by content rather than assuming the next packet is ours.
- **VLAN reconstruction**: `nio_linux_raw` rebuilds an offloaded VLAN tag from
  `PACKET_AUXDATA` (`tp_vlan_tci`). That only fires when the NIC hardware-
  offloads VLAN stripping; veth does not, so the reconstruction branch can't be
  exercised here. The tagged-frame test covers only the non-offloaded passthrough.
