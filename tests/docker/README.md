# docker test suite

**No docker daemon is required.** Despite the module name, `src/hypervisor_docker.c`
exposes four netlink/ioctl commands GNS3 uses to plumb a container's network —
there is no docker socket, no libdocker, no container runtime involved. The
tests need only CAP_NET_ADMIN, like the other kernel suites.

## Commands under test

| Command | What it does |
|-------|---------------|
| `docker create_veth <if1> <if2>` | netlink RTM_NEWLINK veth pair; brings if1 UP, turns off TX checksum on if2 |
| `docker delete_veth <if>` | netlink RTM_DELLINK (the peer goes too) |
| `docker set_mac_addr <if> <mac>` | SIOCSIFHWADDR ioctl, after a regex MAC check |
| `docker move_to_ns <if> <pid> <dst>` | IFLA_NET_NS_PID — move iface into a netns, renamed |

## Prerequisites

```bash
make            # ./ubridge
sudo make install   # or just run the suite under sudo
```

## Running

```bash
cd tests/docker
sudo python3 run_all.py          # or: unshare -Urn python3 run_all.py
```

`run_all.py` exits non-zero if any suite fails, so it gates CI.

## Suites

| Suite | What it covers |
|-------|----------------|
| `test_veth.py` | create_veth: both ends exist, if1 UP; duplicate -> 206; overlong name -> 206. delete_veth: both ends gone; missing -> 207. |
| `test_mac.py` | set_mac_addr applies + replaces (verified via /sys/class/net); bad MAC (non-hex / short) -> 206; overlong iface -> 206; missing iface -> 206. |
| `test_move_ns.py` | move_to_ns: iface leaves current netns, arrives renamed in the target (verified via nsenter), peer stays; missing iface -> 206; bogus pid -> 206. Target netns is an `unshare -n` child. |

## How move_to_ns is verified

A child process is spawned with `unshare -n sleep` so it owns a fresh network
namespace; its PID is the move target. After `docker move_to_ns`, the test runs
`nsenter -t <pid> -n ip link show <dst>` to confirm the interface landed in that
namespace under its new name. Killing the child destroys the namespace (and the
moved interface with it).
