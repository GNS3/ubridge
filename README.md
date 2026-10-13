uBridge
=======

uBridge connects the network interfaces of emulated devices (QEMU, Docker,
IOU, ...) so that GNS3 can wire them into topologies. It is Linux-only, and
gns3-server drives it over a line-based control protocol (a UNIX socket, or
TCP). It provides two data paths:

- a **user-space relay** that bridges NIOs — UDP tunnels, Ethernet, TAP and
  UNIX sockets — with per-bridge packet filters (delay, jitter, loss,
  corruption, BPF);
- a **kernel data plane** it provisions and controls — persistent TAPs,
  kernel bridges (ports, VLAN, STP), VXLAN, veth, tc/netem link impairment
  and AF_PACKET capture — where frames are forwarded by the kernel, without
  entering ubridge.

Packet capture and BPF match filtering are available on both paths.

Installation
------------

### Dependencies

- libpcap (the pcap library). On Debian/Ubuntu:

``` {.bash}
sudo apt-get install libpcap-dev
```

- pthread library.

### Build

In the source directory:

``` {.bash}
make
sudo make install
```

`make install` copies the binary to `/usr/local/bin` and grants it the
`cap_net_admin,cap_net_raw` capabilities via `setcap`, so it can be run by
non-root users.

Hypervisor mode
---------------

The hypervisor mode of uBridge lets you create, configure and remove its
objects — bridges and NIOs, kernel devices, filters, captures — at runtime.

There are two control-channel transports:

- **`-U <socket_path>` (recommended)** — a UNIX domain socket. The peer is
  authenticated by the kernel via `SO_PEERCRED`: only the same UID that runs
  ubridge may issue commands. Connect with a UNIX-socket client, e.g.
  `socat - UNIX-CONNECT:<path>` or `nc -U <path>`.
- **`-H [<ip>:]<tcp_port>`** — TCP (retained for backward compatibility and
  remote use). For security it **defaults to loopback** (`127.0.0.1`); pass an
  explicit IP (e.g. `-H 0.0.0.0:<port>`) to listen on other interfaces. Connect
  with `telnet <host> <port>`.

Usage: ubridge -U <socket_path>  |  ubridge -H [<ip>:]<tcp_port>

The command syntax is simple: *<module>* *<function>* [arguments...]
For example: "bridge create test" creates a bridge named "test".

The modules that are currently defined are given below:

- hypervisor : General hypervisor management
- bridge : the user-space NIO relay (also hosts the packet filters) — [`doc/bridge.md`](doc/bridge.md)
- iol_bridge : IOL (IOS on Linux) bridges management — [`doc/iol_bridge.md`](doc/iol_bridge.md)
- docker : Docker management — [`doc/docker.md`](doc/docker.md)
- brctl : Linux bridge management — [`doc/brctl.md`](doc/brctl.md)
- link : generic interface management — [`doc/link.md`](doc/link.md)
- vxlan : kernel VXLAN device lifecycle (kernel data plane) — [`doc/vxlan.md`](doc/vxlan.md)
- tap : persistent TAP device lifecycle (kernel data plane) — [`doc/tap.md`](doc/tap.md)
- tc : kernel netem link impairment — delay/jitter/loss/dup/corrupt plus
  rate/reorder/loss-gemodel/distribution/seed/limit — `bpf_drop`
  classic-BPF match-drop filters, the eBPF stateful modes
  (`nth_drop`/`quota_drop`/`window_drop`/`flow_drop`, needs CAP_BPF), and
  `tc capabilities` (kernel data plane) — [`doc/tc.md`](doc/tc.md)
- capture : kernel-side AF_PACKET capture (kernel data plane) — [`doc/capture.md`](doc/capture.md)
- marker : packet-filter match signals, pushed to a UDP sink; `add_kernel`
  sniffs a kernel interface directly for data-plane traffic that bypasses
  the relay (kernel data plane) — [`doc/marker.md`](doc/marker.md)

User-space link impairment (delay / jitter / loss / corrupt / BPF) is **not a
separate module**: it is a per-bridge filter chain configured through the
`bridge` module (`bridge add_packet_filter`). It runs inside ubridge's
user-space relay and works on every NIO type, including UDP tunnels that have
no kernel interface to attach a qdisc to.

The `tap`, `tc`, `capture`, and `marker` modules drive the **kernel data
plane** (frames flowing `TAP → kernel bridge → TAP`, bypassing ubridge's
user-space NIO relay): `tap`/`brctl` build the plumbing, `tc` replaces those
user-space packet filters at the qdisc level where a kernel interface is
available, `capture` taps the interface at the kernel level, and `marker`
signals filter matches off band.
See [`doc/packet_filter.md`](doc/packet_filter.md) for filter semantics and
[`doc/`](doc/) for per-module details.

### Hypervisor module ("hypervisor")

- **hypervisor version**: Display the version of ubridge.

``` {.bash}
hypervisor version
100-1.3.0
```

- **hypervisor module_list**: Display the module list, one `101` line per
    module.
- **hypervisor cmd_list** *\<module\>*: Display the commands recognized by
    the specified module, with their argument counts.
- **hypervisor close**: Close the current session.
- **hypervisor stop**: Destroy all objects and stop hypervisor.
- **hypervisor reset**: Destroy all objects. (used to get an empty
    configuration)

### Bridge module ("bridge")

The user-space NIO relay: each bridge connects exactly **two** NIOs with two
listener threads, and hosts one packet-filter chain (shared by both
directions), an optional pcap capture and per-NIO statistics. Full reference:
[`doc/bridge.md`](doc/bridge.md).

- **NIO types**: UDP tunnels, UNIX sockets, TAP, Ethernet (libpcap) and Linux
  RAW (AF_PACKET) — any two can be paired.
- **Packet filters** (`bridge add_packet_filter`): `frequency_drop`,
  `packet_loss`, `delay` (a real delay line, not an inline sleep), `corrupt`,
  `bpf` (drop on match) and `mark` (passive tap — signal + optional pcap).
  Semantics: [`doc/packet_filter.md`](doc/packet_filter.md) and
  [`doc/marker.md`](doc/marker.md).
- **Capture**: `bridge start_capture` / `stop_capture` write a per-bridge
  pcap of the relayed frames; `set_pcap_filter` applies a capture filter on
  an Ethernet NIO.

### Docker module ("docker")

Container plumbing: `create_veth` (pair creation; the host end is hardened
L2-only, brought UP and given the default MTU), `move_to_ns` (move + rename
into a container namespace), `set_mac_addr` and `delete_veth`. See
[`doc/docker.md`](doc/docker.md).

### Linux bridge ("brctl")

Full netlink management of Linux kernel bridges: lifecycle
(`create`/`delete`/`addif`/`delif`/`addip`/`delip`/`setup`/`show`),
bridge-level parameters (STP, ageing, VLAN filtering, multicast snooping,
group forwarding), per-port parameters (priority, path cost, state, hairpin,
isolation) and per-port VLAN membership. See [`doc/brctl.md`](doc/brctl.md).

### Generic interface management ("link")

veth pair creation, IPv4 assignment, link state control and the L2-only
hardening helper (`link l2only`), all via netlink — no `ip` command needed.
See [`doc/link.md`](doc/link.md).

### IOL Bridge module ("iol_bridge")

Terminates the ports of an IOU (IOL) instance on the `/tmp/netio<uid>/` Unix
fabric: each port ends on a UDP tunnel or a persistent TAP anchor, and pairs
with `brctl`/`tc`/`capture`/`marker` for kernel links. See
[`doc/iol_bridge.md`](doc/iol_bridge.md).

### Session example

This will bridge a tap0 interface to a UDP tunnel.

Start the hypervisor:

``` {.bash}
user@host# ./ubridge -U /tmp/ubridge.sock
Hypervisor control socket started (/tmp/ubridge.sock).
```

Connect via a UNIX socket client:

``` {.bash}
user@host# socat - UNIX-CONNECT:/tmp/ubridge.sock
```

``` {.bash}
bridge create br0
100-bridge 'br0' created

bridge start br0
209-bridge 'br0' must have 2 NIOs to be started

bridge add_nio_tap br0 tap0
100-NIO TAP added to bridge 'br0'

bridge add_nio_udp br0 20000 127.0.0.1 30000
100-NIO UDP added to bridge 'br0'

bridge show br0
101 bridge 'br0' is not running
101 Source NIO: tap0
101 Destination NIO: 20000:127.0.0.1:30000
100-OK

bridge start br0
100-bridge 'br0' started
```

Config file mode
----------------

Usage: create a file named `ubridge.ini` in the same directory as uBridge
and then start the executable.

Signal SIGHUP can be used to reload the config file.

Example of content:

``` {.ini}
; bridge Ethernet interface eth0 with an UDP tunnel
[bridge0]
source_ethernet = eth0
destination_udp = 10000:127.0.0.1:10001 ; syntax is local_port:remote_host:remote_port

; bridge TAP interface tap0 with an UDP tunnel
; and capture packets to /tmp/bridge1.pcap
[bridge1]
source_tap = tap0
destination_udp = 11000:127.0.0.1:11001
pcap_file = /tmp/bridge1.pcap
pcap_protocol = EN10MB ; PCAP data link type, default is EN10MB

; it is even possible to bridge two UDP tunnels and capture!
[bridge2]
source_udp = 40000:127.0.0.1:40001
destination_udp = 50000:127.0.0.1:50001
pcap_file = /tmp/bridge2.pcap

; or to bridge 2 interfaces
[bridge3]
source_tap = tap0
destination_ethernet = eth1
```

You can also use a RAW socket to bridge an Ethernet interface (a bit
faster than with the default PCAP method).

``` {.ini}
; bridge Ethernet interface eth0 with an UDP tunnel
; using the RAW socket method (Linux rocks!)
[bridge4]
source_linux_raw = eth0
destination_udp = 42000:127.0.0.1:42001
```

There is also the option to use a UNIX domain socket

``` {.ini}
; bridge UNIX domain socket with an UDP tunnel
[bridge5]
source_unix = /tmp/local_file:/tmp/remote_file
destination_udp = 42002:127.0.0.1:42003
```

Notes
-----

-   A Bridge name (e.g. bridge4) can be anything as long it is unique in
    the same file or inside the hypervisor.
-   Capabilities (`cap_net_admin,cap_net_raw`) must be set on the
    executable (`make install` does this via `setcap`), or you must run
    ubridge with administrator rights to bridge Ethernet or TAP interfaces.
-   In user-space relay mode it is only possible to bridge two interfaces or
    tunnels together — ubridge relays, it is not a hub or a switch. (The
    kernel data plane is different: `brctl` creates real kernel bridges that
    forward between any number of ports; that switching is the kernel's.)
