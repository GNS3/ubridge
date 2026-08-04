uBridge
=======

uBridge is a simple application to create user-land bridges between
various technologies. Currently, bridging between UDP tunnels, Ethernet
and TAP interfaces is supported. Packet capture is also supported.

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

The hypervisor mode of uBridge allows you to dynamically add and remove
bridges.

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
- bridge : bridges management (also hosts the user-space packet filters)
- iol_bridge : IOL (IOS on Linux) bridges management 
- docker : Docker management 
- brctl : Linux bridge management
- link : generic interface management
- tap : persistent TAP device lifecycle (kernel data plane)
- tc : kernel netem link impairment — delay/jitter/loss/dup/corrupt (kernel data plane)
- capture : kernel-side AF_PACKET capture (kernel data plane)
- marker : packet-filter match signals, pushed to a UDP sink (kernel data plane)

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
100-1.1.1
```

- **hypervisor module_list**: Display the module list.

``` {.bash}
101 marker
101 capture
101 tc
101 tap
101 link
101 brctl
101 iol_bridge
101 docker
101 bridge
101 hypervisor
100-OK
```

- **hypervisor cmd_list** *\<module\>*: Display commands
    recognized by the specified module.

``` {.bash}
hypervisor cmd_list bridge
101 list (min/max args: 0/0)
101 set_pcap_filter (min/max args: 1/2)
101 reset_packet_filters (min/max args: 1/1)
101 delete_packet_filter (min/max args: 2/2)
101 add_packet_filter (min/max args: 2/10)
101 stop_capture (min/max args: 1/1)
101 start_capture (min/max args: 2/3)
101 add_nio_linux_raw (min/max args: 2/2)
101 add_nio_ethernet (min/max args: 2/2)
101 add_nio_tap (min/max args: 2/2)
101 add_nio_unix (min/max args: 3/3)
101 delete_nio_udp (min/max args: 4/4)
101 remove_nio_udp (min/max args: 4/4)
101 add_nio_udp (min/max args: 4/4)
101 rename (min/max args: 2/2)
101 reset_stats (min/max args: 1/1)
101 get_stats (min/max args: 1/1)
101 show (min/max args: 1/1)
101 stop (min/max args: 1/1)
101 start (min/max args: 1/1)
101 delete (min/max args: 1/1)
101 create (min/max args: 1/1)
100-OK
```

- **hypervisor close**: Close the current session.

``` {.bash}
hypervisor close
100-OK
Connection closed by foreign host.
```

- **hypervisor stop**: Destroy all objects and stop hypervisor.

``` {.bash}
hypervisor stop
100-OK
Connection closed by foreign host.
```

- **hypervisor reset**: Destroy all objects. (used to get an
    empty configuration)

``` {.bash}
hypervisor reset
100-OK
```

### Bridge module (bridge)

- **bridge create** *\<bridge_name\>*: Create a new bridge.

``` {.bash}
bridge create br0
100-bridge 'br0' created
```

- **bridge list**: List all exiting Bridges.

``` {.bash}
bridge list
101 br0 (NIOs = 0)
100-OK
```

- **bridge delete** *\<bridge_name\>*: Delete a bridge.

``` {.bash}
bridge delete br0
100-bridge 'br0' deleted
```

- **bridge start** *\<bridge_name\>*: Start a bridge. A bridge
    must have 2 NIOs added in order to start.

``` {.bash}
bridge start br0
100-bridge 'br0' started
```

- **bridge stop** *\<bridge_name\>*: Stop a bridge.

``` {.bash}
bridge stop br0
100-bridge 'br0' stopped
```

- **bridge rename** *\<old_bridge_name\>*
    *\<new_bridge_name\>*: Rename a bridge.

``` {.bash}
bridge rename br0 br1
100-bridge 'br0' renamed to 'br1'
```

- **bridge add_nio_udp** *\<bridge_name\>* *\<local_port\>*
    *\<remote_host\>* *\<remote_port\>*: Add an UDP NIO with the
    specified parameters to a bridge.

``` {.bash}
bridge add_nio_udp br0 20000 127.0.0.1 30000
100-NIO UDP added to bridge 'br0'
```

- **bridge delete_nio_udp** *\<bridge_name\>* *\<local_port\>*
    *\<remote_host\>* *\<remote_port\>*: Remove an UDP NIO with the
    specified parameters to a bridge.

``` {.bash}
bridge delete_nio_udp br0 20000 127.0.0.1 30000
100-NIO UDP deleted from bridge 'br0'
```

- **bridge add_nio_unix** *\<local\>* *\<remote\>*: Add an UNIX
    NIO with 'local' the UNIX domain socket to receive and 'remote'
    to send

``` {.bash}
bridge add_nio_unix br0 "/tmp/local" "/tmp/remote"
100-NIO UNIX added to bridge 'br0'
```

- **bridge add_nio_tap** *\<bridge_name\>* *\<tap_device\>*:
    Add a TAP NIO to a bridge. TAP devices require root access.

``` {.bash}
bridge add_nio_tap br0 tap0
100-NIO TAP added to bridge 'br0'
```

- **bridge add_nio_ethernet** *\<bridge_name\>*
    *\<eth_device\>*: Add a generic Ethernet NIO to a bridge, using
    PCAP (0.9.4 and greater). It requires root access.

``` {.bash}
bridge add_nio_ethernet br0 eth0
100-NIO Ethernet added to bridge 'br0'
```

- **bridge add_nio_linux_raw** *\<bridge_name\>*
    *\<eth_device\>*: Add a Linux RAW Ethernet NIO. It requires root access.

``` {.bash}
bridge add_nio_linux_raw br0 eth0
100-NIO Linux raw added to bridge 'br0'
```

- **bridge show** *\<bridge_name\>*: Show the NIOs on a bridge.

``` {.bash}
bridge show bridge0
101 bridge 'br0' is running
101 Source NIO: 20000:127.0.0.1:30000
101 Destination NIO: eth0
```

- **bridge start_capture** *\<bridge_name\>* *\<pcap_file\>*
    \[pcap_linktype\]: Start a PCAP packet capture on a bridge. PCAP
    link type default is Ethernet "EN10MB".

``` {.bash}
bridge start_capture br0 "/tmp/my_capture.pcap"
100-packet capture started on bridge 'br0'
```

- **bridge stop_capture** *\<bridge_name\>*: Stop a PCAP packet
    capture on a bridge.

``` {.bash}
bridge stop_capture br0
100-packet capture stopped on bridge 'br0'
```

- **bridge set_pcap_filter** *\<bridge_name\>* \[filter\]: Set
    a PCAP filter on a bridge. There must be a least one NIO Ethernet
    attached to the bridge. To reset any applied filter, same command
    without a filter.

``` {.bash}
bridge set_pcap_filter br0 "not ether src 00:50:56:c0:00:0a"
100-filter 'not ether src 00:50:56:c0:00:0a' applied on bridge 'br0'
```

``` {.bash}
bridge set_pcap_filter br0
100-filter reset on bridge 'br0'
```

- **bridge get_stats** *\<bridge_name\>*: Show statistics about
    a bridge input/output.

``` {.bash}
bridge get_stats bridge0
101 Source NIO:      IN: 5 packets (90 bytes) OUT: 15 packets (410 bytes)
101 Destination NIO: IN: 15 packets (410 bytes) OUT: 5 packets (90 bytes)
```

- **bridge reset_stats** *\<bridge_name\>*: Reset the statistics
    of a bridge.

``` {.bash}
bridge reset_stats bridge0
100-OK
```

- **bridge add_packet_filter** *\<bridge_name\>*
    *\<filter_name\>* *\<filter_type\>* \[*\<a4\>*
    \[\...*\<a10\>*\]\]: Add a packet filter to a bridge.

#### Filter types

##### frequency_drop

"frequency_drop" has 1 argument "*\<frequency\>*". It will drop
everything with a -1 frequency, drop every Nth packet with a positive
frequency, or drop nothing.

##### packet_loss

"packet_loss" has 1 argument "*\<percentage\>*" (0 to 100%). The
percentage represents the chance for a packet to be lost.

##### delay

"delay" has 1 argument "*\<latency\>*" to delay packets in
milliseconds and 1 optional argument "*\<jitter\>*" to add jitter in
milliseconds (+/-) of the delay

##### corrupt

"corrupt" has 1 argument "*\<percentage\>*" (0 to 100%). The
percentage represents the chance for a packet to be corrupted.

##### bpf

"bpf" has 1 argument "*\<filter_expression\>*", a string written
with the Berkeley Packet Filter (BPF) syntax. This filter will drop any
packet matching the expression. It also has 1 optional argument
*\<pcap_linktype\>* which is the PCAP link type, the default is
Ethernet "EN10MB".

##### mark

"mark" has 1 argument "*\<filter_expression\>*" (libpcap cBPF
syntax, like "bpf") plus optional keyword pairs `tag <id>`, `link <id>`,
`pcap <path>` (any order). It is a **passive tap**: on a match it emits a UDP
marker signal to a configured sink (set via the `marker` module) and, when
`pcap <path>` is given, appends the matched packet to that pcap file — it never
drops traffic (use "bpf" to drop). See [`doc/marker.md`](doc/marker.md).

``` {.bash}
bridge add_packet_filter br0 "my_filter1" "delay" 50 10
bridge add_packet_filter br0 "my_filter2" "frequency_drop" 5
bridge add_packet_filter br0 "my_filter3" "packet_loss" 20
bridge add_packet_filter br0 "my_filter4" "corrupt" 30
bridge add_packet_filter br0 "my_filter5" "bpf" "icmp[icmptype] == 8"
bridge add_packet_filter br0 "my_filter6" "bpf" "ether host 11:22:33:44:55:66"
bridge add_packet_filter br0 "my_filter7" "bpf" "tcp src port 53"
bridge show br0
101 bridge 'br0' is not running
101 Filter 'my_filter1' configured in position 1
101 Filter 'my_filter2' configured in position 2
101 Filter 'my_filter3' configured in position 3
101 Filter 'my_filter4' configured in position 4
101 Filter 'my_filter5' configured in position 5
101 Filter 'my_filter6' configured in position 6
101 Filter 'my_filter7' configured in position 7
101 Source NIO: 20000:127.0.0.1:30000
101 Destination NIO: 20001:127.0.0.1:30001
100-OK
```

- **bridge delete_packet_filter** *\<bridge_name\>*
    *\<filter_name\>*: Delete a packet filter configured on a bridge.

``` {.bash}
bridge delete_packet_filter br0 "my_filter1"
100-Filter 'my_filter1' delete from bridge 'br0'
```

**bridge reset_packet_filters** *\<bridge_name\>*: Delete all
    impairment filters (drop/loss/delay/corrupt/bpf) configured on a bridge.
    `mark` filters are preserved — they are passive observability taps holding
    an open pcap that must survive impairment reapply. (Bridge delete / stop
    still tears down `mark`.)

``` {.bash}
bridge reset_packet_filters br0
100-OK
```

### Docker module ("docker")

- **docker create_veth** *\<interface_name_1\>*
    *\<interface_name_2\>*: Create virtual Ethernet interface pair.

``` {.bash}
docker create_veth hostif guestif
100-veth pair created: hostif and guestif
```

- **docker move_to_ns** *\<interface\>* *\<namespace_id\>*
    *\<dst_interface\>*: Move Ethernet interface to network
    namespace. And rename it after the move.

``` {.bash}
docker move_to_ns guestif 6367 eth0
100-guestif moved to namespace 6367
```

- **docker set_mac_addr** *\<interface\>* *\<mac_addr\>*
    *\<mac_addr\>*: Set a MAC address on an interface.

``` {.bash}
docker set_mac_addr tap-gns3-e0 12:34:56:78:12:42
100-MAC address 12:34:56:78:12:42" has been successfully set on interface tap-gns3-e0
```

- **docker delete_veth** *\<interface_name\>*: Delete virtual
    Ethernet interface.

``` {.bash}
docker delete_veth hostif
100-veth interface hostif has been deleted
```

### Linux bridge ("brctl")

Manage Linux kernel bridges via netlink. The module replaces the
old ioctl-based bridge management with full netlink support and
runtime parameter configuration.

#### Basic commands

- **brctl create** *\<bridge_name\>*: Create a Linux bridge.

``` {.bash}
brctl create br0
100-Bridge br0 created
```

- **brctl delete** *\<bridge_name\>*: Delete a Linux bridge.

``` {.bash}
brctl delete br0
100-Bridge br0 deleted
```

- **brctl addif** *\<bridge_name\>* *\<port_interface\>*:
    Enslave an interface to a bridge and automatically bring it UP.

``` {.bash}
brctl addif br0 tap0
100-tap0 has been added to bridge br0
```

- **brctl delif** *\<bridge_name\>* *\<port_interface\>*:
    Release a port interface from its bridge.

``` {.bash}
brctl delif br0 tap0
100-tap0 removed from bridge br0
```

- **brctl addip** *\<bridge_name\>* *\<ip/prefixlen\>*:
    Assign an IPv4 address to the bridge and bring it UP.

``` {.bash}
brctl addip br0 192.168.1.1/24
100-IP 192.168.1.1/24 added to bridge br0
```

- **brctl setup** *\<bridge_name\>* *\<ip/prefixlen\>*:
    Create a bridge and assign an IPv4 address in one step.

``` {.bash}
brctl setup br0 192.168.1.1/24
100-Bridge br0 created with IP 192.168.1.1/24
```

- **brctl show** *\<bridge_name\>*:
    Show the IP address, prefix and operational flags of a bridge.

``` {.bash}
brctl show br0
100-br0 192.168.1.1/24 UP
```

#### Bridge-level parameters

- **brctl stp** *\<bridge_name\>* **on**|**off**:
    Enable or disable Spanning Tree Protocol.

``` {.bash}
brctl stp br0 on
100-STP enabled on bridge br0
```

- **brctl setbridgeprio** *\<bridge_name\>* *\<0-65535\>*:
    Set the bridge priority (used by STP).

``` {.bash}
brctl setbridgeprio br0 4096
100-Bridge priority 4096 set on br0
```

- **brctl setfd** *\<bridge_name\>* *\<2-30\>*:
    Set forward delay in seconds (STP).

``` {.bash}
brctl setfd br0 15
100-Forward delay 15s set on br0
```

- **brctl sethello** *\<bridge_name\>* *\<1-10\>*:
    Set hello time in seconds (STP).

``` {.bash}
brctl sethello br0 2
100-Hello time 2s set on br0
```

- **brctl setmaxage** *\<bridge_name\>* *\<6-40\>*:
    Set max age in seconds (STP).

``` {.bash}
brctl setmaxage br0 20
100-Max age 20s set on br0
```

- **brctl setageing** *\<bridge_name\>* *\<secs\>*:
    Set MAC address ageing time in seconds.

``` {.bash}
brctl setageing br0 300
100-Ageing time 300s set on br0
```

- **brctl vlanfiltering** *\<bridge_name\>* **on**|**off**:
    Enable or disable VLAN filtering on the bridge.

``` {.bash}
brctl vlanfiltering br0 on
100-VLAN filtering enabled on bridge br0
```

- **brctl setvlanproto** *\<bridge_name\>* **0x8100**|**0x88a8**:
    Set the VLAN protocol (802.1Q or 802.1ad).

``` {.bash}
brctl setvlanproto br0 0x88a8
100-VLAN protocol 0x88a8 set on br0
```

- **brctl mcastsnoop** *\<bridge_name\>* **on**|**off**:
    Enable or disable multicast snooping.

``` {.bash}
brctl mcastsnoop br0 off
100-Multicast snooping disabled on bridge br0
```

- **brctl setgroupfwd** *\<bridge_name\>* *\<0-65535\>*:
    Set the group forwarding mask for link-local frames.

``` {.bash}
brctl setgroupfwd br0 0
100-group_fwd_mask 0x0 set on br0
```

#### Port-level parameters

These commands modify bridge port attributes via the kernel's
IFLA_PROTINFO interface. The port interface must already be
enslaved to the bridge.

- **brctl setportprio** *\<bridge_name\>* *\<port\>* *\<0-63\>*:
    Set the STP port priority (kernel limit; the parser accepts 0-255
    but 64+ is rejected by the kernel with 206).

``` {.bash}
brctl setportprio br0 tap0 48
100-Port priority 48 set on tap0
```

- **brctl setpathcost** *\<bridge_name\>* *\<port\>* *\<1-65535\>*:
    Set the STP path cost for a port.

``` {.bash}
brctl setpathcost br0 tap0 100
100-Path cost 100 set on tap0
```

- **brctl setportstate** *\<bridge_name\>* *\<port\>* *\<0-3\>*:
    Set the STP port state (0=disabled, 1=listening,
    2=learning, 3=forwarding).

``` {.bash}
brctl setportstate br0 tap0 3
100-Port state 3 set on tap0
```

- **brctl hairpin** *\<bridge_name\>* *\<port\>* **on**|**off**:
    Enable or disable hairpin mode (reflect frames back).

``` {.bash}
brctl hairpin br0 tap0 on
100-Hairpin mode enabled on tap0
```

- **brctl isolated** *\<bridge_name\>* *\<port\>* **on**|**off**:
    Enable or disable port isolation. An isolated port can only communicate
    with the bridge's CPU port, not with other bridge ports — used to
    L2-isolate peers that share one bridge.

``` {.bash}
brctl isolated br0 tap0 on
100-Port isolation enabled on tap0
```

#### VLAN membership

Per-port VLAN ID add/delete/show — the primitives for access/trunk/QinQ
port modes. The bridge must have `vlanfiltering on`, and the port must be
enslaved to it. ESW access/trunk modes are composed from these primitives
in gns3server, not here.

- **brctl vlan_add** *\<bridge_name\>* *\<port\>* *\<vid\>* `[vid <end>]` `[pvid]` `[untagged]`:
    Add a VLAN (or `vid <end>` range) to a port. `pvid` = strip the tag on
    ingress (the port's PVID); `untagged` = strip on egress.

``` {.bash}
brctl vlan_add br0 tap0 100 pvid untagged
100-VLAN 100 added on tap0
```

- **brctl vlan_del** *\<bridge_name\>* *\<port\>* *\<vid\>* `[vid <end>]`:
    Delete a VLAN/range from a port (by VID only — flags are not accepted).

``` {.bash}
brctl vlan_del br0 tap0 100
100-VLAN 100 deleted from tap0
```

- **brctl vlan_show** *\<bridge_name\>* `[<port>]`:
    List per-port VLAN membership — one continuation line per (port, vid)
    as `<port> <vid> [PVID] [Egress Untagged]`, then a `100-` summary.

``` {.bash}
brctl vlan_show br0 tap0
101 tap0 1 Egress Untagged
101 tap0 100 PVID Egress Untagged
101 tap0 200
100-3 VLAN entries
```



### Generic interface management ("link")

Manage generic network interfaces (veth pairs, IP assignment, link state)
via netlink — no `ip` command needed, all done with ubridge's capabilities.

- **link veth** *\<name\>* *\<peer\>*: Create a veth pair. Both ends
    start DOWN; use `brctl addif` to attach one end to a bridge and
    `link set ... up` to bring it up.

``` {.bash}
link veth v-host v-ns
100-Veth pair v-host/v-ns created
```

- **link addr** *\<interface\>* *\<ip/prefixlen\>*: Assign an IPv4 address
    to an interface and bring it UP. Works on any interface (veth, bridge,
    dummy, tap), not just bridges.

``` {.bash}
link addr v-host 172.20.0.10/24
100-IP 172.20.0.10/24 set on v-host
```

- **link set** *\<interface\>* **up**|**down**: Bring an interface up or
    down (administrative state).

``` {.bash}
link set v-host up
100-Interface v-host up
```

- **link delete** *\<interface\>*: Delete an interface. For a veth pair,
    deleting one end removes the other automatically.

``` {.bash}
link delete v-host
100-Interface v-host deleted
```

### IOL Bridge module ("iol_bridge")

-   **iol_bridge create** *\<name\>* *\<id\>*

``` {.bash}
iol_bridge create IOL-BRIDGE-513 513
100-IOL bridge 'IOL-BRIDGE-513' created
```

-   **iol_bridge add_nio_udp** *\<name\>* *\<iol_id\>* *\<bay\>*
    *\<unit\>* *\<lport\>* *\<rhost\>* *\<rport\>*
-   **iol_bridge add_packet_filter** *\<name\>* *\<bay\>* *\<unit\>*
    *\<filter_name\>* *\<filter_type\>*
-   **iol_bridge reset_packet_filters** *\<name\>* *\<bay\>* *\<unit\>*
-   **iol_bridge start_capture** *\<name\>* \"*\<output_file\>*\"
    *\<data_link_type\>*
-   **iol_bridge delete** *\<name\>*

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
-   It is only possible to bridge two interfaces or tunnels together.
    uBridge is not a hub or a switch!
