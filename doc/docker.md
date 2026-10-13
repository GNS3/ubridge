# docker module — container plumbing

The `docker` hypervisor module creates and wires the veth plumbing for
container nodes. It is exposed via the hypervisor text protocol as
`docker <command> [args...]`.

All commands require `CAP_NET_ADMIN`; in practice ubridge is granted
capabilities on install (`sudo make install`, `cap_net_admin,cap_net_raw`).
Clients (gns3server) need neither privileges nor the `ip` command.

## Commands

### `docker create_veth <interface_name_1> <interface_name_2>`

Create a veth pair. The **host end** (`interface_name_1`) is brought UP,
hardened L2-only (`link l2only on`) and given the jumbo-safe default MTU
(65521); TX checksum offload is turned off on the guest end
(`interface_name_2`) so the container's own checksums are used as-is.

``` {.bash}
docker create_veth hostif guestif
100-veth pair created: hostif and guestif
```

### `docker move_to_ns <interface> <namespace_id> <dst_interface>`

Move an Ethernet interface into the network namespace of process
`<namespace_id>` and rename it to `<dst_interface>` (`RTM_NEWLINK` +
`IFLA_NET_NS_PID`).

``` {.bash}
docker move_to_ns guestif 6367 eth0
100-guestif moved to namespace 6367
```

### `docker set_mac_addr <interface> <mac_addr>`

Set a MAC address on an interface (`SIOCSIFHWADDR`); the address is
validated before the ioctl.

``` {.bash}
docker set_mac_addr tap-gns3-e0 12:34:56:78:12:42
100-MAC address 12:34:56:78:12:42 has been successfully set on interface tap-gns3-e0
```

### `docker delete_veth <interface_name>`

Delete a veth interface (`RTM_DELLINK`). Deleting one end of a pair removes
the other automatically (kernel behaviour).

``` {.bash}
docker delete_veth hostif
100-veth interface hostif has been deleted
```

## Testing

`tests/docker/` covers veth creation/deletion, namespace moves and MAC
assignment; `CAP_NET_ADMIN` required — run under sudo or `unshare -Urn`.

```bash
cd tests/docker && sudo python3 run_all.py
```
