# vxlan module — kernel VXLAN device management

The `vxlan` hypervisor module manages kernel VXLAN devices entirely through
rtnetlink (no ioctl, no fork+exec of iproute2). It is exposed via the
hypervisor text protocol as `vxlan <command> [args...]`.

A vxlan netdev is the kernel's own encapsulation endpoint: once created, the
dataplane needs nothing further from this module — collect frames with
`bridge add_nio_linux_raw <bridge> <vxlan>` (AF_PACKET on the device), or
enslave the device as a bridge port with `brctl addif` (a vxlan device is an
L2 netdev and bridges like any port). The module owns only the device
lifecycle: create / delete / show.

> **Note:** bringing the device up/down lives in the [`link`](link.md)
> module (`link set <name> up`), as with any interface. A freshly created
> vxlan device is DOWN.

## Transport

Commands are sent over the hypervisor control channel as newline-terminated
text, tokenized by whitespace. The first token is the module (`vxlan`), the
second is the command, the rest are arguments. Argument counts are enforced
by `min_param`/`max_param` in the command table.

Replies are one line, formatted `NNN-<message>`:

| Code | Meaning |
|---|---|
| `100` | ok |
| `204` | invalid parameter (bad VNI/port/address, unknown key, `remote=`+`group=` together, `group=` without `dev=`) |
| `206` | unable to create / device does not exist (show) / kernel refused create |
| `207` | unable to delete (device missing) |
| `212` | `show` on a device that is not a vxlan |

Error replies carry `strerror(errno)` from the netlink exchange; the errno
itself is the contract, the wording is not.

## Commands

### `vxlan create <name> <vni> [key=value ...]`

Creates a DOWN vxlan device. `<vni>` is the 24-bit VXLAN Network Identifier,
1–16777215 (0 is reserved). A duplicate name fails with `206` / `-EEXIST`
(same contract as `brctl create`).

| Key | Value | Kernel attribute | Default |
|---|---|---|---|
| `remote=<ip>` | unicast IPv4/IPv6 tunnel endpoint | `IFLA_VXLAN_GROUP`/`GROUP6` | none |
| `group=<mcast>` | multicast group (requires `dev=`) | same attributes | none |
| `dev=<ifname>` | underlying device (by ifindex) | `IFLA_VXLAN_LINK` | none |
| `dstport=<1-65535>` | UDP destination port | `IFLA_VXLAN_PORT` | **8472** |
| `ttl=<0-255>` | outer TTL (0 = auto) | `IFLA_VXLAN_TTL` | auto |
| `learning=<on\|off>` | source-MAC learning | `IFLA_VXLAN_LEARNING` | on |

Notes:

- **`remote=` and `group=` are mutually exclusive** and must be a unicast /
  multicast address respectively — the kernel packs both into the same
  attribute and decides the mode from the address class, so the module
  enforces the distinction at parse time rather than surfacing kernel
  confusion.
- **`group=` requires `dev=`**: the IGMP join needs a link to ride on. The
  kernel (and iproute2) enforce the same.
- **dstport defaults to the kernel's 8472**, the pre-IANA legacy value —
  NOT the IANA-assigned 4789. Two ends configured with defaults therefore
  agree with each other but not with most other implementations; pass
  `dstport=4789` when interop matters.
- With neither `remote=` nor `group=` the device runs in learning mode with
  the FDB as the source of truth (manageable through the kernel's vxlan FDB
  netlink surface, outside this module).

### `vxlan delete <name>`

Deletes the device (`RTM_DELLINK`). Unlike `brctl delete` there is no
in-use refusal: a vxlan endpoint is not shared state. If the device is
currently a bridge port the kernel detaches it on unregister; the tunnel
going away is the point of the command. Missing name → `207` / `-ENODEV`.

### `vxlan show <name>`

One line describing the device:

```
vx0 vni 42 remote 127.0.0.1 dev lo dstport 14789 ttl 64 learning on
vx1 vni 7 dstport 8472 ttl auto learning off
```

Fields follow the `create` keys; `ttl auto` means inherit-from-inner-packet.
`UP`/`RUNNING` flags are appended when set. `206` if the device does not
exist, `212` if it exists but is not a vxlan.

## Ownership and cleanup

A vxlan device is kernel state that outlives the ubridge process, exactly
like a `brctl` bridge: ubridge creates and deletes on command and holds no
inventory. Orchestration (reconcile-on-start, cleanup of leftovers after a
crash) belongs to the caller, per the bridge contract in
[gns3server-integration.md](gns3server-integration.md).

## Examples

```
vxlan create vx0 42 remote=192.0.2.10 dstport=4789 dev=eth0
link set vx0 up
brctl create fabric
brctl addif fabric vx0
...
vxlan delete vx0        # kernel detaches the port from `fabric` itself
```
