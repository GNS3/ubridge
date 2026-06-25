# link module — generic interface management

The `link` hypervisor module manages generic network interfaces (veth pairs,
IP assignment, link state) entirely through netlink — no `ip` command, no
ioctl. It is exposed via the hypervisor text protocol as
`link <command> [args...]`.

It exists alongside `brctl` (bridge-specific) to avoid confusing bridge
operations with generic interface operations. `brctl` does **not** create
veth pairs or set IPs on arbitrary interfaces — that's `link`'s job.

## Transport

Same text protocol as the other modules: newline-terminated commands, first
token is the module (`link`), second is the command, rest are arguments.
Replies are `NNN-...` (final) or `NNN ...` (intermediate).

## Privileges

All commands require `CAP_NET_ADMIN`. In practice ubridge is granted
capabilities on install:

```bash
sudo make install       # sets cap_net_admin,cap_net_raw=ep on the binary
getcap $(which ubridge) # verify
```

The whole point of the module is that **clients don't need privileges or
the `ip` command** — they talk to ubridge over TCP, and ubridge does the
netlink work with its own capabilities.

## Commands

### `link veth <name> <peer>`

Create a veth pair. Both ends start **DOWN**; use `brctl addif` to attach one
end to a bridge and `link set ... up` to bring it up.

| Arg | Description |
|-----|-------------|
| `<name>` | Name of one end of the pair (≤ 15 chars, `IFNAMSIZ`) |
| `<peer>` | Name of the other end (≤ 15 chars) |

Implementation: `RTM_NEWLINK` + `IFLA_INFO_KIND="veth"` with nested
`VETH_INFO_PEER` (a zeroed `struct ifinfomsg` followed by the peer's
`IFLA_IFNAME`).

```
link veth v-host v-ns
100-Veth pair v-host/v-ns created
```

Duplicate names → `206/EEXIST`. Name too long → `204/EINVAL`.

### `link addr <iface> <ip/prefix>`

Assign an IPv4 address to an interface and bring it UP. The CIDR must
include a `/` and a prefix ≤ 32 (e.g. `172.20.0.10/24`).

Implementation: `RTM_NEWADDR` (`NLM_F_CREATE|REPLACE`) followed by
`RTM_SETLINK` + `IFF_UP`. This is the generalized form of `brctl addip`
— it works on **any** interface (veth, bridge, dummy, tap), not just
bridges.

```
link addr v-host 172.20.0.10/24
100-IP 172.20.0.10/24 set on v-host
```

Bad CIDR → `204/EINVAL`. Missing interface → `206/ENODEV`.

### `link set <iface> up|down`

Bring an interface UP or DOWN (administrative state).

Implementation: `RTM_SETLINK` + `IFF_UP` (set in `ifi_flags` with
`ifi_change |= IFF_UP`).

```
link set v-host up
100-Interface v-host up
link set v-host down
100-Interface v-host down
```

Invalid state (not `up`/`down`) → `204/EINVAL`. Missing interface →
`206/ENODEV`.

## Status codes

| Code | Meaning |
|------|---------|
| `100` | OK |
| `204` | Invalid parameter value |
| `206` | Unable to create object |

## Typical workflow

The canonical GNS3 use case — host reaches a node inside a per-project
bridge via a veth pair:

```
host (172.20.0.10) ──veth──▶ bridge (no IP) ──▶ tap (QEMU node, 172.20.0.130)
```

```
brctl create projA-br
link veth v-host v-ns
brctl addif projA-br v-ns
link addr v-host 172.20.0.10/24      # host side gets IP + UP
link set v-ns up                     # bridge side up
# QEMU node's tap is created by the emulator and added with brctl addif
```

No `ip` command, no root — ubridge does it all via netlink.

## Implementation notes

- **netlink library** — `src/netlink/nl.c`. Helpers: `nlmsg_alloc`,
  `nlmsg_data`, `netlink_open/transaction/close`, `nla_put_string/u32`,
  `nla_begin_nested`/`nla_end_nested`.
- **Shared helpers** — `parse_cidr()` and `br_set_address()` are defined in
  `hypervisor_brctl.c` and exported via `hypervisor_brctl.h`, so both
  `brctl` (bridge IPs) and `link` (generic IPs) share one implementation.
- **Error handling** — all helpers return a **negative errno** (not `-1`);
  command handlers report `strerror(-err)`.
- **VETH_INFO_PEER nesting** — the trickiest part. The peer info is a
  **nested attribute whose payload is a raw `struct ifinfomsg` (no NLA
  header) followed by NLA-formatted attributes**. The `struct ifinfomsg`
  is written directly via `NLMSG_TAIL` rather than `nla_put_*`.

## Testing

Smoke-tested on **Linux 6.19.11-1-default** (x86_64), ubridge with
`cap_net_admin,cap_net_raw=ep`. Kernel-side state verified with
`ip -o link show` / `ip -o addr show` after each command.
```
