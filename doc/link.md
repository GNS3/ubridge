# link module — generic interface management

The `link` hypervisor module manages generic network interfaces (veth pairs,
IP assignment, link state, L2-only hardening) entirely through netlink — no
`ip` command, no ioctl. It is exposed via the hypervisor text protocol as
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

### `link delete <iface>`

Delete an interface. For a **veth pair**, deleting one end removes the
other automatically (kernel behaviour).

Implementation: `RTM_DELLINK`.

```
link delete v-host
100-Interface v-host deleted
```

Missing interface → `207/ENODEV`. Missing arg → `203`.

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

### `link l2only <iface> [on|off]`

Make an **existing** device pure L2: no IPv6 link-local address and no IPv6
stack activity on it. Default state is `on`.

| Arg | Description |
|-----|-------------|
| `<iface>` | An existing device. A missing name fails (`208/ENODEV`) and never creates a transient device. |
| `on` / `off` | `on` = suppress IPv6 address generation and stack activity; `off` = restore the kernel default. |

Why: a host-side anchor that is UP gets an IPv6 link-local address from the
kernel with no user-space actor involved, and with it MLD reports, DAD
neighbour solicitations and router solicitations. On an emulated link those
frames flood into the segment and the host **answers** ND for its own
link-local, so an emulated IPv6 router can form an adjacency with the host —
a phantom neighbour. The anchors gns3-server creates (`tap create`,
`docker create_veth` host end, `link veth` both ends, `brctl create`) apply
this themselves, before their success reply; gns3-server never issues
`link l2only` directly and a caller cannot forget it.

```
link l2only gq1234abcd
100-L2-only set on gq1234abcd
link l2only gq1234abcd on
100-L2-only set on gq1234abcd          # idempotent, same reply
link l2only gq1234abcd off
100-L2-only cleared on gq1234abcd
```

Implementation: `RTM_SETLINK` with `IFLA_AF_SPEC{ AF_INET6 {
IFLA_INET6_ADDR_GEN_MODE } }` (what `ip link set dev X addrgenmode none`
sends). The address the kernel already assigned is **not** removed by that —
it survives the mode change and even a down/up cycle (measured on 7.2) — so an
anchor that was brought UP before this call is cleaned up explicitly with
`RTM_DELADDR`. Both the mode and the absence of a link-local are read back
with `RTM_GETLINK` before `100` is sent, so a caller may treat `100` as
verified rather than requested.

`off` writes the kernel's built-in default back (`eui64`); the kernel
re-provisions the link-local on the next down/up cycle, not on the mode change
itself.

Without the attribute (old kernel) the creators log and continue — device
creation never fails because of this hardening — while an explicit
`link l2only` reports it. Never `/proc/sys/net/ipv6/conf/<if>/disable_ipv6`:
those files are root-owned mode 0644, so a setcap'd non-root ubridge can be
refused by the DAC check despite holding `CAP_NET_ADMIN`.

Bad state → `204/EINVAL`. Missing interface → `208/ENODEV`. Any other netlink
error → `206`.

What hardening does **not** remove: the device's own group-membership reports.
Group membership is not address generation, and one or two still go out at
bring-up — an MLDv2 report (dst `ff02::16`, source `::`, hop-by-hop Router
Alert) and, on a bridge, the IPv4 twin: an IGMP report (dst `224.0.0.22`,
source `0.0.0.0`) from the bridge's own MAC. Neither carries an address of the
device, so neither can make the host answer ND or ARP for one; the neighbour
discovery, DAD and router solicitations are what is gone.

On a bridge those two *are* multicast snooping: the kernel enables it by
default, and what it makes the bridge join is exactly those all-snoopers
groups. `brctl create` now turns it off, so a link bridge emits nothing at
all and the `bridge with two attached ports` role is held to literal silence
rather than to "no identity chatter". Turning it off is also the honest model
— a cable floods multicast, it does not prune to whoever last joined. `brctl
mcastsnoop <bridge> on` restores the reports along with the snooping.

Measured on 7.2 over the full `brctl create` → `link set up` → `addif` ×2 →
`delif` ×2 sequence: 5 frames with snooping on, repeating rather than the
one-shot burst §E.2 assumes (0.5 s to 1.7 s in), and 0 with it off. Measured
with `capture start_kernel` — see `tests/link/test_l2only.py`.

## Status codes

| Code | Meaning |
|------|---------|
| `100` | OK |
| `203` | Bad number of parameters |
| `204` | Invalid parameter value |
| `206` | Unable to create object |
| `207` | Unable to delete object |
| `208` | Unknown object (no such device) |

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
  The other direction: `link_set_l2only()` / `link_harden_l2only()` are
  defined here and exported via `hypervisor_link.h`, because the hardening
  belongs to this module while the creators that must apply it live in
  `tap`, `docker` and `brctl`.
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
