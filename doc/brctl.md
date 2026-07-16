# brctl module — Linux bridge management

The `brctl` hypervisor module manages Linux kernel bridges entirely through
netlink (no ioctl). It is exposed via the hypervisor text protocol as
`brctl <command> [args...]`.

It supports the full bridge lifecycle (create/delete, port enslave/release,
IP assignment), runtime bridge-level parameters (STP, ageing, VLAN, multicast),
per-port parameters (priority, path cost, state, hairpin) and per-port VLAN
membership (the primitives for access/trunk/QinQ port modes).

> **Note:** veth pair creation, IP assignment on arbitrary interfaces, and
> link state control live in the separate [`link`](link.md) module
> (`link veth`, `link addr`, `link set`). `brctl` is bridge-specific.

## Transport

Commands are sent over the hypervisor TCP control port as newline-terminated
text, tokenized by whitespace. The first token is the module (`brctl`), the
second is the command, the rest are arguments. Argument counts are enforced by
`min_param`/`max_param` in the command table.

Replies are one line per result, formatted `NNN<sep>message`:

- `NNN` — 3-digit status code (see below)
- `<sep>` — `-` for the final reply of a command

### Status codes

| Code | Meaning |
|------|---------|
| `100` | OK / informational |
| `203` | Bad number of parameters |
| `204` | Invalid parameter value |
| `206` | Unable to create object |
| `207` | Unable to delete object |

## Privileges

All commands require `CAP_NET_ADMIN` (bridge create/delete, address
assignment, parameter changes). `brctl show` is read-only but still go
through netlink. In practice the ubridge binary is granted capabilities:

```bash
sudo make install       # sets cap_net_admin,cap_net_raw=ep on the binary
getcap $(which ubridge) # verify
```

## Commands

### Basic lifecycle

| Command | Args | Description |
|---------|------|-------------|
| `create <bridge>` | 1 | Create a Linux bridge (`RTM_NEWLINK`, kind=bridge, `NLM_F_CREATE|EXCL`). Duplicate → `EEXIST`. |
| `delete <bridge>` | 1 | Delete a Linux bridge (`RTM_DELLINK`). Missing → `ENODEV`. |
| `addif <bridge> <port>` | 2 | Enslave a port to the bridge (`RTM_SETLINK` + `IFLA_MASTER`) **and bring the port UP**. Port must pre-exist. |
| `delif <bridge> <port>` | 2 | Release a port from a bridge. Verifies the port is actually on the given bridge; else `-EINVAL`. |
| `addip <bridge> <ip/prefix>` | 2 | Assign an IPv4 address (`RTM_NEWADDR`) and bring the bridge UP. CIDR must include a `/` and prefix ≤ 32. |
| `delip <bridge> <ip/prefix>` | 2 | Remove an IPv4 address from a bridge (`RTM_DELADDR`). Bad CIDR → `204`; missing bridge/IP → `207`. |
| `setup <bridge> <ip/prefix>` | 2 | `create` + `addip` in one step. Validates the CIDR **before** creating; rolls back the bridge if `addip` fails. |
| `show <bridge>` | 1 | Query the bridge's IPv4 address/prefix and operational flags (`UP`/`RUNNING`). |

### Bridge-level parameters (10)

All set attributes via `RTM_NEWLINK` + `IFLA_LINKINFO{kind=bridge, INFO_DATA{attr}}`.

| Command | Netlink attr | Valid range |
|---------|-------------|-------------|
| `stp <bridge> on\|off` | `IFLA_BR_STP_STATE` | `on`/`off` (also `1`/`0`, `yes`/`no`, `true`/`false`) |
| `setbridgeprio <bridge> <n>` | `IFLA_BR_PRIORITY` | 0–65535 |
| `setfd <bridge> <s>` | `IFLA_BR_FORWARD_DELAY` | 2–30 (seconds) |
| `sethello <bridge> <s>` | `IFLA_BR_HELLO_TIME` | 1–10 (seconds) |
| `setmaxage <bridge> <s>` | `IFLA_BR_MAX_AGE` | 6–40 (seconds) |
| `setageing <bridge> <s>` | `IFLA_BR_AGEING_TIME` | 0–1000000 (seconds; 0 = never age) |
| `vlanfiltering <bridge> on\|off` | `IFLA_BR_VLAN_FILTERING` | `on`/`off` |
| `setvlanproto <bridge> <v>` | `IFLA_BR_VLAN_PROTOCOL` (u16) | `0x8100` (802.1Q) or `0x88a8` (802.1ad) |
| `mcastsnoop <bridge> on\|off` | `IFLA_BR_MCAST_SNOOPING` | `on`/`off` |
| `setgroupfwd <bridge> <n>` | `IFLA_BR_GROUP_FWD_MASK` | 0–65535 |

> Time-valued attributes (`setfd`/`sethello`/`setmaxage`/`setageing`) are
> converted seconds → centiseconds (×`sysconf(_SC_CLK_TCK)`, i.e. ×100 on x86)
> because the kernel stores them as `clock_t`/jiffies.
>
> All `on|off` commands (`stp`, `vlanfiltering`, `mcastsnoop`, and the port-level
> `hairpin`/`isolated`) share one parser and accept `on`/`off`, `1`/`0`,
> `yes`/`no`, `true`/`false`.

### Port-level parameters (5)

All set attributes via `RTM_SETLINK` + `IFLA_PROTINFO{attr}` with
`ifi_family = AF_BRIDGE` and `NLA_F_NESTED` on `IFLA_PROTINFO`. The port must
already be enslaved to the bridge; otherwise `-EINVAL`.

| Command | Netlink attr | Valid range |
|---------|-------------|-------------|
| `setportprio <bridge> <port> <n>` | `IFLA_BRPORT_PRIORITY` | 0–63 (kernel; parse accepts 0–255, 64+ → 206) |
| `setpathcost <bridge> <port> <n>` | `IFLA_BRPORT_COST` | 1–65535 |
| `setportstate <bridge> <port> <n>` | `IFLA_BRPORT_STATE` | 0–3 (0=disabled, 1=listening, 2=learning, 3=forwarding) |
| `hairpin <bridge> <port> on\|off` | `IFLA_BRPORT_MODE` | `on`/`off` (on = `BRIDGE_MODE_HAIRPIN`) |
| `isolated <bridge> <port> on\|off` | `IFLA_BRPORT_ISOLATED` | `on`/`off` (on = port can only reach the CPU, not other ports) |

### VLAN membership (3)

Per-port VID add/delete — the building blocks for access/trunk/QinQ port modes.
VLANs ride in `IFLA_AF_SPEC` (the `AF_BRIDGE` sibling of `IFLA_PROTINFO`), as
iproute2 `bridge vlan add|del` sends them: `add` maps to the kernel's
`br_setlink`, `del` to `br_dellink`. The port must be enslaved to the bridge,
and the bridge must have `vlanfiltering on` (else the kernel rejects with
`-EINVAL`). No `IFLA_BRIDGE_FLAGS` is sent — an unset flags field routes the
op through the MASTER path (`br_setlink`), like iproute2 with no
`self`/`master`; sending `BRIDGE_FLAGS_SELF` would instead target the port's
own `ndo_bridge_setlink` and fail with `-EOPNOTSUPP` on plain (non-switchdev)
ports.

| Command | Args | Description |
|---------|------|-------------|
| `vlan_add <bridge> <port> <vid> [vid <end>] [pvid] [untagged]` | 3–7 | Add a VID (or `vid <end>` range). `pvid` = strip tag on ingress (sets the port PVID); `untagged` = strip on egress. A range is encoded as `RANGE_BEGIN`/`RANGE_END`. Re-adding a VID is idempotent (success; flags are updated if they differ). |
| `vlan_del <bridge> <port> <vid> [vid <end>]` | 3–5 | Delete a VID/range. Flags are rejected — deletion is by VID only. |
| `vlan_show <bridge> [port]` | 1–2 | List per-port VID membership (`RTM_GETLINK` AF_BRIDGE dump + `IFLA_EXT_MASK=RTEXT_FILTER_BRVLAN`). One line per (port, vid): `<port> <vid> [PVID] [Egress Untagged]`. |

VIDs are 1–4094 (4095 reserved); an out-of-range or reversed range → `204`.

ESW access/trunk modes are composed from these two primitives (in gns3-server,
not here): access VLAN *N* = `vlanfiltering on` → `vlan_del <port> 1` →
`vlan_add <br> <port> N pvid untagged`; a dot1q trunk's tagged list is a series
of `vlan_add` (ranges), with the native VLAN added `pvid untagged`.

## Implementation notes

- **netlink library** — `src/netlink/nl.c` (lxc-derived). Helpers used:
  `nlmsg_alloc`, `nlmsg_data`, `netlink_open/transaction/close`,
  `nla_put_string/u32/u16`, `nla_begin_nested`/`nla_end_nested`. The latter two
  support multi-level nesting (used for `IFLA_LINKINFO`/`IFLA_INFO_DATA`).
- **Error handling** — all `br_*` helpers return a **negative errno** on every
  error path (not `-1`); command handlers report `strerror(-err)`. This avoids
  relying on the volatile `errno`, which `perror()`/stdio can clobber
  (see "Known pitfalls" below).
- **Bridge vs port attribute transport** — bridge attributes go through
  `RTM_NEWLINK`; port attributes through `RTM_SETLINK` with `AF_BRIDGE`.
  Mixing them up makes the kernel silently ignore the change.
- **dump parsing** — `br_dump_addresses` walks every `nlmsg`
  packed into a `recvmsg()` datagram via `NLMSG_OK`/`NLMSG_NEXT` (a datagram
  may carry several coalesced records). `NLMSG_ERROR` and any `recv` error
  (e.g. `-EMSGSIZE` when a datagram overflows the receive buffer) are treated
  as a real failure, never as end-of-dump.
- **`<bridge>` scoping** — `delif` and the port-parameter commands query the
  port's current master (`IFLA_MASTER` via `RTM_GETLINK`) and reject (`-EINVAL`)
  operations on a port not enslaved to the specified bridge, matching classic
  `brctl` semantics.

### Known pitfalls (fixed in this module)

| Pitfall | Effect | Fix |
|---------|--------|-----|
| `perror()` in `netlink_transaction` clobbers `errno` → `return -errno` returns `EINVAL(22)` instead of the real kernel error (e.g. `EEXIST`) | Duplicate `create` reported "Invalid argument" | Return `-err->error` directly from the ACK, never read `errno` back after `perror()` |
| Dump loop only inspected the first `nlmsg` per datagram | `br_get_address` silently dropped addresses when the kernel coalesced messages | Inner `NLMSG_OK`/`NLMSG_NEXT` loop |
| Bridge params sent via `RTM_SETLINK` | Kernel silently ignored them (all params stayed at defaults) | Use `RTM_NEWLINK` for bridge attributes |
| Port params missing `ifi_family=AF_BRIDGE` and `NLA_F_NESTED` on `IFLA_PROTINFO` | Kernel silently ignored port attribute changes | Set `AF_BRIDGE`; set `NLA_F_NESTED` on the nested `IFLA_PROTINFO` header |
| `parse_cidr` truncated overlong input with `strncpy` | Invalid overlong CIDR could look valid after truncation | Reject `strlen(cidr) >= sizeof(buf)` up front |
| `setup` created the bridge before validating the CIDR | Invalid CIDR left a half-created bridge | Validate CIDR first; also roll back the bridge if `addip` fails |
| Dump `recv` error (e.g. `-EMSGSIZE` when a datagram overflows the buffer) treated as end-of-dump | `br_get_address` silently returned a truncated address list as complete → `show` printed a wrong/missing IP | Treat `netlink_rcv < 0` as failure (`ret = -1`); only `r == 0` / `NLMSG_DONE` ends the dump |
| `realloc` failure in `br_dump_addresses` jumped to the success path | Partial address list returned as a complete dump under memory pressure | `ret = -1; goto out` on realloc failure |
| `netlink_open` returned `-errno` without closing the socket after `setsockopt` / `bind` / `getsockname` failed | fd leak on (rare) open-time failure paths | `goto err` closes the fd and preserves the original errno |
| `br_set_port_attr` sent `IFLA_BRPORT_PRIORITY` as u8 | Kernel policy `NLA_U16` rejects the 1-byte attr with `-ERANGE` → `setportprio` always failed (masked by older kernels' lenient netlink parsing) | Send u16 via the dedicated `br_set_port_attr_u16` |

## Testing

Tested on **Linux 7.1.2-1-default** (x86_64), ubridge with
`cap_net_admin,cap_net_raw=ep`. Kernel-side state was verified with
`ip -d link show <bridge>` and `ip -d link show <port>` (the `bridge_slave`
attributes appear on the port).

### Prerequisites

```bash
# ubridge installed with capabilities
sudo make install

# A throwaway dummy port for addif/delif/port-param tests.
# Auto-created when suites run under sudo (ensure_ubtest in common.py);
# create it manually only if you run a suite without privileges:
sudo ip link add ubtest type dummy
```

### Test suites

A comprehensive test suite lives in `tests/brctl/` (stdlib only, no third-party
dependencies). Install prerequisites, then run:

```bash
cd tests/brctl

# single suite
python3 test_basic.py

# or all suites
python3 run_all.py
```

Eight suites (155 tests in total):

| Suite | Tests | Scope |
|-------|-------|-------|
| `test_basic` | 22 | Lifecycle, common errors, bridge scoping |
| `test_boundary` | 58 | Boundary values for all ranged parameters, kernel-side verification |
| `test_concurrency` | 6 | Multi-client create races, show under churn |
| `test_robustness` | 20 | Malformed input, overlong names, IPv6, crash-freedom |
| `test_state` | 12 | addif/addip idempotency, UP/DOWN transitions, ports on delete |
| `test_stress` | 5 | 400 create/delete cycles, fd stability, dump at scale (60 bridges) |
| `test_no_privs` | 4 | No-cap binary rejects mutations, survives gracefully |
| `test_vlan` | 28 | Per-port VLAN add/del/show/range, kernel-side verification, error paths |

All 155 tests pass on the reference kernel (7.1.2-1-default).

### Kernel verification reference

| Set via brctl | Read back from `ip -d link show` |
|---------------|----------------------------------|
| `stp on` | `stp_state 1` |
| `setbridgeprio 4096` | `priority 4096` |
| `setfd 7` | `forward_delay 700` |
| `sethello 3` | `hello_time 300` |
| `setmaxage 25` | `max_age 2500` |
| `setageing 600` | `ageing_time 60000` |
| `setportprio 8` | `priority 8` (on the port) |
| `setpathcost 500` | `cost 500` (on the port) |
| `hairpin on` | `hairpin on` (on the port) |
```

VLAN membership is verified with `bridge vlan show dev <port>` instead:

| Set via brctl | Read back from `bridge vlan show dev <port>` |
|---------------|----------------------------------------------|
| `vlan_add <br> <p> 100 pvid untagged` | `100 PVID Egress Untagged` |
| `vlan_add <br> <p> 200` | `200` |
| `vlan_add <br> <p> 300 vid 302` | `300`, `301`, `302` (per-VID lines; `300-302` only with `bridge -compressed vlan show`) |
| `vlan_del <br> <p> 200` | `200` row gone |
