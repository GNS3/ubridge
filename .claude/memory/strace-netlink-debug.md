---
name: strace-netlink-debug
description: Use strace ip addr show to discover correct netlink parameters for any operation
metadata:
  type: reference
---

# strace + `ip` command to discover netlink parameters

When the correct netlink message format for a kernel operation is unknown or
the kernel rejects your request with `EOPNOTSUPP`, use `strace` to observe
what the `ip` tool (iproute2) actually sends over netlink.

## Workflow

1. Run the equivalent `ip` command under strace, filtering for netlink sendmsg/sendto:

   ```bash
   strace -e sendmsg,sendto,recvmsg -f ip addr show <ifname>
   ```

2. Read the `sendmsg`/`sendto` call for `RTM_*` messages to see the exact
   `nlmsg_type`, `nlmsg_flags`, and attribute payload the kernel expects.

3. Compare with your own netlink message construction and fix the differences.

## Concrete example: RTM_GETADDR

When implementing `br_get_address()` (query IPv4 address of an interface),
the kernel on Debian 12 (6.1) rejected `NLM_F_REQUEST` without `NLM_F_DUMP`
with `EOPNOTSUPP`.  Even with `NLM_F_DUMP` the dump returned only the first
address (loopback) before `NLMSG_DONE`.

**Fix discovered via strace:** `ip addr show Gns3Mg-26af378b` sends:

```
sendto(3, [
  {nlmsg_len=24, nlmsg_type=RTM_GETADDR,
   nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP, ...},
  {ifa_family=AF_UNSPEC, ifa_prefixlen=0, ifa_flags=0,
   ifa_scope=RT_SCOPE_UNIVERSE, ifa_index=701}
], ...)
```

Key differences from the incorrect implementation:

| Field | `ip` tool | Initial code | Fix |
|---|---|---|---|
| `ifa_family` | `AF_UNSPEC` | `AF_INET` | `AF_UNSPEC` |
| `ifa_index` | 701 (set!) | 0 (not set) | `if_nametoindex(name)` |

**Why:** Without `ifa_index` in the request, the kernel returns ALL addresses
across all interfaces in the dump.  The first response (usually `127.0.0.1/8`
on lo) was read, and the dump ended before reaching the target interface.
Setting `ifa_index` filters the dump to a single interface.

## Applicable to any RTM_* operation

This technique works for any netlink operation:
- `ip link show` → `RTM_GETLINK` parameters
- `ip addr add` → `RTM_NEWADDR` parameters
- `ip link set` → `RTM_SETLINK` parameters
- `bridge link set` → `RTM_SETLINK` + `IFLA_MASTER`

The `ip` tool is the reference implementation.  When in doubt, strace it.
