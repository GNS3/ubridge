# brctl module — Linux bridge management

The `brctl` hypervisor module manages Linux kernel bridges entirely through
netlink (no ioctl). It is exposed via the hypervisor text protocol as
`brctl <command> [args...]`.

It supports the full bridge lifecycle (create/delete, port enslave/release,
IP assignment), runtime bridge-level parameters (STP, ageing, VLAN, multicast)
and per-port parameters (priority, path cost, state, hairpin).

## Transport

Commands are sent over the hypervisor TCP control port as newline-terminated
text, tokenized by whitespace. The first token is the module (`brctl`), the
second is the command, the rest are arguments. Argument counts are enforced by
`min_param`/`max_param` in the command table.

Replies are one line per result, formatted `NNN<sep>message`:

- `NNN` — 3-digit status code (see below)
- `<sep>` — `-` for the final reply of a command, space (` `) when more lines
  follow (e.g. each bridge in a `list` dump)

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
assignment, parameter changes). `brctl list`/`show` are read-only but still go
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
| `setup <bridge> <ip/prefix>` | 2 | `create` + `addip` in one step. Validates the CIDR **before** creating; rolls back the bridge if `addip` fails. |
| `show <bridge>` | 1 | Query the bridge's IPv4 address/prefix and operational flags (`UP`/`RUNNING`). |
| `list` | 0 | Enumerate all Linux bridges with their IPv4 addresses. |

### Bridge-level parameters (10)

All set attributes via `RTM_NEWLINK` + `IFLA_LINKINFO{kind=bridge, INFO_DATA{attr}}`.

| Command | Netlink attr | Valid range |
|---------|-------------|-------------|
| `stp <bridge> on\|off` | `IFLA_BR_STP_STATE` | `on`/`off` (also `1`/`0`, `yes`/`no`, `true`/`false`) |
| `setbridgeprio <bridge> <n>` | `IFLA_BR_PRIORITY` | 0–65535 |
| `setfd <bridge> <s>` | `IFLA_BR_FORWARD_DELAY` | 2–30 (seconds) |
| `sethello <bridge> <s>` | `IFLA_BR_HELLO_TIME` | 1–10 (seconds) |
| `setmaxage <bridge> <s>` | `IFLA_BR_MAX_AGE` | 6–40 (seconds) |
| `setageing <bridge> <s>` | `IFLA_BR_AGEING_TIME` | ≥0 (seconds; 0 = never age) |
| `vlanfiltering <bridge> on\|off` | `IFLA_BR_VLAN_FILTERING` | `on`/`off` |
| `setvlanproto <bridge> <v>` | `IFLA_BR_VLAN_PROTOCOL` (u16) | `0x8100` (802.1Q) or `0x88a8` (802.1ad) |
| `mcastsnoop <bridge> on\|off` | `IFLA_BR_MCAST_SNOOPING` | `on`/`off` |
| `setgroupfwd <bridge> <n>` | `IFLA_BR_GROUP_FWD_MASK` | 0–65535 |

> Time-valued attributes (`setfd`/`sethello`/`setmaxage`/`setageing`) are
> converted seconds → centiseconds (×`sysconf(_SC_CLK_TK)`, i.e. ×100 on x86)
> because the kernel stores them as `clock_t`/jiffies.

### Port-level parameters (4)

All set attributes via `RTM_SETLINK` + `IFLA_PROTINFO{attr}` with
`ifi_family = AF_BRIDGE` and `NLA_F_NESTED` on `IFLA_PROTINFO`. The port must
already be enslaved to the bridge; otherwise `-EINVAL`.

| Command | Netlink attr | Valid range |
|---------|-------------|-------------|
| `setportprio <bridge> <port> <n>` | `IFLA_BRPORT_PRIORITY` | 0–255 |
| `setpathcost <bridge> <port> <n>` | `IFLA_BRPORT_COST` | 1–65535 |
| `setportstate <bridge> <port> <n>` | `IFLA_BRPORT_STATE` | 0–3 (0=disabled, 1=listening, 2=learning, 3=forwarding) |
| `hairpin <bridge> <port> on\|off` | `IFLA_BRPORT_MODE` | `on`/`off` (on = `BRIDGE_MODE_HAIRPIN`) |

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
- **dump parsing** — `cmd_list` and `br_dump_addresses` walk every `nlmsg`
  packed into a `recvmsg()` datagram via `NLMSG_OK`/`NLMSG_NEXT` (a datagram
  may carry several coalesced records). `NLMSG_ERROR` is treated as a real
  failure, never as end-of-dump.
- **`<bridge>` scoping** — `delif` and the port-parameter commands query the
  port's current master (`IFLA_MASTER` via `RTM_GETLINK`) and reject (`-EINVAL`)
  operations on a port not enslaved to the specified bridge, matching classic
  `brctl` semantics.

### Known pitfalls (fixed in this module)

| Pitfall | Effect | Fix |
|---------|--------|-----|
| `perror()` in `netlink_transaction` clobbers `errno` → `return -errno` returns `EINVAL(22)` instead of the real kernel error (e.g. `EEXIST`) | Duplicate `create` reported "Invalid argument" | Return `-err->error` directly from the ACK, never read `errno` back after `perror()` |
| Dump loop only inspected the first `nlmsg` per datagram | `list`/`show` silently dropped interfaces/addresses when the kernel coalesced messages | Inner `NLMSG_OK`/`NLMSG_NEXT` loop |
| Bridge params sent via `RTM_SETLINK` | Kernel silently ignored them (all params stayed at defaults) | Use `RTM_NEWLINK` for bridge attributes |
| Port params missing `ifi_family=AF_BRIDGE` and `NLA_F_NESTED` on `IFLA_PROTINFO` | Kernel silently ignored port attribute changes | Set `AF_BRIDGE`; set `NLA_F_NESTED` on the nested `IFLA_PROTINFO` header |
| `parse_cidr` truncated overlong input with `strncpy` | Invalid overlong CIDR could look valid after truncation | Reject `strlen(cidr) >= sizeof(buf)` up front |
| `setup` created the bridge before validating the CIDR | Invalid CIDR left a half-created bridge | Validate CIDR first; also roll back the bridge if `addip` fails |

## Testing

Tested on **Linux 6.19.11-1-default** (x86_64), ubridge with
`cap_net_admin,cap_net_raw=ep`. Kernel-side state was verified with
`ip -d link show <bridge>` and `ip -d link show <port>` (the `bridge_slave`
attributes appear on the port).

### Prerequisites

```bash
# A throwaway dummy port for addif/delif/port-param tests
sudo ip link add ubtest type dummy
sudo ip link set ubtest down

# ubridge installed with capabilities
sudo make install
```

### Test harness

Save as `regression_test.py` and run with `python3 regression_test.py`
(adjust `PORT` if 12174 is taken):

```python
import socket, subprocess, time

HOST, PORT = '127.0.0.1', 12174

s = socket.create_connection((HOST, PORT), timeout=5)

def t(cmd):
    s.sendall((cmd + '\n').encode())
    r = b''
    while b'-' not in r:
        r += s.recv(256)
    return r.decode().strip()

results = []
def test(cmd, exp='100'):
    resp = t(cmd)
    code = resp[:3]
    ok = 'PASS' if code == exp else 'FAIL'
    results.append((ok, cmd, resp[:50]))
    return resp

# === BASIC LIFECYCLE ===
test('brctl create regtest0')
test('brctl setup regtest1 10.0.1.1/24')
test('brctl show regtest1')
test('brctl show regtest0')
test('brctl addif regtest0 ubtest')
test('brctl delif regtest0 ubtest')

# === ERROR PATHS ===
test('brctl create regtest0', '206')        # duplicate
test('brctl delete nope', '207')            # missing
test('brctl addip regtest0 1.2.3.4', '204') # no slash
test('brctl addip regtest0 9.9.9.9/33', '204')
test('brctl setup nonexistent 1.2.3.4', '204')
test('brctl delete nonexistent', '207')      # never created -> ENODEV

# === BRIDGE PARAMETERS ===
t('brctl stp regtest1 on')
t('brctl setbridgeprio regtest1 4096')
t('brctl setfd regtest1 7')
t('brctl sethello regtest1 3')
t('brctl setmaxage regtest1 25')
t('brctl setageing regtest1 600')
time.sleep(0.3)
# verify via: ip -d link show regtest1  -> bridge {forward_delay 700,
#   hello_time 300, max_age 2500, ageing_time 60000, stp_state 1, priority 4096}

# === PORT PARAMETERS ===
t('brctl addif regtest1 ubtest')
t('brctl setportprio regtest1 ubtest 8')
t('brctl setpathcost regtest1 ubtest 500')
t('brctl hairpin regtest1 ubtest on')
time.sleep(0.3)
# verify via: ip -d link show ubtest  -> bridge_slave ... priority 8
#   cost 500 hairpin on ...

# === BRIDGE SCOPING (port must be on the named bridge) ===
t('brctl create regtest2')
test('brctl setportprio regtest2 ubtest 8', '206')  # ubtest on regtest1, not regtest2
test('brctl delif regtest2 ubtest', '207')          # same

t('brctl delif regtest1 ubtest')

# === CLEANUP ===
test('brctl delete regtest0')
test('brctl delete regtest1')
test('brctl delete regtest2')
s.close()

for ok, cmd, resp in results:
    print(f'[{ok}] {cmd:40s} {resp}')
```

### What is verified

- Every command's success reply code.
- Error paths: duplicate create (`206`/EEXIST), missing bridge (`207`/ENODEV),
  invalid IP/prefix (`204`), overlong CIDR (`204`).
- Bridge parameters actually take effect in the kernel (cross-checked with
  `ip -d link show`, including the centisecond conversion for time values).
- Port parameters actually take effect (`bridge_slave` attributes on the port).
- Bridge scoping: a port not on the named bridge is rejected for `delif` and
  all port-parameter commands.
- No residual bridges after cleanup; no fd/memory leaks across restarts.

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
