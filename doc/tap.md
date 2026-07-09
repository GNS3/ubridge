# tap module — persistent TAP device lifecycle

The `tap` hypervisor module creates, owns, and destroys **persistent** TAP
devices via `/dev/net/tun` ioctls. It is exposed over the hypervisor text
protocol as `tap <command> [args...]`.

It exists to support the kernel-side data-plane model: frames flow between a
persistent TAP and a kernel bridge (managed by the [`brctl`](brctl.md) module)
entirely in the kernel, never through ubridge's user-space NIO relay. A
persistent TAP survives its creating fd being closed, so an unprivileged
emulator (QEMU) can open it later by name — provided ownership was handed over
with `set_owner`.

`tap` does **not** add TAPs to bridges (that's `brctl addif`) and does **not**
open a TAP as an NIO relay (that's the `bridge` module's `add_nio_tap`, which
opens a non-persistent TAP tied to a bridge). `tap` is purely lifecycle.

## Transport

Same text protocol as the other modules: newline-terminated commands, first
token is the module (`tap`), second is the command, rest are arguments.
Replies are `NNN-...` (final line).

## Privileges

All commands require `CAP_NET_ADMIN`. In practice ubridge is granted
capabilities on install:

```bash
sudo make install       # sets cap_net_admin,cap_net_raw=ep on the binary
getcap $(which ubridge) # verify
```

Clients (gns3server) need neither privileges nor `/dev/net/tun` access — they
talk to ubridge over TCP, and ubridge does the ioctl work with its own
capabilities.

## Commands

### `tap create <name>`

Create a persistent TAP device (`open /dev/net/tun` + `TUNSETIFF`
`IFF_TAP|IFF_NO_PI|IFF_TUN_EXCL` + `TUNSETPERSIST(1)`, then close). The device
starts **DOWN**; bring it up with `brctl addif` (which auto-UPs a port) or
`link set <name> up`.

| Arg | Description |
|-----|-------------|
| `<name>` | Device name, ≤ 15 chars (`IFNAMSIZ - 1`) |

```
tap create tap-gns3-e0
100-Persistent TAP tap-gns3-e0 created
```

Duplicate name → `206/EBUSY` (the `IFF_TUN_EXCL` flag rejects re-attaching to
an existing device). Name too long → `204`.

### `tap set_owner <name> <uid>`

Set the owner (uid) of a persistent TAP device. **Critical for the
unprivileged-QEMU case**: after this, the given uid can `open()` the device.
Implemented by re-attaching to the existing device (`TUNSETIFF`) then
`ioctl(TUNSETOWNER, uid)`.

| Arg | Description |
|-----|-------------|
| `<name>` | An existing persistent TAP device |
| `<uid>` | Numeric user ID (0–4294967295) |

```
tap set_owner tap-gns3-e0 1000
100-Owner 1000 set on TAP tap-gns3-e0
```

Non-numeric or out-of-range uid → `204`. Missing device → `206/ENODEV`.

### `tap delete <name>`

Delete a persistent TAP device (`TUNSETIFF` re-attach + `TUNSETPERSIST(0)`,
then close — the kernel destroys the device once the last fd is closed and
persistence is off).

```
tap delete tap-gns3-e0
100-TAP tap-gns3-e0 deleted
```

Missing device → `207/ENODEV`.

## Status codes

| Code | Meaning |
|------|---------|
| `100` | OK |
| `204` | Invalid parameter (name too long, bad uid) |
| `206` | Unable to create / set owner (`EEXIST`, `EBUSY`, `ENODEV`) |
| `207` | Unable to delete (`ENODEV`) |

## Typical workflow

The canonical GNS3 use case — a QEMU node opens a persistent TAP that is
already bridged:

```
tap create tap-node-e0                       # ubridge creates persistent TAP
tap set_owner tap-node-e0 <qemu-uid>         # hand it to the emulator's uid
brctl create proj-br                         # per-link kernel bridge
brctl addif proj-br tap-node-e0              # enslave TAP (+ auto UP)
# QEMU launches with: -netdev tap,ifname=tap-node-e0,script=no,...
```

No root, no `/dev/net/tun` access for the emulator beyond owning the device —
ubridge does the privileged setup via ioctls.

## Implementation notes

- **Stateless.** A persistent TAP survives its creating fd closing, so each
  command opens `/dev/net/tun`, re-attaches to the named device with
  `TUNSETIFF`, performs the ioctl, and closes the fd. ubridge holds no
  per-device fd or registry — same "one call, one transaction" style as
  `brctl`/`link`.
- **Re-attach semantics.** Calling `TUNSETIFF` with the name of an existing
  persistent TAP attaches to it (it does not create a new one). `create` adds
  `IFF_TUN_EXCL` so a duplicate create is rejected with `EBUSY` rather than
  silently re-attaching.
- **Error handling.** Helpers return a **negative errno** (not `-1`); command
  handlers report `strerror(-err)`.
- **`IFF_TUN_EXCL`** has been in `<linux/if_tun.h>` since 2.6.26; the module
  defines it locally as a fallback for very old headers.

## Testing

Smoke-tested on **Linux 6.x** (x86_64), ubridge with
`cap_net_admin,cap_net_raw=ep`. Kernel-side state verified with
`ip -o link show <name>` and `ip -o tuntap show` after each command.

```bash
sudo make install                 # install fresh binary with caps
cd tests/tap
sudo python3 test_basic.py        # single suite
sudo python3 run_all.py           # or all suites
```

The suite covers lifecycle (create/owner/delete), error paths (duplicate
create → 206, missing delete → 207, overlong name / bad uid → 204), and the
`brctl addif` integration that wires a persistent TAP into a kernel bridge.
```
