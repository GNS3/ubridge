# iol_bridge module — IOU/IOL instance ports

The `iol_bridge` module terminates the ports of an IOU (IOL) instance. An IOU
instance has no host netdev: its only wire is the Unix-datagram fabric in
`/tmp/netio<uid>/`, where a frame carries an 8-byte IOL header and the NETMAP
file maps every `bay/unit` of the instance to a second, fake instance — which
is uBridge itself, bound at the instance id the server passes to
`iol_bridge create`. Each port of that fake instance ends on a **destination
NIO**, and there are two kinds: a UDP tunnel (`add_nio_udp`) or a persistent
TAP (`add_nio_tap`).

It is exposed via the hypervisor text protocol as `iol_bridge <command>
[args...]`, and it pairs with the generic modules: `brctl` for the bridges,
`link` for interfaces, `tc`/`capture`/`marker` for everything `*_kernel`.

## Transport

Same text protocol as the other modules: newline-terminated commands, first
token is the module (`iol_bridge`), second is the command, rest are
arguments. Replies are `NNN-...` (final) or `NNN ...` (intermediate).

## The fabric

```
/tmp/netio<uid>/<id>          AF_UNIX datagram, one socket per instance id
```

| Byte | Field |
|------|-------|
| 0–1 | destination instance id |
| 2–3 | source instance id |
| 4 | destination port (`bay + unit * 16`) |
| 5 | source port |
| 6 | message type (0 = free, 1 = data) |
| 7 | channel |

A port is addressed as `port_key = bay + unit * 16` in a `unsigned char`, so
bay and unit are 0–15 and the ceiling is 255 (`MAX_PORTS` is 256; the
`port_key > MAX_PORTS` guard can therefore never fire). A bridge cannot serve
an instance whose id equals its own application id (the fabric would be
talking to itself) — that is refused with `206`.

## Privileges

`add_nio_udp`, the control commands and the capture/filter commands need no
capability. `add_nio_tap` opens `/dev/net/tun` and therefore needs
`CAP_NET_ADMIN`, which ubridge is granted on install
(`cap_net_admin,cap_net_raw=ep`).

## Commands

### `iol_bridge create <name> <application_id>` · `delete <name>`

`create` binds `/tmp/netio<uid>/<application_id>` (creating the directory if
needed — mode 0700) and takes a lock on that path: an id already locked by
another pid is refused (`206`). `delete` stops the bridge if it is running,
releases every port (see *Implementation notes*), closes the fabric socket
and unlinks it.

```
iol_bridge create IOL-BRIDGE-513 513
100-IOL bridge 'IOL-BRIDGE-513' created
iol_bridge delete IOL-BRIDGE-513
100-IOL bridge 'IOL-BRIDGE-513' deleted
```

Duplicate name or a locked id → `206`. Missing bridge → `214`.

### `iol_bridge start <name>` · `stop <name>` · `rename <old> <new>`

`start` creates the fabric listener and one listener per port that already
holds a NIO; `stop` cancels and joins them but **keeps** the NIOs, so
`start` resumes with the same ports. Already running → `209`, not running →
`210`, missing → `214`; `rename` to a name in use → `213`.

### `iol_bridge add_nio_udp <bridge> <iol_id> <bay> <unit> <lport> <rhost> <rport>`

Terminates the port on a connected UDP tunnel: frames read from the fabric
are sent to `<rhost>:<rport>`, and datagrams received on `<lport>` are
prepended with the port's IOL header and sent into the fabric. `206` when the
socket cannot be created, `214` for a missing bridge.

### `iol_bridge delete_nio_udp <bridge> <bay> <unit>`

Stops the port's listener and releases the NIO (closing the socket). Deleting
a port that holds no NIO is also `100`.

### `iol_bridge add_nio_tap <bridge> <iol_id> <bay> <unit> <tap_name>` (5 args)

Terminate the port on a **pre-existing persistent TAP** — an *anchor* — that
the server created with `tap create` (hardened per the L2-only rules). uBridge
opens it by name and plays, on that TAP, the role the QEMU process plays on
its own TAP; everything that is keyed on the interface name works on the
anchor regardless of who holds the fd: `brctl addif` enslavement, `tc`,
`capture start_kernel`, `marker add_kernel`, and `link set up|down` for
carrier and suspend.

| Arg | Description |
|-----|-------------|
| `<bridge>` | An existing IOL bridge (`208` if not) |
| `<iol_id>` | The real instance's id, encoded into the IOL header as with `add_nio_udp`; must differ from the bridge's own id (`206`) |
| `<bay>` `<unit>` | Port coordinates, same encoding as `add_nio_udp` |
| `<tap_name>` | An existing device (`208` if not); at most `IFNAMSIZ-1` = 15 chars (`204` otherwise) |

```
iol_bridge add_nio_tap IOL-BRIDGE-513 1 0 0 gi0badfe9e0p0
100-NIO TAP added to IOL bridge 'IOL-BRIDGE-513'
iol_bridge delete_nio_tap IOL-BRIDGE-513 0 0
100-NIO TAP deleted from IOL bridge 'IOL-BRIDGE-513'
```

The device must already exist, and that check is not politeness: `TUNSETIFF`
on an absent name silently **creates** a transient TAP that dies with the fd,
and an anchor that vanishes on detach is worse than a clear error (the same
reasoning as the `tap` module's own existence check). A port may swap
`add_nio_udp` ↔ `add_nio_tap` repeatedly — that is the datapath-switch path.

There is no carrier argument: administrative state is the server's lever,
through `link set <tap> up|down`.

### `iol_bridge delete_nio_tap <bridge> <bay> <unit>`

Same body as `delete_nio_udp`, except that **the persistent device survives**
— the server deletes it with `tap delete` when the node stops, exactly as it
does for QEMU anchors. Deleting a port that holds no NIO is a no-op `100`.

### The anchor can be administratively DOWN

A TAP anchor is expected to sit admin-DOWN for long periods: a port anchored
with no link attached yet, or a suspended link. The listeners treat that as
normal, not as an error:

- **fabric → anchor**: a write to a DOWN TAP fails with `EIO`. The frame is
  dropped (with a `perror` line) and the listener continues. Without this the
  first frame on a suspended link would take the whole daemon down.
- **anchor → fabric**: a read returns `EIO`, and a return of `0` carries no
  frame — it is skipped. Counting or forwarding a zero-length read would
  fabricate header-only packets for the instance.

`ECONNREFUSED`, `ENETDOWN` and `EINVAL` were already tolerated on these paths
for the UDP case and stay that way. The fabric-side `sendto` keeps tolerating
`ENOENT` for the window before the IOU process has created its endpoint.

### `iol_bridge get_stats <name>` · `reset_stats <name>` · `list`

`get_stats` prints one intermediate line per port that holds a NIO, then
`100-OK`:

```
101-port 0/0:      IN: 12 packets (1440 bytes) OUT: 9 packets (1080 bytes)
100-OK
```

`list` prints `101-<name> (ports = N)` per bridge, then `100-OK`.

### Capture and filters

`start_capture <bridge> <bay> <unit> <file> [linktype]` /
`stop_capture <bridge> <bay> <unit>` (see `doc/capture.md`) and
`add_packet_filter` / `delete_packet_filter` / `enable_packet_filter` /
`reset_packet_filters` (see `doc/packet_filter.md`) work unchanged on a
TAP-terminated port. On a kernel link the server uses the anchor's `tc` path
instead; the two are never applied to the same port at once.

## Status codes

| Code | Meaning |
|------|---------|
| `100` | OK |
| `203` | Bad number of parameters |
| `204` | Invalid parameter value (e.g. TAP name longer than 15 chars) |
| `206` | Unable to create object (locked id, bad `iol_id`, TAP fd cannot be opened) |
| `208` | Unknown object — bridge or TAP device does not exist (`*_tap` commands) |
| `209` | Unable to start (already running) |
| `210` | Unable to stop (not running) |
| `213` | Unable to rename (name in use) |
| `214` | Not found (missing bridge, `port_key` out of range) |

Note the deliberate asymmetry: the `*_tap` commands answer `208` for an
unknown bridge, the older `*_udp` ones answer `214`. The existing commands
are frozen — gns3-server already handles both.

## Typical workflow

The deployment shape the anchor exists for — an IOU port joining a per-link
kernel bridge, so the link itself is the kernel:

```
IOU node ──fabric──▶ iol_bridge port ──▶ tap anchor ──▶ kernel bridge ──▶ peer
                                                          (tc, markers,
                                                           start_kernel capture)
```

```
tap create gi0badfe9e0p0             # server: persistent, hardened anchor
iol_bridge create IOL-BRIDGE-513 513
iol_bridge add_nio_tap IOL-BRIDGE-513 1 0 0 gi0badfe9e0p0
iol_bridge start IOL-BRIDGE-513
brctl create projA-iol
link set projA-iol up
brctl addif projA-iol gi0badfe9e0p0  # the anchor joins the bridge
```

The older datapath keeps `add_nio_udp`: one userspace relay hop is
irreducible on the IOU leg either way, since the fabric is IOU's only
physical layer — what the anchor buys is that the link *segment* is the
kernel, not that the relay disappears.

## Implementation notes

- **Two listeners per bridge.** `iol_bridge_listener` reads the fabric and
  forwards each frame to the destination port's NIO; one `iol_nio_listener`
  per port reads that NIO and sends into the fabric. Both look up the port by
  `pkt[IOL_DST_PORT]`; the per-port IOL header is precomputed at attach time,
  so a port can be re-pointed at any time.
- **One teardown path.** `iol_port_release()` stops the port's listener,
  destroys both delay lines under `iol_delay_lock`, frees capture, filters
  and the NIO. It is used by `create_iol_port_entry` (when re-pointing a
  port), `delete_nio_udp`, `delete_nio_tap` and `cmd_delete_bridge`. The
  delete-bridge case used to run the teardown only when the bridge was
  running, which leaked every port NIO of a stopped bridge — a leaked TAP fd
  keeps the persistent device attached (a second `TUNSETIFF` attach answers
  `EBUSY`, `TUNSETPERSIST 0` answers `EBADFD`), so the server's `tap delete`
  could never succeed after stop → delete. The teardown is now unconditional
  and guards the listener cancel on `tid`, which is 0 for a stopped bridge.
- **Locking.** The hypervisor dispatcher already holds `global_lock` around
  every command, so handlers do not take it again. The relay listeners take
  it only to snapshot the filter list and re-read `destination_nio` —
  it may have been set to NULL by a delete while they were blocked in a read.
  Command handlers cancel and join those listeners while holding
  `global_lock`, so the delay-line teardown uses a separate `iol_delay_lock`;
  taking `global_lock` in `iol_delay_route` would deadlock the join.

## Testing

| Suite | What it covers |
|-------|----------------|
| `tests/iol/test_lifecycle.py` | Command surface and error codes (no caps) |
| `tests/iol/test_relay.py` | Dataplane: header stripping/prepending, per-port routing (no caps) |
| `tests/iol/test_tap_anchor.py` | Anchors: relay both ways, validation, swap semantics, DOWN-anchor resilience, kernel-bridge interop (needs `CAP_NET_ADMIN`) |
| `tests/delay/test_iol.py` | Delay filters on both directions |

Run them all with `cd tests/iol && unshare -Urn python3 run_all.py` (the
anchor suite self-skips without privileges; it needs `lo` up, which the
suites do themselves).

**Crafting frames that must cross a bridge.** When `br_netfilter` is loaded —
`bridge-nf-call-iptables=1`, the usual state on a host running firewalld or
docker — a bridge port runs the netfilter hooks, and the bridge's own
validation drops a frame that claims to be IPv4 without a well-formed IP
header. Measured through a tap→bridge→tap chain on such a host: `0x0800` +
ASCII payload → dropped, `0x0800` + valid IPv4 header → forwarded, `0x88B5`
(non-IP) → forwarded. Test frames therefore use `PROBE_ET` (0x88B5) unless
they really are IP.
