# tc module — kernel netem link impairment

The `tc` hypervisor module attaches and removes a **netem** qdisc at the root
of an interface, providing kernel-side link impairment (delay / jitter / loss /
duplicate / corrupt). It is exposed over the hypervisor text protocol as
`tc <command> [args...]`.

It exists for the **kernel data plane**: once frames flow `TAP → kernel bridge
(brctl) → TAP`, they never reach ubridge's user-space NIO relay, so the
`bridge` module's user-space packet filters (`delay` / `packet_loss` / `corrupt`
/ `bpf`) no longer see the traffic. The impairment has to live in the kernel
qdisc instead. `tc` is that kernel-side replacement for the subset of user-space
filters that netem covers (delay/jitter/loss/dup/corrupt).

## Transport

Same text protocol as the other modules: newline-terminated commands, first
token is the module (`tc`), second is the command, rest are arguments. Replies
are `NNN-...` (final line).

## Privileges

Requires `CAP_NET_ADMIN` (attaching a qdisc). In practice ubridge is granted
capabilities on install:

```bash
sudo make install       # sets cap_net_admin,cap_net_raw=ep on the binary
getcap $(which ubridge) # verify
```

## Commands

### `tc netem set <if> [delay <ms>] [jitter <ms>] [loss <%>] [dup <%>] [corrupt <%>]`

Attach/replace a netem qdisc at the root of `<if>` (`RTM_NEWQDISC`,
`NLM_F_CREATE|REPLACE`). At least one option must be given. Keyword/value
pairs, any order:

| Option | Unit | Notes |
|--------|------|-------|
| `delay <ms>` | milliseconds (may be fractional) | added latency |
| `jitter <ms>` | milliseconds | latency variation |
| `loss <%>` | 0–100 | random packet loss |
| `dup <%>` | 0–100 | random duplication |
| `corrupt <%>` | 0–100 | random corruption |

```
tc netem set tap-gns3-e0 delay 100 jitter 10 loss 5
100-netem set on tap-gns3-e0
```

Verify in the kernel with `tc qdisc show dev <if>`:
```
qdisc netem 8002: root refcnt 2 limit 1000 delay 100.0ms  10.0ms loss 5% ...
```
(`tc` prints jitter as a bare second time value after delay, not the word
"jitter".)

Bad value / unknown keyword → `204`. Bad number of params → `203`. Missing
interface → `206/ENODEV`.

### `tc reset <if>`

Remove the root qdisc of `<if>` (`RTM_DELQDISC`). This removes whatever root
qdisc is attached (netem or the default); the kernel re-creates a default
qdisc.

```
tc reset tap-gns3-e0
100-qdisc reset on tap-gns3-e0
```

Missing interface → `207/ENODEV`.

## Status codes

| Code | Meaning |
|------|---------|
| `100` | OK |
| `203` | Bad number of parameters |
| `204` | Invalid parameter value |
| `206` | Unable to create / set (`ENODEV`, etc.) |
| `207` | Unable to delete (`ENODEV`) |

## Implementation notes

- **netem ABI** (per `net/sched/sch_netem.c` `netem_change`): `TCA_OPTIONS` is a
  nested attribute whose payload begins with a raw `struct tc_netem_qopt`
  (mandatory), optionally followed by nested `TCA_NETEM_*` attributes.
- **delay/jitter** are sent as `TCA_NETEM_LATENCY64` / `TCA_NETEM_JITTER64`
  (s64 nanoseconds), which override the legacy u32 struct fields and avoid the
  `PSCHED_TICKS` unit ambiguity. **loss / duplicate** go in the struct fields as
  `probability × 2³²`; **corrupt** is the fixed-size `TCA_NETEM_CORRUPT` nested
  attr (`struct tc_netem_corrupt { probability, correlation }`).
- Uses ubridge's netlink library (`src/netlink/nl.c`); `nla_put_buffer` carries
  the s64 `*64` attrs and the corrupt struct (no `nla_put_u64` needed).
- Helpers return a **negative errno**; command handlers report `strerror(-err)`.

## Relationship to user-space packet filters

| user-space filter (`bridge add_packet_filter`) | kernel equivalent |
|------------------------------------------------|-------------------|
| `delay`(+`jitter`) | `tc netem delay/jitter` |
| `packet_loss` | `tc netem loss` |
| `corrupt` | `tc netem corrupt` |
| (none) | `tc netem dup` (no user-space dup filter) |
| `frequency_drop` (exact every-Nth) | none — netem loss is stochastic; exact needs eBPF |
| `bpf` (cBPF drop filter) | none — needs tc clsact eBPF (not implemented) |

## Testing

`tests/tc/` attaches netem to a throwaway dummy interface and reads it back with
`tc qdisc show` (delay/jitter/loss/dup/corrupt), plus reset and error paths.
Requires `CAP_NET_ADMIN` — run under sudo.

```bash
sudo make install
cd tests/tc && sudo python3 run_all.py   # 17/17 PASS
```
