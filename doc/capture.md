# capture module — kernel-side AF_PACKET capture

The `capture` hypervisor module captures frames on a kernel interface into a
pcap file via an `AF_PACKET` raw socket. It is exposed over the hypervisor text
protocol as `capture <command> [args...]`.

It exists for the **kernel data plane**: once frames flow `TAP → kernel bridge
(brctl) → TAP`, they never reach ubridge's user-space NIO relay, so the
`bridge` module's NIO-level `start_capture` can't see them. `capture` taps the
interface at the kernel level instead.

## Transport

Same text protocol as the other modules. Replies are `NNN-...` (final line).

## Privileges

Requires `CAP_NET_RAW` (raw socket) — already granted by `sudo make install`.

## Commands

### `capture start_kernel <if> <pcap> [dlt]`

Open an `AF_PACKET` `SOCK_RAW` socket bound to `<if>` (promiscuous), start a
capture thread, and write frames to `<pcap>`. `<dlt>` is the pcap link type
(default `EN10MB`). Reuses ubridge's existing pcap writer
(`create_pcap_capture` / `pcap_capture_packet`).

```
capture start_kernel tap-gns3-e0 /tmp/cap.pcap
100-kernel capture started on tap-gns3-e0 -> /tmp/cap.pcap
```

Only **one** kernel capture at a time (singleton); a second `start_kernel`
while one is active → `209/EALREADY`. Missing interface → `208/ENODEV`.

### `capture stop_kernel`

Stop the active capture (cancel + join the thread, close the socket and pcap
file). Idempotent: if no capture is active, replies `100-no active kernel
capture` (not an error).

```
capture stop_kernel
100-kernel capture stopped
```

## Status codes

| Code | Meaning |
|------|---------|
| `100` | OK |
| `208` | No such interface (`ENODEV`) on start |
| `209` | A capture is already running (`EALREADY`) |

## Implementation notes

- **Singleton**: one global capture (`g_capture`), guarded by a mutex so
  concurrent connections can't race.
- **Thread model**: a dedicated thread loops on `recvfrom()`; stop is via
  `pthread_cancel` + `pthread_join` (`recvfrom` is a cancellation point),
  mirroring how `free_bridges()` stops the NIO listener threads. The socket is
  closed and the pcap writer freed only after the thread has joined, so the
  thread never touches freed state.
- **AF_PACKET open** mirrors `nio_linux_raw.c`: `socket(PF_PACKET, SOCK_RAW,
  htons(ETH_P_ALL))`, bind to `sockaddr_ll.sll_ifindex` (not `SO_BINDTODEVICE`),
  `PACKET_ADD_MEMBERSHIP` promisc.
- Reuses the existing pcap writer; link-type handling via libpcap
  (`pcap_datalink_name_to_val`), default `DLT_EN10MB`.

## Relationship to `bridge start_capture`

| | `bridge start_capture` (NIO capture) | `capture start_kernel` (AF_PACKET) |
|---|---------------------------------------|------------------------------------|
| Taps | the user-space NIO relay loop | a kernel interface |
| Sees | relay-bridge traffic (traditional UDP bridges) | kernel-data-plane traffic (TAP+bridge) |
| Granularity | per-bridge (`bridge->capture`) | process singleton |
| Both can run | yes — independent, different pcap files | yes |

The **pcap file format is identical** (same writer); the **packet contents
differ** because they tap different points. Use `bridge start_capture` for
user-space-relay bridges, `capture start_kernel` for the kernel data plane.

## Testing

`tests/capture/` captures one end of a veth pair while `ping` generates
ARP/ICMP, confirms a non-empty pcap, plus start/stop lifecycle and error paths.
Requires `CAP_NET_ADMIN` (to create the veth) — run under sudo.

```bash
sudo make install
cd tests/capture && sudo python3 run_all.py   # 8/8 PASS
```
