# bridge module tests

Black-box tests for the generic `bridge` module (the NIO relay), driven over
the hypervisor control socket. The deployment shape under test is the
Docker/IOL relay: a per-node bridge holding a unix-socket NIO (the container
leg) for the node's whole life, with the topology leg (udp/tap) swapping as
links come and go.

| Suite | What it covers | Privileges |
|-------|----------------|------------|
| `test_zero_length.py` | A zero-length read is skipped, not forwarded or counted — the regression for the `nio_recv` 0→-1 collapse, which wedged a relay thread mid-`exit()` on one empty datagram (dead direction, half-torn-down control channel) | none |
| `test_swap.py` | `delete_nio_tap`: validation codes (214/204), the running refusal (use-after-free guard), device-survives semantics, four-way udp↔tap swaps, the unix binding surviving the swap window (a frame sent while stopped arrives after start), kernel-truncated names matching by their resolved 15 chars, teardown order (`bridge delete` → `tap delete`) | `CAP_NET_ADMIN` |
| `test_relay.py` | unix↔tap relay in both directions; an admin-DOWN anchor as a steady state (every write dropped with EIO accounted, daemon alive, control channel healthy); recovery after `link set up` | `CAP_NET_ADMIN` |

Run everything (the tap suites self-skip without caps):

```sh
python3 run_all.py
```

Privileged suites under a user namespace, against the just-built binary:

```sh
unshare -Urn --map-root-user bash -c 'python3 run_all.py'
```

Notes:

- The zero-length regression is why `test_zero_length` exists as its own
  suite: the bug reproduced with a *single* empty datagram, on a bridge with
  no TAP involved at all. Do not fold it into the tap suites.
- Probe frames use ethertype `0x88B5` (see `tests/iol/README.md`): with
  `br_netfilter` loaded, a frame claiming IPv4 without a well-formed IP
  header is dropped at bridge ingress.
- An AF_PACKET socket bound to an interface goes `ENETDOWN` across a
  down/up cycle — re-create it after recovery (same note as the iol suite).
