# link test suite

Black-box tests for the `link` hypervisor module (generic interface
management: veth pairs, IP assignment, link state, deletion, L2-only
hardening) and for the creators in `tap` / `docker` / `brctl` that apply the
hardening themselves.

## Prerequisites

ubridge installed with capabilities:

```bash
make
sudo make install          # sets cap_net_admin,cap_net_raw=ep
getcap /usr/local/bin/ubridge
```

The tests run ubridge themselves (control port 13008, `test_l2only.py` 13009)
and tear it down when done. They also need the `ip` tool (read-only queries
only — every privileged step goes through ubridge).

## Running

```bash
cd tests/link

# one suite
python3 test_basic.py

# everything
python3 run_all.py
```

`run_all.py` exits non-zero if any suite fails, so it can gate CI.

## Suites

| Suite | What it covers |
|-------|----------------|
| `test_basic.py` | veth create (both ends exist, duplicate → 206, overlong name → 204), set up/down (+ kernel flag verification), addr (kernel IP verification, brings iface UP, bad CIDR/prefix → 204), delete (removes both ends, missing → 207), param-count errors. |
| `test_l2only.py` | `link l2only` per the L2-anchor spec §E and the creators that apply it: command contract (208/204/203/100, default `on`, idempotency, no transient device), `addrgenmode none` + no address after each of the five creators (including the transient TAP `bridge add_nio_tap` creates for a free name, while an attach to a pre-existing device keeps its address), an already-UP anchor is cleaned up (and only the named device is touched), `off` reverts and the link-local returns on the next down/up, and idle silence per role (veth with peer up / TAP with an fd / bridge with two ports) against an unhardened control. |
| `test_mtu.py` | The jumbo-safe default MTU (65521) every creator applies to its plumbing: link veth both ends, docker create_veth on the host anchor (the guest end is the container's eth0 and keeps 1500 — raising it opts into bidirectional jumbo, verified with 9000-byte frames across the veth), tap create, and the transient TAP `bridge add_nio_tap` creates — while an attach to a pre-existing TAP keeps its admin MTU (§B gate); the bridge itself derives its MTU from the ports (`br_mtu_auto_adjust`: 65521 → 1500 when a dummy port joins → back); and end-to-end, a 9000-byte AF_PACKET frame crosses a two-port bridge intact in both directions. The admin-MTU fixture, the dummy port, and the AF_PACKET injections need the test process to hold CAP_NET_ADMIN/CAP_NET_RAW — in CI's unprivileged run (capped binary, plain user) those groups self-skip. |

## Conventions

- Shares `Ubridge`/`Client`/`Results` from the brctl suite via
  `helpers.py` (loaded by file path, no shared package needed).
- Tests clean up after themselves; `no_residual_link()` asserts no test
  interfaces leak.
- `test_l2only.py` drives the **installed** binary by default (that is the one
  with file capabilities when CI runs the suite unprivileged). Set
  `UBRIDGE_BINARY=$PWD/ubridge` to drive the in-repo build instead — needed
  when the installed one predates the feature, which then answers
  `202-Unknown command 'l2only'`.
- `test_l2only.py` self-skips rather than passing vacuously where the kernel
  gives it nothing to measure: no CAP_NET_ADMIN, no IPv6 self-provisioning in
  the netns, no `capture`, or an unhardened control that emits no traffic at
  all. A skip is printed with its reason and is not counted as a pass.
- Its silence checks depend on kernel timing that is documented in
  `doc/link.md` and `doc/capture.md`: the chatter is a one-shot at bring-up,
  and a capture must be started **after** its interface is UP. Both are
  respected by the suite; the two remaining documented quirks (MLD reports
  still go out; the settled window) are why the checks are split into
  "no ND/DAD/RS" and "idle once settled".
