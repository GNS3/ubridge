# brctl test suite

Black-box tests for the `brctl` hypervisor module. They drive ubridge's
TCP control port as a client would, and verify behaviour both from the
reply codes and (where it matters) from kernel state via `ip`.

## Prerequisites

1. **ubridge installed with capabilities** (for everything except `test_no_privs`):

   ```bash
   make
   sudo make install          # sets cap_net_admin,cap_net_raw=ep
   getcap /usr/local/bin/ubridge
   ```

2. **A throwaway dummy port** for the port / addif / delif tests:

   ```bash
   sudo ip link add ubtest type dummy
   sudo ip link set ubtest down
   ```

3. The tests run ubridge themselves (each suite picks a distinct control
   port in the 13001–13007 range) and tear it down when done.

## Running

```bash
cd tests/brctl

# one suite
python3 test_basic.py

# everything
python3 run_all.py
```

`run_all.py` exits non-zero if any suite fails, so it can gate CI.

## Suites

| Suite | What it covers |
|-------|----------------|
| `test_basic.py` | Lifecycle (create/delete/addif/delif/addip/setup/show/list), common error paths, bridge scoping. The smoke test. |
| `test_boundary.py` | Boundary values for every ranged parameter (inclusive edges accepted, just-beyond rejected), on/off token variants, vlan-protocol whitelist; verifies a few values took effect in the kernel. |
| `test_concurrency.py` | Many clients racing to create the same bridge (exactly one wins), and a `list` reader under create/delete churn. Catches the multithreaded races the module was bitten by. |
| `test_robustness.py` | Malformed input (non-numeric numbers, bad CIDRs, IPv6, overlong names, missing ports). Must reject gracefully, never crash. |
| `test_state.py` | State transitions: enslave twice, re-add IP (replace), delete a bridge with a port attached, DOWN vs UP bridge operations. |
| `test_stress.py` | Hundreds of create/delete cycles, fd-count stability, and `list` correctness with many bridges (dump coalescing at scale). |
| `test_no_privs.py` | Runs the no-cap `./ubridge`: mutations must be rejected, the process must survive. Uses the in-repo build (no caps) rather than the installed one. |

## Conventions

- Each suite is standalone: `python3 <suite>.py` returns exit 0 on pass,
  non-zero on fail.
- All suites share helpers in `common.py` (`Ubridge` context manager,
  `Client`, `Results`, `kernel_bridge_attr`, `no_residual`).
- Tests clean up after themselves; `no_residual()` asserts no test bridges
  leak. Pre-existing bridges (e.g. `docker0`) are never touched.
- The dummy port `ubtest` is created/removed by the operator, not the tests
  (they skip port tests gracefully if it is absent).
