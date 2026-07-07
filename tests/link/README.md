# link test suite

Black-box tests for the `link` hypervisor module (generic interface
management: veth pairs, IP assignment, link state, deletion).

## Prerequisites

ubridge installed with capabilities:

```bash
make
sudo make install          # sets cap_net_admin,cap_net_raw=ep
getcap /usr/local/bin/ubridge
```

The tests run ubridge themselves (control port 13008) and tear it down
when done.

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

## Conventions

- Shares `Ubridge`/`Client`/`Results` from the brctl suite via
  `helpers.py` (loaded by file path, no shared package needed).
- Tests clean up after themselves; `no_residual_link()` asserts no test
  interfaces leak.
