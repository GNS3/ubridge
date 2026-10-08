# vxlan test suite

Black-box regression for the `vxlan` hypervisor module (kernel VXLAN device
lifecycle via rtnetlink), driven over the AF_UNIX control socket like the
brctl suite. Stdlib Python only.

## Prerequisites

- CAP_NET_ADMIN in the current network namespace (create/delete vxlan
  devices), plus the `ip` utility from iproute2 for kernel cross-checks.
- Either the installed binary (`make install`, carries cap_net_admin), or
  point `UBRIDGE_BINARY` at the in-repo build.

## Running

    # dev loop, no install needed (root in the new user namespace holds
    # CAP_NET_ADMIN there):
    unshare -Urn env UBRIDGE_BINARY=$PWD/ubridge \
        python3 tests/vxlan/run_all.py

    # against the installed binary (as root or via the capped install):
    cd tests/vxlan && python3 run_all.py

CI runs it in the kernel job of test-ubridge.yml (capped installed binary),
after the brctl suite.

## Suites

| Suite | Scope |
|---|---|
| `test_basic` | lifecycle (create/delete/show), full key=value surface, kernel cross-verification via `ip -d link`, error paths (duplicate, bad VNI, address-class mixups, remote/group exclusivity), kernel default dstport = 8472 |
| `test_boundary` | VNI/dstport/ttl range edges, IFNAMSIZ name length, IPv4+IPv6 unicast/multicast, group-requires-dev, bridge-attach orchestration path incl. EBUSY-protected delete ordering |
