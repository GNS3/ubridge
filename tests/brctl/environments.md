# Test environments

Test results across different environments.

## Local workstation

- **OS**: kernel 6.19.11-1-default (x86_64)
- **glibc**: —
- **ubridge**: `/usr/local/bin/ubridge` with `cap_net_admin,cap_net_raw=ep`
- **ubtest dummy**: present (used for port-level tests)
- **Pre-existing bridges**: `docker0`, `br-ce45044e6a6a`
- **Result**: 95/95 PASS (all suites)

## Home server

- **OS**: Debian 12 (bookworm), kernel 6.1.0-42-amd64 x86_64
- **glibc**: 2.36-9+deb12u13
- **ubridge**: `/usr/local/bin/ubridge` with `cap_net_admin,cap_net_raw=ep`; `./ubridge` also has effective caps
- **ubtest dummy**: absent (port-level tests skipped gracefully)
- **Pre-existing bridges**: none
- **Result**: 95/95 PASS (all suites)
