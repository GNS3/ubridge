"""Per-port VLAN membership (vlan_add / vlan_del) regression for the brctl module.

Drives the RTM_SETLINK/DELLINK + IFLA_AF_SPEC path and reads the result back
from the kernel with `bridge vlan show`: access-port (pvid untagged), idempotent
re-add, tagged single VID, tagged range, deletion (single + range), and the
error paths (bad VID, reversed range, pvid-on-range, flag-on-delete,
wrong-bridge scoping).

Prerequisite (run as root): an installed, capable binary (`sudo make install`).
The `ubtest` port is auto-created under root (ensure_ubtest in common.py); run
    sudo ip link add ubtest type dummy
manually only if a suite is run without privileges.
"""
import subprocess as _sp
from common import Ubridge, Results, no_residual, ensure_ubtest


def port_vlans(port):
    """Return `bridge vlan show dev <port>` text ("" if bridge tool/port absent)."""
    try:
        return _sp.run(["bridge", "vlan", "show", "dev", port],
                       capture_output=True, text=True).stdout
    except FileNotFoundError:
        return ""


def _vid_line(text, vid):
    """First whitespace-token line of `bridge vlan show` text whose tokens
    contain exactly `vid` (avoids matching vid 1 inside "100" or "300-302")."""
    for line in text.splitlines():
        if str(vid) in line.split():
            return line
    return ""


def _has_range(text, lo, hi):
    """True if `bridge vlan show` text reflects every VID in [lo,hi] — either as
    individual per-VID lines (the default, non-compressed dump) or as one
    collapsed 'lo-hi' token."""
    toks = text.split()
    if "%d-%d" % (lo, hi) in toks:
        return True
    return all(str(v) in toks for v in range(lo, hi + 1))


def main():
    r = Results()
    with Ubridge(port=13005) as ub:
        c = ub.connect()

        has_port = ensure_ubtest()
        if not has_port:
            print("  [NOTE] no ubtest dummy and not root — port tests skipped")

        # --- filtering bridge + port ---
        r.check("create regtestv0", c.code("brctl create regtestv0") == "100")
        r.check("vlanfiltering on regtestv0",
                c.code("brctl vlanfiltering regtestv0 on") == "100")

        if has_port:
            r.check("addif regtestv0 ubtest",
                    c.code("brctl addif regtestv0 ubtest") == "100")

            # access-port: vid 100, pvid (ingress untag) + untagged (egress untag)
            r.check("vlan_add 100 pvid untagged -> 100",
                    c.code("brctl vlan_add regtestv0 ubtest 100 pvid untagged") == "100")
            vl = port_vlans("ubtest")
            r.check("kernel: 100 is PVID + Egress Untagged",
                    "PVID" in _vid_line(vl, 100) and "Egress" in _vid_line(vl, 100), vl)

            # idempotent: re-adding the same VID/flags is a no-op success
            r.check("vlan_add 100 again (idempotent) -> 100",
                    c.code("brctl vlan_add regtestv0 ubtest 100 pvid untagged") == "100")

            # tagged single VID (no flags)
            r.check("vlan_add 200 -> 100",
                    c.code("brctl vlan_add regtestv0 ubtest 200") == "100")
            r.check("kernel: 200 present", "200" in port_vlans("ubtest").split())

            # tagged range 300-302
            r.check("vlan_add 300 vid 302 -> 100",
                    c.code("brctl vlan_add regtestv0 ubtest 300 vid 302") == "100")
            r.check("kernel: 300..302 present", _has_range(port_vlans("ubtest"), 300, 302))

            # delete a single VID
            r.check("vlan_del 200 -> 100",
                    c.code("brctl vlan_del regtestv0 ubtest 200") == "100")
            r.check("kernel: 200 gone", "200" not in port_vlans("ubtest").split())

            # delete a range
            r.check("vlan_del 300 vid 302 -> 100",
                    c.code("brctl vlan_del regtestv0 ubtest 300 vid 302") == "100")
            r.check("kernel: 300..302 gone", not _has_range(port_vlans("ubtest"), 300, 302))

            # --- error paths (parse-level -> 204) ---
            r.check("vlan_add vid 0 -> 204",
                    c.code("brctl vlan_add regtestv0 ubtest 0") == "204")
            r.check("vlan_add vid 4095 -> 204",
                    c.code("brctl vlan_add regtestv0 ubtest 4095") == "204")
            r.check("vlan_add reversed range -> 204",
                    c.code("brctl vlan_add regtestv0 ubtest 50 vid 10") == "204")
            r.check("vlan_add pvid on range -> 204 (port has one PVID)",
                    c.code("brctl vlan_add regtestv0 ubtest 10 vid 20 pvid") == "204")
            r.check("vlan_del with pvid -> 204 (del is VID-only)",
                    c.code("brctl vlan_del regtestv0 ubtest 100 pvid") == "204")

            # wrong-bridge scoping: ubtest is on regtestv0, not regtestv1
            r.check("create regtestv1", c.code("brctl create regtestv1") == "100")
            r.check("vlan_add wrong bridge -> 206",
                    c.code("brctl vlan_add regtestv1 ubtest 400") == "206")
            r.check("delete regtestv1", c.code("brctl delete regtestv1") == "100")

        r.check("delete regtestv0", c.code("brctl delete regtestv0") == "100")
        c.close()

    r.check("no residual bridges", no_residual())
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
