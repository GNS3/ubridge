"""Basic lifecycle + error-path regression for the brctl module.

Covers create/delete/addif/delif/addip/setup/show/list, common error paths
(duplicate create, missing bridge, bad CIDR), and bridge scoping for port
commands. This is the smoke test — see the other test_*.py for deeper
coverage.
"""
from common import Ubridge, Results, no_residual


def main():
    r = Results()
    with Ubridge(port=13001) as ub:
        c = ub.connect()

        # --- basic lifecycle ---
        r.check("create regtest0", c.code("brctl create regtest0") == "100")
        r.check("setup regtest1", c.code("brctl setup regtest1 10.0.1.1/24") == "100")
        r.check("show regtest1 has IP+UP",
                "10.0.1.1/24" in c.send("brctl show regtest1") and "UP" in c.send("brctl show regtest1"))
        r.check("show regtest0 bare", c.send("brctl show regtest0")[:3] == "100")

        list_out = c.send("brctl list")
        r.check("list mentions regtest0/1",
                "regtest0" in list_out and "regtest1" in list_out)

        import subprocess as _sp
        _has_ubtest = _sp.run(["ip","-o","link","show","ubtest"]).returncode == 0
        if _has_ubtest:
            r.check("addif regtest0 ubtest", c.code("brctl addif regtest0 ubtest") == "100")
            r.check("delif regtest0 ubtest", c.code("brctl delif regtest0 ubtest") == "100")

        # --- error paths ---
        r.check("duplicate create -> 206/EEXIST",
                c.code("brctl create regtest0") == "206",
                c.send("brctl create regtest0"))
        r.check("delete missing -> 207/ENODEV",
                c.code("brctl delete nope") == "207")
        r.check("addip no slash -> 204",
                c.code("brctl addip regtest0 1.2.3.4") == "204")
        r.check("addip prefix>32 -> 204",
                c.code("brctl addip regtest0 9.9.9.9/33") == "204")
        r.check("setup bad ip -> 204 (and no bridge created)",
                c.code("brctl setup nonexistent 1.2.3.4") == "204"
                and c.code("brctl show nonexistent")[:3] == "206")

        # --- bridge scoping (only if ubtest exists) ---
        r.check("create regtest2", c.code("brctl create regtest2") == "100")
        if _has_ubtest:
            r.check("addif regtest1 ubtest", c.code("brctl addif regtest1 ubtest") == "100")
            r.check("setportprio wrong bridge -> 206",
                    c.code("brctl setportprio regtest2 ubtest 8") == "206")
            r.check("setportprio right bridge -> 100",
                    c.code("brctl setportprio regtest1 ubtest 8") == "100")
            r.check("delif wrong bridge -> 207",
                    c.code("brctl delif regtest2 ubtest") == "207")
            r.check("delif right bridge -> 100",
                    c.code("brctl delif regtest1 ubtest") == "100")

        # --- cleanup ---
        r.check("delete regtest0", c.code("brctl delete regtest0") == "100")
        r.check("delete regtest1", c.code("brctl delete regtest1") == "100")
        r.check("delete regtest2", c.code("brctl delete regtest2") == "100")
        c.close()

    r.check("no residual bridges", no_residual())
    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
