"""Privilege-failure test: run ubridge WITHOUT cap_net_admin.

All bridge mutations (create/delete/addif/addip/parameters) must fail
gracefully with an error reply (EPERM/EINVAL), never crash the process.
`list` is read-only netlink and may still succeed.

This test deliberately uses the in-repo `./ubridge` binary, which is built
without capabilities (the installed `/usr/local/bin/ubridge` has them via
`make install`). Run it from the repo root.
"""
import os.path

from common import Client, Results, Ubridge


def main():
    r = Results()

    # Force the no-cap in-repo build, resolved relative to this test file
    # (run_all.py runs from tests/brctl/, so the binary is two levels up).
    _repo = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
    local = os.path.join(_repo, "ubridge")
    if not os.path.exists(local):
        print("SKIP: ./ubridge not built (run `make` in the repo root).")
        return 0

    import subprocess
    try:
        caps = subprocess.run(["getcap", local], capture_output=True, text=True).stdout
    except FileNotFoundError:
        caps = ""  # getcap not installed, assume no caps
    if "cap_net_admin" in caps:
        print("NOTE: ./ubridge has cap_net_admin — this test won't be meaningful.")
        print("      Build a clean copy: `cp ubridge /tmp/ubridge-nocap` and edit this file.")

    with Ubridge(port=13007, binary=local) as ub:
        c = ub.connect()

        # read-only list should still work (no caps needed for RTM_GETLINK dump)
        list_reply = c.code("brctl list")
        r.check("list works without caps (read-only)", list_reply.startswith("100"), list_reply)

        # all mutations must be rejected, not crash
        code_create = c.code("brctl create noprivtest")
        r.check("create rejected without caps",
                code_create in ("206", "207"),
                "got %s" % code_create)
        code_delete = c.code("brctl delete noprivtest")
        r.check("delete rejected without caps",
                code_delete in ("206", "207"),
                "got %s" % code_delete)

        # process must still be alive and responding after the rejections
        r.check("process alive after rejected mutations",
                c.code("brctl list").startswith("100"))

        c.close()

    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
