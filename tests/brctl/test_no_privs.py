"""Privilege-failure test: run ubridge WITHOUT cap_net_admin.

All bridge mutations (create/delete/addif/addip/parameters) must fail
gracefully with an error reply (EPERM/EINVAL), never crash the process.
`list` is read-only netlink and may still succeed.

This test uses the in-repo `./ubridge` binary, which normally has no caps.
If the binary is somehow privileged, the test detects this (create succeeds)
and skips with a SKIP note — it cannot meaningfully test the no-cap path.
"""
import os.path

from common import Client, Results, Ubridge


def main():
    r = Results()

    _repo = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
    local = os.path.join(_repo, "ubridge")
    if not os.path.exists(local):
        print("SKIP: ./ubridge not built (run `make` in the repo root).")
        return 0

    with Ubridge(port=13007, binary=local) as ub:
        c = ub.connect()

        # read-only show should always work
        list_reply = c.code("brctl show docker0")
        r.check("show works without caps (read-only)", list_reply.startswith("100"), list_reply)

        # Probe: if create succeeds the binary has effective privilege;
        # skip mutation tests (cannot test no-cap path on this binary).
        code_probe = c.code("brctl create privprobe")
        if code_probe == "100":
            c.send("brctl delete privprobe")
            c.close()
            print("SKIP: binary has effective caps — mutation rejection not testable")
            return 0

        # Binary is unprivileged: all mutations must be rejected.
        r.check("create -> 206/EPERM",
                code_probe in ("206", "207"), "got %s" % code_probe)
        r.check("delete missing -> 206/EPERM",
                c.code("brctl delete noprivtest") in ("206", "207"))
        r.check("process alive after test",
                c.code("brctl show docker0").startswith("100"))

        c.close()

    ok = r.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
