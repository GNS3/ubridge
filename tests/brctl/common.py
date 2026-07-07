"""Shared helpers for the brctl test suite.

Each test file imports Ubridge / Client / Results from here. No third-party
dependencies — stdlib only.
"""
import os
import socket
import subprocess
import time


def ubridge_binary():
    """Return the path to a usable ubridge binary.

    Prefers the installed binary (which has cap_net_admin via `make install`);
    falls back to the in-repo build (no caps — used by test_no_privs). Works
    whether run from the repo root or from tests/brctl/.
    """
    _here = os.path.dirname(os.path.abspath(__file__))
    for path in (
        "/usr/local/bin/ubridge",
        os.path.join(_here, "..", "..", "ubridge"),  # from tests/brctl/.
        "./ubridge",
    ):
        p = os.path.normpath(path)
        if os.path.exists(p):
            return p
    raise RuntimeError("ubridge binary not found (run `make` or `make install`)")


class Client:
    """A single connection to a ubridge hypervisor instance."""

    def __init__(self, sock):
        self.s = sock

    def send(self, cmd):
        """Send one brctl command and read replies until the final line."""
        self.s.sendall((cmd + "\n").encode())
        buf = b""
        while b"-" not in buf:
            chunk = self.s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf.decode(errors="replace").strip()

    def code(self, cmd):
        """Send a command and return just its 3-digit status code."""
        return self.send(cmd)[:3]

    def close(self):
        self.s.close()


class Ubridge:
    """Context manager that starts/stops a ubridge hypervisor instance."""

    def __init__(self, port=13000, binary=None):
        self.port = port
        self.binary = binary or ubridge_binary()
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            [self.binary, "-H", "127.0.0.1:%d" % self.port],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait until the control port accepts connections.
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return self
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("ubridge did not open control port %d" % self.port)

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        return False

    def connect(self):
        return Client(socket.create_connection(("127.0.0.1", self.port), timeout=5))


class Results:
    """Collects pass/fail checks and prints a summary."""

    def __init__(self):
        self.items = []

    def check(self, name, cond, detail=""):
        self.items.append((name, bool(cond), detail))
        return bool(cond)

    def summary(self):
        npass = sum(1 for _, ok, _ in self.items if ok)
        nfail = sum(1 for _, ok, _ in self.items if not ok)
        for name, ok, detail in self.items:
            tag = "PASS" if ok else "FAIL"
            line = "  [%s] %s" % (tag, name)
            if detail:
                line += "  -- " + detail
            print(line)
        print("\n%d/%d PASS" % (npass, npass + nfail))
        return nfail == 0


def kernel_bridge_attr(bridge, *keys):
    """Return a dict of {key: value} for keys found in `ip -d link show <bridge>`.

    Scans the `bridge ...` section for `key value` token pairs. Useful for
    verifying a parameter actually took effect in the kernel.
    """
    out = subprocess.run(
        ["ip", "-d", "link", "show", bridge], capture_output=True, text=True
    ).stdout
    section = out.split("bridge", 1)[1] if "bridge" in out else ""
    toks = section.split()
    result = {}
    for i, tok in enumerate(toks):
        if tok in keys and i + 1 < len(toks):
            result[tok] = toks[i + 1]
    return result


def no_residual(prefix="regtest"):
    """True if no bridge whose name starts with `prefix` remains."""
    out = subprocess.run(
        ["ip", "-o", "link", "show", "type", "bridge"], capture_output=True, text=True
    ).stdout
    return not any(prefix in line for line in out.splitlines())
