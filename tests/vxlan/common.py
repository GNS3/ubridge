"""Shared helpers for the vxlan test suite.

Each test file imports Ubridge / Client / Results from here. No third-party
dependencies — stdlib only. Mirrors tests/brctl/common.py.
"""
import os
import socket
import subprocess
import time


def ubridge_binary():
    """Return the path to a usable ubridge binary.

    Prefers the installed binary (which has cap_net_admin via `make install`);
    falls back to the in-repo build (no caps — dev runs point UBRIDGE_BINARY
    at it from inside `unshare -Urn`, where root in the new user namespace
    holds CAP_NET_ADMIN; see README.md).
    """
    override = os.environ.get("UBRIDGE_BINARY")
    if override:
        if not os.path.exists(override):
            raise RuntimeError("UBRIDGE_BINARY=%s does not exist" % override)
        return override
    _here = os.path.dirname(os.path.abspath(__file__))
    for path in (
        "/usr/local/bin/ubridge",
        os.path.join(_here, "..", "..", "ubridge"),  # from tests/vxlan/.
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
        """Send one command and read replies until the final line."""
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
    """Context manager that starts/stops a ubridge hypervisor instance.

    The control channel is an AF_UNIX socket authenticated via SO_PEERCRED.
    `port` is kept as the constructor argument only so each test gets a unique
    socket path — distinct ports map to distinct socket files.
    """

    def __init__(self, port=13500, binary=None):
        self.port = port
        self.sock_path = "/tmp/ubridge-vxlan-test-%d.sock" % port
        self.binary = binary or ubridge_binary()
        self.proc = None

    def __enter__(self):
        # Remove a stale socket left by a previous run.
        try:
            os.unlink(self.sock_path)
        except FileNotFoundError:
            pass
        self.proc = subprocess.Popen(
            [self.binary, "-U", self.sock_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait until the control socket accepts connections.
        for _ in range(50):
            if os.path.exists(self.sock_path):
                try:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.settimeout(0.2)
                    s.connect(self.sock_path)
                    s.close()
                    return self
                except OSError:
                    pass
            time.sleep(0.1)
        raise RuntimeError("ubridge did not open control socket %s" % self.sock_path)

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        # ubridge unlinks the socket on a clean exit, but be defensive.
        try:
            os.unlink(self.sock_path)
        except FileNotFoundError:
            pass
        return False

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(self.sock_path)
        return Client(s)


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


def kernel_vxlan_attr(name, *keys):
    """Return a dict of {key: value} for keys found in `ip -d link show <name>`.

    Scans the `vxlan ...` section for `key value` token pairs, so a test can
    verify a parameter actually took effect in the kernel rather than only in
    `vxlan show` output.
    """
    out = subprocess.run(
        ["ip", "-d", "link", "show", name], capture_output=True, text=True
    ).stdout
    if " vxlan " not in out:
        return {}
    section = out.split(" vxlan ", 1)[1]
    toks = section.split()
    result = {}
    for i, tok in enumerate(toks):
        if tok in keys and i + 1 < len(toks):
            result[tok] = toks[i + 1]
    return result


def no_residual(prefix="vxt"):
    """True if no vxlan device whose name starts with `prefix` remains."""
    out = subprocess.run(
        ["ip", "-o", "link", "show", "type", "vxlan"], capture_output=True, text=True
    ).stdout
    return not any(prefix in line for line in out.splitlines())
