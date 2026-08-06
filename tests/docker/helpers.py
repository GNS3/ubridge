"""Shared helpers for the docker test suite.

Despite the module name, this is NOT about docker containers —
`src/hypervisor_docker.c` exposes four netlink/ioctl commands GNS3 uses to
plumb a container's network: create_veth, delete_veth, set_mac_addr, move_to_ns.
No docker daemon is involved; the tests need only CAP_NET_ADMIN.

Re-uses the delay harness (Ubridge/Client/Results) by file path; interface
state is verified via `ip` and /sys/class/net, and move_to_ns targets a child
process in a fresh network namespace (verified via `nsenter`).
"""
import importlib.util
import os
import subprocess

_delay_helpers = os.path.join(os.path.dirname(__file__), "..", "delay", "helpers.py")
_spec = importlib.util.spec_from_file_location("docker_delay_helpers", _delay_helpers)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

HOST = _mod.HOST
Ubridge = _mod.Ubridge
Client = _mod.Client
Results = _mod.Results
ubridge_binary = _mod.ubridge_binary

IFNAMSIZ = 16   # Linux interface-name limit (incl. NUL); strlen >= 16 is rejected


def sh(*args):
    """Run a command, return CompletedProcess (no raise)."""
    return subprocess.run(args, capture_output=True, text=True)


def iface_exists(name):
    """True if interface `name` exists in the current netns."""
    return sh("ip", "-o", "link", "show", name).returncode == 0


def iface_is_up(name):
    """True if interface `name` has the IFF_UP flag set."""
    out = sh("ip", "-o", "link", "show", name).stdout
    if "<" not in out or ">" not in out:
        return False
    flags = out[out.find("<") + 1: out.find(">")]
    return "UP" in flags.split(",")


def iface_mac(name):
    """The current MAC of `name` (lowercase aa:bb:..), or None. Uses netlink
    (`ip link`) rather than /sys/class/net, so it works inside a network
    namespace whose sysfs is still pinned to the init netns (e.g. unshare)."""
    import re
    r = sh("ip", "-o", "link", "show", name)
    if r.returncode != 0:
        return None
    m = re.search(r"link/ether ([0-9a-fA-F:]{17})", r.stdout)
    return m.group(1).lower() if m else None


def ip_link_del(name):
    """Delete an interface (best-effort cleanup)."""
    sh("ip", "link", "del", name)


class NetnsChild:
    """A child process in its own fresh network namespace, used as a target
    for `docker move_to_ns <if> <pid> <dst>`. Entered/killed by the test."""

    def __init__(self):
        # unshare -n puts `sleep` in a new netns; its PID is the move target.
        self.proc = subprocess.Popen(["unshare", "-n", "sleep", "300"])
        self.pid = self.proc.pid

    def has_iface(self, name):
        """True if `name` is visible inside the child's netns."""
        r = sh("nsenter", "-t", str(self.pid), "-n", "ip", "-o", "link", "show", name)
        return r.returncode == 0

    def stop(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
