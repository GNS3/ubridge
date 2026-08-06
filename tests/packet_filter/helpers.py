"""Shared helpers for the packet_filter test suite.

Re-uses the delay suite's UDP traffic primitives (build_bridge / send_burst /
recv_count / bound_udp) and the brctl Ubridge/Client/Results harness by file
path, the same way delay/helpers.py loads brctl/common.py — so the test trees
stay independent with no shared package.

The filters under test (corrupt / packet_loss / frequency_drop) are pure
user-space impairments applied on the bridge relay path. No CAP_NET_ADMIN
needed; runs against the in-repo ./ubridge (the installed binary may be stale).
"""
import importlib.util
import os

_delay_helpers = os.path.join(os.path.dirname(__file__), "..", "delay", "helpers.py")
_spec = importlib.util.spec_from_file_location("pf_delay_helpers", _delay_helpers)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

HOST = _mod.HOST
Ubridge = _mod.Ubridge
Client = _mod.Client
Results = _mod.Results
ubridge_binary = _mod.ubridge_binary
bound_udp = _mod.bound_udp
send_burst = _mod.send_burst
recv_count = _mod.recv_count
build_bridge = _mod.build_bridge
