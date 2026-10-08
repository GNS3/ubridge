"""Run the whole bridge test suite in sequence, exit non-zero if any fail.

test_zero_length needs no privileges; test_swap and test_relay self-skip
without CAP_NET_ADMIN (they create persistent TAPs).
"""
import importlib
import sys

SUITES = [
    "test_zero_length",
    "test_swap",
    "test_relay",
]


def main():
    overall = 0
    for name in SUITES:
        print("\n" + "=" * 60)
        print(name)
        print("=" * 60)
        mod = importlib.import_module(name)
        rc = mod.main()
        if rc != 0:
            overall = rc
    print("\n" + "=" * 60)
    print("ALL SUITES: " + ("PASS" if overall == 0 else "FAIL"))
    print("=" * 60)
    return overall


if __name__ == "__main__":
    sys.path.insert(0, __file__[: -len("run_all.py")])
    raise SystemExit(main())
