"""Run the whole marker test suite in sequence, exit non-zero if any fail."""
import importlib
import sys

SUITES = [
    "test_basic",
    "test_dir_filter",
    "test_linktype",
    "test_pause",
    "test_reset_preserves_mark",
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
