# delay filter tests

Regression coverage for the `delay` packet filter, which had a structural
flaw (GNS3/ubridge#114, root cause of gns3/gns3-server#2827):

> the filter slept inline in the per-direction bridge thread (`nanosleep`),
> so each direction serviced at most ~`1000/latency` pps. Any heavier load
> backed up in the kernel UDP buffer, RTT climbed without bound, and the link
> collapsed with packet loss.

The fix routes delayed sends through a real delay line
(`src/delay_line.[ch]`) with a dedicated release thread, so the receive loop
never blocks and per-packet latency stays bounded regardless of offered load.

## What is checked

`test_latency.py` drives ubridge's hypervisor protocol with a bridge of two
UDP NIOs (looped back to receiver sockets under the test's control) and a
`delay` filter:

1. **single-packet one-way latency** ~= the configured delay (100 ms).
2. **burst under load** — 30 packets sent back-to-back at 100 ms drain in
   bounded time (< 1.2 s) with no loss. The serial-sleep bug would take
   ~3 s (30 × 100 ms) and shed packets; the delay line drains in ~0.12 s.
3. **reverse direction** is bounded too — confirms each direction has its own
   delay line.
4. **jitter** keeps every sample in a sane window (delay ± jitter + slack).
5. **no filter** — forwarding stays fast (sanity, regression guard).
6. **`bridge get_stats`** still reports IN/OUT counters after a burst.
7. **queue limit** — under overload, delivery is capped at the delay line's
   depth limit (default 1000 packets, matching the kernel netem limit) and
   excess packets are tail-dropped, so memory stays bounded while latency
   stays bounded. Uses `UBRIDGE_DELAY_LIMIT=20` for a deterministic check.

## Tuning

The per-direction queue depth defaults to 1000 packets (same as netem's
`NETEM_LIMIT_DEFAULT`). Override it without recompiling:

```
UBRIDGE_DELAY_LIMIT=2000 ubridge -H 127.0.0.1:21000
```

A packet beyond the limit is tail-dropped (excess load is shed, never buffered
without bound).

## Running

No privileges needed (high UDP ports only). Build first, then:

```
make                       # from the repo root
python3 tests/delay/run_all.py
```

or a single suite:

```
cd tests/delay && python3 test_latency.py
```

Stdlib only — no third-party dependencies. The harness reuses the
`Ubridge` / `Client` / `Results` helpers from `tests/brctl/common.py`.
