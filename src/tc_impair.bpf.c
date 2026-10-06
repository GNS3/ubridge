/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2015 GNS3 Technologies Inc.
 *
 *   ubridge is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   ubridge is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * The eBPF stateful impairment classifier (kernel-impairment spec B.1).
 *
 * Freestanding: no CO-RE, no BTF-typed pointers, plain packet access.
 * Its instructions are embedded into the build as an instruction array
 * (src/tc_ebpf_insns.c, regenerated from the compiled object by
 * tools/gen_tc_impair.py / `make bpf`) — no runtime clang/libbpf.
 *
 * Verifier-friendly by construction: NO LOOPS AT ALL (the window cycle
 * catch-up is a fixed number of straight-line steps — see its comment for
 * why a loop, however small, cannot be used here), every packet access is
 * preceded by a bounds check, L4 ports are only read for TCP/UDP over IPv4
 * with the full L4 header verified present.
 */

#include "tc_impair.h"

/*
 * Minimal freestanding definitions (the BPF target has no libc; pulling in
 * the uapi <linux/bpf.h> drags arch-dependent headers). The __sk_buff
 * offsets used here (len @0, data @76, data_end @80) are the stable uapi
 * layout, asserted from the native side in tc_ebpf.c.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define SEC(NAME) __attribute__((section(NAME), used))

/* Keep every helper inlined into the classifier: the committed-insn
 * pipeline (tools/gen_tc_impair.py + the raw-syscall loader) carries no
 * intra-program call relocations — an outlined helper would emit an
 * R_BPF_64_32 the generator refuses (a silent call-to-self otherwise). */
#define inline_always __attribute__((always_inline))

struct min_skb {
    u32 len;                 /* offset 0 */
    u8 _pad[76 - 4];         /* keep data/data_end at their uapi offsets */
    u32 data;                /* offset 76 */
    u32 data_end;            /* offset 80 */
};

/* legacy (pre-BTF) map definition — the loader creates the maps itself and
 * patches the two pseudo-fd loads in the embedded instructions */
struct bpf_map_def {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 map_flags;
};

struct bpf_map_def SEC("maps") cfg_map = {
    .type = 2,                              /* BPF_MAP_TYPE_ARRAY */
    .key_size = sizeof(u32),
    .value_size = sizeof(struct tc_impair_cfg),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") cnt_map = {
    .type = 2,                              /* BPF_MAP_TYPE_ARRAY */
    .key_size = sizeof(u32),
    .value_size = sizeof(struct tc_impair_cnt),
    .max_entries = 1,
};

/* helper functions by stable uapi id */
static void *(*map_lookup_elem)(const void *map, const void *key) = (void *)1;
static u64 (*ktime_get_ns)(void) = (void *)5;

#define TC_ACT_OK    0
#define TC_ACT_SHOT  2
/* Not a verdict: return this on every non-drop path so the lower-prio
 * filters (bpf_drop at prio 10..99) still evaluate the packet.  In
 * direct-action mode TC_ACT_OK *ends* the prio chain, so a surviving
 * packet would bypass every bpf_drop filter behind us. */
#define TC_ACT_UNSPEC (-1)

#define ETH_HLEN   14
#define ETH_P_IPV4 0x0800

/* How many catch-up steps the recurring-window walk may take per packet.
 * Must match the number of win_step() calls in the window block; the test
 * suite asserts the two stay in sync and small. */
#define WIN_CATCHUP_STEPS 16

/*
 * One draw = one atomic ticket.  The value is a deterministic mix of the
 * userspace seed and the ticket (splitmix64 finalizer), so every draw point
 * observes a distinct value — a shared xorshift state read-modify-written
 * without atomics let two CPUs draw the same number — and a fixed sequence
 * of draw points replays exactly for a given seed.
 */
static inline_always u32 prng_next(struct tc_impair_cnt *cnt)
{
    u64 t = __sync_fetch_and_add(&cnt->draw_seq, 1) + 1;
    u64 x = cnt->prng_seed + t * 0x9E3779B97F4A7C15ULL;

    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return (u32)(x >> 32);
}

/*
 * Percentage draw shared by quota and window: compare a 32-bit draw against
 * the netem-style encoding of percent (p * 2^32 / 100, 100 => ~0).
 * Returns 1 (drop) with probability pct/100.
 */
static inline_always int pct_drop(struct tc_impair_cnt *cnt, u32 pct)
{
    if (pct == 0)
        return 0;
    return prng_next(cnt) < TC_IMPAIR_PCT_ENCODE(pct);
}

/*
 * Uniform draw in [nominal-jitter, nominal+jitter] for the jittered window
 * schedule, on the whole-millisecond grid (the command surface is
 * ms-integer), clamped to >= 1 ms.  Multiply-shift maps the 32-bit draw
 * uniformly onto the span (no modulo bias); the ms grid keeps
 * rnd * span < 2^64 for every validated jitter (<= 1e9 ms).
 */
static inline_always u64 draw_range(struct tc_impair_cnt *cnt, u64 nominal_ns, u64 jitter_ns)
{
    u64 lo = nominal_ns > jitter_ns ? (nominal_ns - jitter_ns) / 1000000ULL : 1;
    u64 hi = (nominal_ns + jitter_ns) / 1000000ULL;
    u32 rnd;

    if (hi <= lo)
        return lo * 1000000ULL;
    rnd = prng_next(cnt);
    /* span+1 so the draw includes the upper endpoint: the documented
     * interval is [nominal-jitter, nominal+jitter], both ends inclusive. */
    return (lo + (((unsigned long long)rnd * (hi - lo + 1)) >> 32)) * 1000000ULL;
}

/*
 * One catch-up step for the recurring time window: the cycle the clock is
 * in, or the next one once the clock has passed the end of this one — i.e.
 * "cross off one elapsed cycle". Called WIN_CATCHUP_STEPS times in a row,
 * hand-unrolled, never in a loop: see the window block for why.
 */
static inline_always u64 win_step(u64 now, u64 start, u64 cur)
{
    return now >= start + cur ? start + cur : start;
}

/*
 * Jenkins one-at-a-time fold over the flow-mask-selected header fields.
 * Non-IP frames contribute only their MAC fields; ports only for TCP/UDP
 * over IPv4 with the header verified present. All loads are bytewise (no
 * packet-alignment assumptions).
 */
static inline_always int flow_hash(struct min_skb *ctx, u32 mask, u32 *hash_out)
{
    u8 *d = (u8 *)(unsigned long)ctx->data;
    u8 *d_end = (u8 *)(unsigned long)ctx->data_end;
    u32 h = 0;
    int i;

    /* Ethernet header must be fully present: a runt is unclassifiable and
     * must pass — returning a hash here would read as a match and drop it. */
    if (d + ETH_HLEN > d_end)
        return -1;

#define FOLD(b) do { h += (b); h += h << 10; h ^= h >> 6; } while (0)

    if (mask & 0x2)                    /* dst MAC first: frames to the same peer fold alike */
        for (i = 0; i < 6; i++)
            FOLD(d[i]);
    if (mask & 0x1)                    /* src MAC */
        for (i = 6; i < 12; i++)
            FOLD(d[i]);

    if ((u16)((d[12] << 8) | d[13]) == ETH_P_IPV4) {
        u8 *ip = d + ETH_HLEN;

        if (ip + 20 > d_end)
            goto out;                  /* truncated IPv4 header: fold MACs only */
        /* All pointer arithmetic below uses FIXED offsets: variable-offset
         * packet-pointer arithmetic (ip + ihl) is prohibited for !root by
         * the verifier, and uBridge must load as a setcap'd non-root
         * process. Consequence: L4 ports are folded only for IHL == 20
         * (no IP options) — packets with IP options fold MACs + proto. */
        if (mask & 0x10)
            FOLD(ip[9]);
        if ((ip[0] & 0xf) == 5 && ip + 28 <= d_end) {
            u8 proto = ip[9];
            if (proto == 6 || proto == 17) {   /* TCP / UDP */
                u8 *l4 = ip + 20;
                if (mask & 0x4) {
                    FOLD(l4[0]);
                    FOLD(l4[1]);
                }
                if (mask & 0x8) {
                    FOLD(l4[2]);
                    FOLD(l4[3]);
                }
            }
        }
    }
out:
    h += h << 3;
    h ^= h >> 11;
    h += h << 15;
    *hash_out = h;
    return 0;
}

SEC("tc_impair")
int tc_impair_prog(struct min_skb *ctx)
{
    struct tc_impair_cfg *cfg;
    struct tc_impair_cnt *cnt;
    u32 key = 0;
    u64 now;

    cfg = map_lookup_elem(&cfg_map, &key);
    if (!cfg)
        return TC_ACT_UNSPEC;
    cnt = map_lookup_elem(&cnt_map, &key);
    if (!cnt)
        return TC_ACT_UNSPEC;

    /* Lazy reset: userspace bumps cfg->reset_seq together with every mode
     * command's single cfg write and never writes CNT after the load-time
     * seed (its old read-modify-write replayed a stale snapshot over
     * counters and draws the program was advancing concurrently).  The
     * zeroing is idempotent if two CPUs apply it; a packet racing the very
     * first post-reset one can land its atomic add before the zeroing — a
     * ±1 counter start, invisible to the modes' semantics. */
    if (cnt->seen_seq != cfg->reset_seq) {
        cnt->seen_seq = cfg->reset_seq;
        if (cfg->reset_mask & TC_IMPAIR_RESET_NTH)
            cnt->nth_state = 0;
        if (cfg->reset_mask & TC_IMPAIR_RESET_QUOTA) {
            cnt->packets = 0;
            cnt->bytes = 0;
        }
        if (cfg->reset_mask & TC_IMPAIR_RESET_WINDOW) {
            cnt->win_start_cur_ns = cfg->win_start_ns;
            cnt->win_outage_cur_ns = cfg->win_len_ns;
            cnt->win_period_cur_ns = cfg->win_period_ns;
        }
    }

    /* 1. nth: drop every Nth packet — exact across CPUs via atomic add, and
     * exact past 2^32 too: the BPF ISA has a native 64-bit modulo
     * (BPF_ALU64|BPF_MOD — clang emits a mod instruction, not a libcall),
     * so the counter is used at full width. */
    if (cfg->nth) {
        u64 n = __sync_fetch_and_add(&cnt->nth_state, 1) + 1;
        if (n % cfg->nth == 0)
            return TC_ACT_SHOT;
    }

    /* 2. quota: after quota_bytes of traffic (counted from the last
     * quota_drop enable), drop each packet with quota_pct probability.
     * Only traffic that survived nth is counted (evaluation is ordered). */
    if (cfg->quota_bytes) {
        __sync_fetch_and_add(&cnt->packets, 1);
        if (__sync_fetch_and_add(&cnt->bytes, ctx->len) + ctx->len
                >= cfg->quota_bytes
            && pct_drop(cnt, cfg->quota_pct))
            return TC_ACT_SHOT;
    }

    /* 3. window: period 0 = a single [start, start+len) outage — packets
     * pass before AND after it. With a period, outages recur: inside the
     * current cycle's [start, start+outage) drop with win_pct, in the rest
     * of the cycle pass. jitter > 0 re-draws the cycle's outage and period
     * uniformly in nominal ±jitter ONCE, on entering it (jitter 0 consumes
     * no PRNG values and is exactly the fixed schedule). The catch-up is
     * straight-line and draw-free — the draws stay out of it, an in-loop
     * draw chain is what the verifier rejects the whole program for
     * (ebpf=0). Traffic pausing across cycles still lands in the right one:
     * the walk is resumable, each further packet advances it up to
     * WIN_CATCHUP_STEPS more cycles.  The advancing start lives in CNT
     * (runtime state): a cfg rewrite by an unrelated mode command cannot
     * rewind the phase; window_drop (re)seeds it via TC_IMPAIR_RESET_WINDOW
     * and remains the way to re-anchor a pathological pause. */
    if (cfg->win_len_ns) {
        u64 start = cnt->win_start_cur_ns;
        u64 out_len = cnt->win_outage_cur_ns ? cnt->win_outage_cur_ns
                                             : cfg->win_len_ns;

        now = ktime_get_ns();
        if (cfg->win_period_ns) {
            u64 cur = cnt->win_period_cur_ns ? cnt->win_period_cur_ns
                                             : cfg->win_period_ns;
            int advanced;

            /* Straight-line catch-up: NO loop here, not even a bounded one.
             * Production ubridge never runs as root (it carries CAP_BPF),
             * and the verifier's non-root path does NOT keep a loop
             * counter's constant bound — it sees a wide scalar (observed:
             * R4=scalar(smax=umax32=0xfffff086) for a 127-trip counter),
             * unrolls the loop as if unbounded and piles up unexplored
             * branch states until push_stack() exceeds
             * BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192) and rejects the WHOLE
             * program with E2BIG ("The sequence of N jumps is too complex",
             * N = pending states, not jumps), taking all four modes down
             * since they share this one program. The same binary run as
             * root verifies fine — which is exactly why sudo-only testing
             * never caught it. So: advance, then retry, a fixed number of
             * times, by hand.
             *
             * The guard keeps the hot path at ONE comparison: in steady
             * state only the packet that crosses a cycle boundary enters
             * these steps. The walk is RESUMABLE (start is stored back), so
             * a pause of N cycles re-syncs within ceil(N /
             * WIN_CATCHUP_STEPS) further packets — and while it is behind,
             * the window is in the past, so packets are classified "outside
             * the window" (pass), the safe way. Re-issuing window_drop
             * re-anchors the phase if a pause was pathological. */
            if (now >= start + cur) {
                u64 base = start;

                /* WIN_CATCHUP_STEPS calls, hand-unrolled */
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                start = win_step(now, start, cur);
                advanced = start != base;
            } else {
                advanced = 0;
            }
            if (advanced) {
                cnt->win_start_cur_ns = start;
                if (cfg->win_jitter_ns) {
                    u64 o = draw_range(cnt, cfg->win_len_ns,
                                       cfg->win_jitter_ns);
                    u64 p = draw_range(cnt, cfg->win_period_ns,
                                       cfg->win_jitter_ns);

                    out_len = o;
                    cur = p;
                    if (out_len > cur)    /* keep cycles non-overlapping */
                        out_len = cur;
                    cnt->win_outage_cur_ns = out_len;
                }
                cnt->win_period_cur_ns = cur;
            }
            if (now >= start && now < start + out_len
                && pct_drop(cnt, cfg->win_pct))
                return TC_ACT_SHOT;
        } else if (now >= start && now < start + cfg->win_len_ns
                   && pct_drop(cnt, cfg->win_pct)) {
            return TC_ACT_SHOT;
        }
    }

    /* 4. flow: hash the selected fields; remainder 0 modulo target drops.
     * A frame too short to classify (no full Ethernet header) passes. */
    if (cfg->flow_mask && cfg->flow_target) {
        u32 hash;

        if (flow_hash(ctx, cfg->flow_mask, &hash) == 0
            && hash % cfg->flow_target == 0)
            return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
