#!/usr/bin/env python3
"""Analyze inter-packet timing of WiFi RID (Open Drone ID) beacons in a pcapng.

Self-contained pcapng + radiotap + 802.11 parser (no scapy/tshark needed).
Selects beacons carrying the ASTM Open Drone ID vendor IE (OUI fa:0b:bc),
groups them by transmitter MAC, and reports inter-arrival statistics.

Usage: python3 analyze_rid_timing.py <capture.pcapng>
"""
import struct
import sys
from collections import defaultdict

ASTM_OUI = b"\xfa\x0b\xbc"  # ASTM International, used by Open Drone ID


def parse_epbs(path):
    """Yield (src_mac, t_seconds, is_rid) for every 802.11 frame."""
    buf = open(path, "rb").read()
    off, n, ts_resol = 0, len(buf), 1e-6
    while off + 12 <= n:
        bt, bl = struct.unpack_from("<II", buf, off)
        if bl < 12 or off + bl > n:
            break
        if bt == 1:  # Interface Description Block -> timestamp resolution option
            opt = off + 16
            while opt + 4 <= off + bl - 4:
                code, olen = struct.unpack_from("<HH", buf, opt)
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    r = buf[opt + 4]
                    ts_resol = 2 ** -(r & 0x7F) if r & 0x80 else 10 ** -r
                opt += 4 + ((olen + 3) // 4 * 4)
        elif bt == 6:  # Enhanced Packet Block
            _, th, tl, caplen = struct.unpack_from("<IIII", buf, off + 8)
            t = ((th << 32) | tl) * ts_resol
            pkt = buf[off + 28 : off + 28 + caplen]
            if len(pkt) >= 4:
                rtlen = struct.unpack_from("<H", pkt, 2)[0]
                d = pkt[rtlen:]
                if len(d) >= 16:
                    fctl = d[0]
                    is_beacon = ((fctl >> 2) & 3, (fctl >> 4) & 0xF) == (0, 8)
                    src = d[10:16].hex(":")
                    rid = is_beacon and _has_astm_ie(d)
                    yield src, t, rid
        off += bl


def _has_astm_ie(d):
    p = 36  # 24-byte mgmt hdr + 12-byte fixed beacon params
    while p + 2 <= len(d):
        tag, tlen = d[p], d[p + 1]
        if tag == 221 and d[p + 2 : p + 5] == ASTM_OUI:
            return True
        p += 2 + tlen
    return False


def stats(deltas):
    deltas = sorted(deltas)
    k = len(deltas)
    mean = sum(deltas) / k
    var = sum((x - mean) ** 2 for x in deltas) / k if k > 1 else 0.0
    return {
        "count": k + 1,
        "mean_ms": mean * 1e3,
        "std_ms": var**0.5 * 1e3,
        "min_ms": deltas[0] * 1e3,
        "median_ms": deltas[k // 2] * 1e3,
        "max_ms": deltas[-1] * 1e3,
        "rate_hz": 1.0 / mean if mean else float("inf"),
    }


def cluster_1d(xs, centers, iters=50):
    """Tiny 1-D k-means; returns (centers, labels-per-point)."""
    centers = list(centers)
    labels = [0] * len(xs)
    for _ in range(iters):
        groups = defaultdict(list)
        for i, x in enumerate(xs):
            c = min(range(len(centers)), key=lambda j: abs(x - centers[j]))
            labels[i] = c
            groups[c].append(x)
        centers = [sum(g) / len(g) if g else centers[j] for j, g in sorted(groups.items())]
    return centers, labels


def predictability(deltas):
    """Treat intervals as a symbol stream, find the repeating cycle, and report
    how deterministic the transmit schedule is."""
    dms = [x * 1e3 for x in deltas]
    k = min(len(set(round(x, 0) for x in dms)), 3) or 1
    # seed from quantiles (robust to a few long-gap outliers, and separates
    # genuinely close modes better than uniform min..max seeding)
    sd = sorted(dms)
    seeds = [sd[min(len(sd) - 1, int(len(sd) * (i + 0.5) / k))] for i in range(k)]
    centers, labels = cluster_1d(dms, seeds)
    order = sorted(range(k), key=lambda j: centers[j])  # ascending by duration
    name = {order[i]: "SMLXYZ"[i] for i in range(k)}
    syms = [name[c] for c in labels]

    print("  interval modes (ms):")
    for j in order:
        g = [x for x, c in zip(dms, labels) if c == j]
        mean = sum(g) / len(g)
        std = (sum((x - mean) ** 2 for x in g) / len(g)) ** 0.5
        print(f"    {name[j]}: n={len(g):3d}  {mean:7.2f} ± {std:5.2f} ms  [{min(g):.1f}, {max(g):.1f}]")

    # dominant successor of each symbol = the cycle rule
    from collections import Counter

    trans = Counter(zip(syms, syms[1:]))
    succ = {}
    for a in sorted(set(syms)):
        row = {b: trans.get((a, b), 0) for b in sorted(set(syms))}
        succ[a] = max(row, key=row.get)
    ok = sum(1 for a, b in zip(syms, syms[1:]) if b == succ[a])
    n = len(syms) - 1
    cyc = " -> ".join(succ[s] for s in _walk_cycle(succ))
    print(f"  cycle rule: {cyc} -> ...   holds {ok}/{n} = {ok / n * 100:.2f}% of transitions")
    drops = sum(1 for a, b in zip(syms, syms[1:]) if b != succ[a])
    print(f"  phase slips / dropped beacons: {drops} ({drops / n * 100:.1f}%)")
    # period from per-mode medians, not means: a few drop-merged intervals land in the
    # longest (L) bucket and inflate its mean, overstating the cycle; the median is robust.
    meds = []
    for j in order:
        g = sorted(x for x, cc in zip(dms, labels) if cc == j)
        meds.append(g[len(g) // 2])
    period = sum(meds)
    print(f"  full cycle ~{period:.0f} ms (~{1000 / period:.2f} Hz)  -> next beacon predictable to sub-ms between slots\n")


def _walk_cycle(succ):
    start = min(succ)
    out, cur = [start], succ[start]
    while cur != start and len(out) < len(succ):
        out.append(cur)
        cur = succ[cur]
    return out


def _fit_period(start_times, seed=0.6399):
    """Drop-aware least-squares period: assign each cycle-start an integer cycle
    index by rounding to the seed period, then fit; iterate so the count is
    self-consistent. Returns (period_s, t0, cycle_indices)."""
    t0 = start_times[0]
    period = seed
    cyc = [round((s - t0) / period) for s in start_times]
    for _ in range(8):
        cm = sum(cyc) / len(cyc)
        tm = sum(start_times) / len(start_times)
        denom = sum((c - cm) ** 2 for c in cyc)
        if denom == 0:
            break
        period = sum((c - cm) * (s - tm) for c, s in zip(cyc, start_times)) / denom
        cyc = [round((s - t0) / period) for s in start_times]
    return period, t0, cyc


def listen_requirement(ts, slot_offsets=(0.0, 80.0, 320.0),
                       durations=(0.7, 1.0, 1.3, 1.6, 1.9, 2.2, 2.6, 3.2)):
    """How long must the attacker listen (once) to reach the drift floor? Sweeps the
    lock DURATION over every start position and reports median / 90th-percentile
    open-loop drift over the whole capture, for two period estimators: fitting from
    cycle-starts only, and from all three beacons per cycle (3x the points over the
    same baseline). The all-beacon fit reaches the floor from a shorter listen, so it
    is the cheaper way to the same accuracy."""
    ts = sorted(ts)
    dms = [(b - a) * 1e3 for a, b in zip(ts, ts[1:])]
    cen = [79.9, 240.0, 320.0]
    syms = ["SML"[min(range(3), key=lambda i: abs(x - cen[i]))] for x in dms]
    starts = [ts[i] for i, s in enumerate(syms) if s == "S"]
    if len(starts) < 3:
        return
    offs = sorted(slot_offsets)
    guard = min(b - a for a, b in zip(offs, offs[1:])) / 2.0
    p_full = _fit_period(starts)[0]

    def drift(t0, period):
        worst = 0.0
        for t in ts:
            ph = (t - t0 - int((t - t0 + 0.040) // period) * period) * 1e3
            worst = max(worst, abs(ph - min(offs, key=lambda o: abs(ph - o))))
        return worst

    def fit(t0, dur, all_beacons):
        xs, ys = [], []
        for t in ts:
            if not (t0 <= t <= t0 + dur):
                continue
            k = int((t - t0 + 0.040) // p_full)
            ph = (t - t0 - k * p_full) * 1e3
            slot = min(offs, key=lambda o: abs(ph - o))
            if all_beacons:
                xs.append(k + slot / (p_full * 1e3))  # fractional cycle position
                ys.append(t)
            elif abs(ph - offs[0]) < guard:  # cycle-starts only
                xs.append(float(k))
                ys.append(t)
        if len({round(x, 4) for x in xs}) < 2:
            return None
        mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
        den = sum((x - mx) ** 2 for x in xs)
        return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den if den else None

    def pct(v, q):
        v = sorted(v)
        return v[min(len(v) - 1, int(q / 100 * len(v)))]

    print(f"  minimal listen to reach the drift floor (guard = {guard:.0f} ms):")
    print("    listen(s)  cycle-start fit med/p90   all-beacon fit med/p90")
    for dur in durations:
        out = {}
        for mode in (False, True):
            ds = [drift(t0, fit(t0, dur, mode)) for t0 in starts
                  if t0 + dur <= ts[-1] - 5 and fit(t0, dur, mode)]
            out[mode] = (pct(ds, 50), pct(ds, 90)) if ds else (float("nan"), float("nan"))
        print(f"    {dur:5.1f}      {out[False][0]:5.1f} / {out[False][1]:6.1f} ms        "
              f"{out[True][0]:5.1f} / {out[True][1]:6.1f} ms")
    print()


def openloop_drift(ts, airtime_ms=1.5, slot_offsets=(0.0, 80.0, 320.0), locks=(1, 2, 3, 5)):
    """Fire-and-forget attack model: lock the schedule on the first N cycles, then
    predict open-loop with NO re-fitting for the rest of the capture. A suppression
    or overshadow attacker cannot listen mid-attack -- any silent interval lets the
    beacon it is masking reach the receiver -- so it locks once and runs blind.

    Every printed number is derived here. For each lock length N it reports: the
    period-fit error |P_hat - P| against the whole-capture period P; the worst-case
    timing error (drift) over the whole run when locking at the start; the collision
    window (2*drift, because the sign of the period error is unknown without a second
    observation, plus the beacon airtime) and its duty cycle over the three slots per
    cycle; and -- by sliding the lock over every start position -- the median and
    90th-percentile drift, so the single figure is read against its spread. The guard
    is half the shortest inter-slot gap: the drift at which a predicted frame would be
    assigned to the neighbouring slot, equivalently at which adjacent jam windows merge."""
    ts = sorted(ts)
    dms = [(b - a) * 1e3 for a, b in zip(ts, ts[1:])]
    cen = [79.9, 240.0, 320.0]
    syms = ["SML"[min(range(3), key=lambda i: abs(x - cen[i]))] for x in dms]
    starts = [ts[i] for i, sym in enumerate(syms) if sym == "S"]
    if len(starts) < 2:
        return
    offs = sorted(slot_offsets)
    guard = min(b - a for a, b in zip(offs, offs[1:])) / 2.0  # half shortest gap
    p_full, _, cyc_full = _fit_period(starts)
    ncyc = max(cyc_full)
    cycle_ms = p_full * 1e3
    flight = ts[-1] - ts[0]

    def drift_for(t0, period):  # worst |within-cycle offset - nearest slot| over all beacons, ms
        worst = 0.0
        for t in ts:
            rel = t - t0
            ph = (rel - int((rel + 0.040) // period) * period) * 1e3
            worst = max(worst, abs(ph - min(offs, key=lambda o: abs(ph - o))))
        return worst

    def pct(xs, q):
        xs = sorted(xs)
        return xs[min(len(xs) - 1, int(q / 100 * len(xs)))]

    print(f"  open-loop (no re-fit) fire-and-forget prediction  [P={cycle_ms:.3f} ms, "
          f"{ncyc} cycles, guard={guard:.0f} ms]:")
    for n in locks:
        lock_starts = [s for s, c in zip(starts, cyc_full) if c <= n]
        if len(lock_starts) < 2:
            continue
        p_lock = _fit_period(lock_starts)[0]
        eps = abs(p_lock - p_full) * 1e3
        drift = drift_for(lock_starts[0], p_lock)
        window = 2 * drift + airtime_ms
        duty = 3 * window / cycle_ms * 100
        sweep = []
        for c0 in range(ncyc - n):
            win_starts = [s for s, c in zip(starts, cyc_full) if c0 <= c <= c0 + n]
            if len(win_starts) >= 2:
                sweep.append(drift_for(win_starts[0], _fit_period(win_starts)[0]))
        med, p90 = (pct(sweep, 50), pct(sweep, 90)) if sweep else (float("nan"), float("nan"))
        flag = "   <-- exceeds guard" if drift > guard else ("   <-- near guard" if drift > 0.7 * guard else "")
        print(
            f"    lock {n}c (~{n * cycle_ms / 1000:.1f}s): |P_hat-P|={eps:5.3f} ms/cyc  "
            f"drift(start) {drift:5.1f} ms  window {window:5.1f} ms  duty {duty:4.1f}%  "
            f"| sweep median {med:4.1f} / p90 {p90:5.1f} ms{flag}"
        )
    print()


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "evaluation/data/RID_anechoicchamber.pcapng"
    times = defaultdict(list)
    total = 0
    for src, t, rid in parse_epbs(path):
        total += 1
        if rid:
            times[src].append(t)

    rid_total = sum(len(v) for v in times.values())
    print(f"{path}")
    print(f"frames: {total}   RID beacons: {rid_total}   transmitters: {len(times)}\n")
    for src, ts in sorted(times.items(), key=lambda kv: -len(kv[1])):
        ts.sort()
        deltas = [b - a for a, b in zip(ts, ts[1:])]
        if not deltas:
            print(f"{src}: 1 beacon (no intervals)")
            continue
        s = stats(deltas)
        span = ts[-1] - ts[0]
        print(f"transmitter {src}  ({s['count']} beacons over {span:.2f}s)")
        print(
            f"  interval  mean {s['mean_ms']:.2f} ms  std {s['std_ms']:.2f} ms  "
            f"median {s['median_ms']:.2f} ms  min {s['min_ms']:.2f}  max {s['max_ms']:.2f}"
        )
        print(f"  beacon rate ~{s['rate_hz']:.2f} Hz")
        predictability(deltas)
        openloop_drift(ts)
        listen_requirement(ts)


if __name__ == "__main__":
    main()
