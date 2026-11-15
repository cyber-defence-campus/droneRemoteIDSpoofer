"""Summarise a scenario run (JSONL logs written by authority, senders and receivers).

    python bench/analyze.py results/basic-<timestamp>
"""
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path


def stats(xs):
    if not xs:
        return "-"
    xs = sorted(xs)
    return f"n={len(xs):4d} median={xs[len(xs) // 2]:9.1f} p95={xs[int(0.95 * (len(xs) - 1))]:9.1f}"


def load(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main(run: Path):
    report = {}
    print(f"# {run.name}\n")

    print("## Senders")
    for f in sorted(run.glob("sender-*.jsonl")):
        ev = load(f)
        tx = [e for e in ev if e["event"] == "tx"]
        span = (tx[-1]["t"] - tx[0]["t"]) if len(tx) > 1 else 1
        by_kind = Counter()
        for e in tx:
            by_kind[e["kind"]] += e["bytes"]
        sessions = [e for e in ev if e["event"] == "session_start"]
        print(f"{f.stem}: sessions={len(sessions)} tx={sum(by_kind.values()) / span:.0f} B/s "
              f"(data {by_kind['data'] / span:.0f}, heartbeat {by_kind['heartbeat'] / span:.0f}) "
              f"core={sessions[0]['core_bytes'] if sessions else '-'} B "
              f"refused={'yes' if any(e['event'] == 'enrol_refused' for e in ev) else 'no'}")
        report[f.stem] = {"Bps": sum(by_kind.values()) / span, "sessions": len(sessions)}
    sign = defaultdict(list)
    for f in run.glob("sender-*.jsonl"):
        for e in load(f):
            if e["event"] in ("group_sign", "session_keygen", "enrol"):
                sign[e["event"]].append(e["us"])
            elif e["event"] == "pack_sign":
                sign[f"pack_sign/{e['kind']}"].append(e["us"])
    for k, v in sorted(sign.items()):
        print(f"  {k:22s} µs {stats(v)}")

    print("\n## Receivers")
    for f in sorted(run.glob("*.jsonl")):
        if f.stem.startswith(("sender-", "authority")):
            continue
        ev = load(f)
        start = ev[0]["t"] if ev else 0
        rx = [e for e in ev if e["event"] == "rx"]
        counts = Counter(e["status"] for e in rx)
        print(f"{f.stem}: {dict(counts)}")
        per_status = defaultdict(list)
        for e in rx:
            per_status[e["status"]].append(e["us"])
        for k in ["verified", "core_verified", "unknown_session", "wrong_epoch", "future_epoch"]:
            if per_status[k]:
                print(f"  rx[{k:15s}] µs {stats(per_status[k])}")
        gv = [e["us"] for e in ev if e["event"] == "group_verify"]
        print(f"  group_verify          µs {stats(gv)}")
        sv = [e for e in ev if e["event"] == "session_verified"]
        # Time from receiver start to the first verified session of drones already flying.
        first = sorted(e["t"] - start for e in sv)[:3]
        print(f"  first verified sessions after start (s): {[round(x, 2) for x in first]}")
        opened = [e for e in ev if e["event"] == "opened"]
        if opened:
            print(f"  open RTT              µs {stats([e['open_rtt_us'] for e in opened])}")
            print(f"  decrypt RTT           µs {stats([e['decrypt_rtt_us'] for e in opened])}")
            members = Counter((e["epoch"], e["member"]) for e in opened)
            print(f"  opened (epoch, member): {dict(members)}")
        report[f.stem] = {"status_counts": dict(counts), "group_verify_us": gv}

    auth = run / "authority.jsonl"
    if auth.exists():
        print("\n## Authority")
        ev = load(auth)
        for name in ["group_setup", "join_mgr", "open"]:
            print(f"  {name:22s} µs {stats([e['us'] for e in ev if e['event'] == name])}")
    audit = run / "audit.json"
    if audit.exists():
        a = json.loads(audit.read_text())
        print(f"  audit log: {len(a['entries'])} entries, chain valid={a['valid']}")
    (run / "analysis.json").write_text(json.dumps(report, indent=1))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
