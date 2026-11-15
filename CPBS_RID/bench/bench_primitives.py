"""Microbenchmarks of the CPBS pipeline (Python orchestration over C crypto) and byte overhead.

    python bench/bench_primitives.py [--iters 500] [--out results/bench]

Writes primitives.tsv (timings: median / p95 / mean in µs) and overhead.tsv.
"""
import argparse
import statistics
import time
from pathlib import Path

from cpbs.clock import ManualClock
from cpbs.config import Config
from cpbs.crypto import seal
from cpbs.crypto.groupsig import GroupScheme, join_local
from cpbs.crypto.session import SessionKey, verify
from cpbs.odid import messages as odid
from cpbs.protocol import framing
from cpbs.protocol.core import (FIELD_SERIAL, encode_fields)
from cpbs.protocol.session import SenderSession
from cpbs.protocol.verifier import Verifier

SERIAL = b"1581F5FHC23400000001"   # 20 chars, CTA-2063-A maximum


def measure(fn, iters):
    xs = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        fn()
        xs.append((time.perf_counter_ns() - t0) / 1000)
    xs.sort()
    return xs[len(xs) // 2], xs[int(0.95 * (len(xs) - 1))], statistics.fmean(xs)


def c_enc_fields(membership):
    return encode_fields({FIELD_SERIAL: SERIAL})  # same in both models


def bench_scheme(name, iters, rows, overhead):
    scheme = GroupScheme(name)
    state = scheme.setup()
    memkey = join_local(scheme, state)
    keys = scheme.signing_keys(memkey, state.grpkey)
    gpk = scheme.verifying_key(state.grpkey)
    clock = ManualClock()
    _, rpk = seal.generate_keypair()
    t = clock.now()
    loc = odid.build_location_vector(473_766_000, 85_417_000, 90, t, speed=8, height=60)
    sysm = odid.build_system(473_760_000, 85_410_000, t)

    def row(op, fn, n=iters):
        rows.append((name, op, *measure(fn, n)))

    msg = bytes(300)
    sig = scheme.sign(None, None, msg, keys=keys)
    row("group_sign", lambda: scheme.sign(None, None, msg, keys=keys))
    row("group_verify", lambda: scheme.verify(sig, msg, None, grpkey=gpk))
    row("session_start (keygen+seal+group_sign)",
        lambda: SenderSession(scheme, keys, 0, seal.seal(rpk, c_enc_fields("drone")), t))

    s = SenderSession(scheme, keys, 0, seal.seal(rpk, c_enc_fields("drone")), t)
    row("sender data_pack", lambda: s.data_pack(loc, sysm, t))
    row("sender heartbeat", lambda: s.heartbeat(t))

    # Receiver: steady state (cached session) and new session (heartbeat: Wrapper + GroupVerify)
    cfg = Config(scheme=name, max_new_sessions_per_s=1e9)
    v = Verifier(scheme, cfg, clock)
    v.set_group_key(0, state.grpkey)
    v.handle(s.heartbeat(t))
    packs = iter([s.data_pack(loc, sysm, t) for _ in range(iters)])
    row("receiver verified data pack", lambda: v.handle(next(packs)))
    row("receiver parse only", lambda: framing.parse_pack(s.data_pack(loc, sysm, t)))

    hbs = [SenderSession(scheme, keys, 0, seal.seal(rpk, c_enc_fields("drone")), t).heartbeat(t)
           for _ in range(min(iters, 200))]
    it = iter(hbs)

    def new_session():
        assert v.handle(next(it)).status == "core_verified"
    row("receiver new session (Core)", new_session, len(hbs))

    idx_sig = s.core.group_sig
    row("open (1 member)", lambda: scheme.open(idx_sig, state), min(iters, 50))

    # Byte overhead per membership mode
    for membership in ["drone", "operator"]:
        ss = SenderSession(scheme, keys, 0, seal.seal(rpk, c_enc_fields(membership)), t)
        hb = ss.heartbeat(t)
        dp = ss.data_pack(loc, sysm, t)
        overhead.append({
            "scheme": name, "membership": membership,
            "group_sig_B": len(ss.core.group_sig), "c_enc_B": len(ss.core.c_enc),
            "core_B": len(ss.core_bytes), "heartbeat_B": len(hb),
            "data_pack_B": len(dp), "data_pack_msgs": (len(dp) - 3) // 25,
        })


def baseline_overhead():
    """Plain (unauthenticated) ODID packs: US = Basic ID + Location + System; EU adds Operator ID."""
    return {"drone": 3 + 3 * 25, "operator": 3 + 4 * 25}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=500)
    ap.add_argument("--out", default="results/bench")
    ap.add_argument("--heartbeat-s", type=float, default=3.0)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    rows, overhead = [], []
    sk = SessionKey()
    m = bytes(200)
    sig = sk.sign(m)
    rsk, rpk = seal.generate_keypair()
    ct = seal.seal(rpk, m[:40])
    rows.append(("ed25519", "keygen", *measure(SessionKey, a.iters)))
    rows.append(("ed25519", "sign (200 B)", *measure(lambda: sk.sign(m), a.iters)))
    rows.append(("ed25519", "verify (200 B)", *measure(lambda: verify(sk.pk, m, sig), a.iters)))
    rows.append(("sealed_box", "seal (40 B)", *measure(lambda: seal.seal(rpk, m[:40]), a.iters)))
    rows.append(("sealed_box", "unseal (40 B)", *measure(lambda: seal.unseal(rsk, ct), a.iters)))
    for name in ["bbs04"]:
        bench_scheme(name, a.iters, rows, overhead)

    with open(out / "primitives.tsv", "w") as f:
        f.write("component\toperation\tmedian_us\tp95_us\tmean_us\n")
        for r in rows:
            f.write(f"{r[0]}\t{r[1]}\t{r[2]:.1f}\t{r[3]:.1f}\t{r[4]:.1f}\n")

    base = baseline_overhead()
    with open(out / "overhead.tsv", "w") as f:
        cols = list(overhead[0].keys()) + ["baseline_pack_B", "cpbs_Bps", "baseline_Bps", "increase_pct",
                                           "cpbs_frames_per_s", "baseline_frames_per_s"]
        f.write("\t".join(cols) + "\n")
        for o in overhead:
            b = base[o["membership"]]
            cpbs_bps = o["data_pack_B"] + o["heartbeat_B"] / a.heartbeat_s
            o.update(baseline_pack_B=b, cpbs_Bps=round(cpbs_bps, 1), baseline_Bps=b,
                     increase_pct=round(100 * (cpbs_bps / b - 1), 1),
                     cpbs_frames_per_s=round(1 + 1 / a.heartbeat_s, 2),  # data pack + heartbeat frames
                     baseline_frames_per_s=1)
            f.write("\t".join(str(o[c]) for c in cols) + "\n")

    for p in ["primitives.tsv", "overhead.tsv"]:
        print(f"== {p}\n" + (out / p).read_text())


if __name__ == "__main__":
    main()
