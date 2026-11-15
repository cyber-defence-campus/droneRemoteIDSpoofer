"""Run a CPBS scenario locally: authority + receivers + drones as separate processes.

    python bench/run_scenario.py scenarios/basic.json [--out results/]

Scenario JSON:
  config      Config fields (cpbs/config.py); receivers are filled in here
  duration_s  total run time
  drones      [{"serial", "operator", "start_s"?}]
  receivers   [{"name", "start_s"?, "trusted"?}]
  events      [{"at_s", "action": "revoke"|"rollover", "member"?}]
Each process writes <out>/<name>.jsonl; receivers also write <name>.summary.json.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
BASE_PORT = 8472


def wait_for(url: str, timeout: float = 20.0) -> None:
    t_end = time.time() + timeout
    while time.time() < t_end:
        try:
            httpx.get(url + "/epoch", timeout=1).raise_for_status()
            return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise RuntimeError("authority did not start")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario")
    ap.add_argument("--out", default=str(ROOT / "results"))
    a = ap.parse_args()

    sc = json.loads(Path(a.scenario).read_text())
    out = Path(a.out) / f"{Path(a.scenario).stem}-{datetime.now():%Y%m%d-%H%M%S}"
    out.mkdir(parents=True)
    cfg = dict(sc.get("config", {}))
    cfg["receivers"] = [f"127.0.0.1:{BASE_PORT + i}" for i in range(len(sc["receivers"]))]
    cfg_path = out / "config.json"
    cfg_path.write_text(json.dumps({"config": cfg}, indent=2))
    duration = sc["duration_s"]
    url = cfg.get("authority_url", "http://127.0.0.1:8471")
    py = sys.executable

    # Shared time origin so every process prints on the same time axis.
    t0 = time.time()
    os.environ["CPBS_T0"] = str(t0)
    from cpbs.console import say  # imported after CPBS_T0 is set
    say("scenario", f"{Path(a.scenario).stem}: {len(sc['drones'])} drones, {len(sc['receivers'])} receivers, "
                    f"{duration}s, scheme={cfg.get('scheme', 'bbs04')}, membership={cfg.get('membership', 'drone')}")
    if sc.get("description"):
        say("scenario", sc["description"])

    procs = [subprocess.Popen([py, "-m", "cpbs.authority.service", "--scheme", cfg.get("scheme", "bbs04"),
                               "--port", url.rsplit(":", 1)[1], "--metrics", str(out / "authority.jsonl")],
                              cwd=ROOT)]
    try:
        wait_for(url)
        pending = []
        for i, r in enumerate(sc["receivers"]):
            args = [py, "-m", "cpbs.receiver.main", "--config", str(cfg_path), "--name", r["name"],
                    "--listen", cfg["receivers"][i], "--metrics", str(out / f"{r['name']}.jsonl"),
                    "--summary", str(out / f"{r['name']}.summary.json")]
            args += ["--trusted"] if r.get("trusted") else []
            pending.append((r.get("start_s", 0), args, duration - r.get("start_s", 0)))
        for i, d in enumerate(sc["drones"]):
            args = [py, "-m", "cpbs.sender.main", "--config", str(cfg_path), "--serial", d["serial"],
                    "--operator", d.get("operator", "CHEop000000000"), "--seed", str(i),
                    "--lat", str(47.37 + 0.01 * i), "--lon", str(8.54 + 0.01 * i),
                    "--metrics", str(out / f"sender-{d['serial']}.jsonl")]
            pending.append((d.get("start_s", 0.5), args, duration - d.get("start_s", 0.5) - 0.5))
        actions = [(e["at_s"], e) for e in sc.get("events", [])]

        timeline = sorted([(t, "proc", (args, dur)) for t, args, dur in pending]
                          + [(t, "event", e) for t, e in actions], key=lambda x: x[0])
        for at, what, item in timeline:
            time.sleep(max(0.0, t0 + at - time.time()))
            if what == "proc":
                args, dur = item
                role = "receiver" if "cpbs.receiver.main" in args else "drone"
                ident = args[args.index("--name" if role == "receiver" else "--serial") + 1]
                say("scenario", f"starting {role} {ident}" + (" (trusted)" if "--trusted" in args else ""))
                procs.append(subprocess.Popen(args + ["--duration", str(dur)], cwd=ROOT))
            else:
                if item["action"] == "revoke":
                    httpx.post(f"{url}/revoke/{item['member']}").raise_for_status()
                elif item["action"] == "rollover":
                    httpx.post(f"{url}/rollover").raise_for_status()
                say("scenario", f"event: {item['action']} {item.get('member', '')}".rstrip())

        for p in procs[1:]:
            p.wait(timeout=duration + 30)
        (out / "audit.json").write_text(json.dumps(httpx.get(f"{url}/audit").json(), indent=2))
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            p.wait(timeout=10)
    say("scenario", f"done; results in {out}")


if __name__ == "__main__":
    main()
