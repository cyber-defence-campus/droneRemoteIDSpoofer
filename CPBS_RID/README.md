# CPBS Remote ID: proof of concept

Local proof of concept of the Conditionally Private Broadcasting Scheme
(design notes: [CONDITIONALLY_PRIVATE_BROADCASTING_SCHEME.MD](CONDITIONALLY_PRIVATE_BROADCASTING_SCHEME.MD)).
Drones broadcast ASTM F3411-22a message packs that are authenticated with a
per-session Ed25519 key. The session key is bound to an anonymous,
openable group signature (IBM libgroupsig, BBS04 on BLS12-381).
Everything runs locally as separate processes over UDP; nothing is sent over the air.

## Architecture

Every actor is its own OS process (separate interpreters, so the GIL does not
distort timings), started by `bench/run_scenario.py`:

```
                         bench/run_scenario.py  (starts processes, fires revoke/rollover events)
                                   │
        ┌──────────────────────────┼─────────────────────────────────────────┐
        ▼                          ▼                                         ▼
┌────────────────┐        ┌──────────────────┐                     ┌──────────────────┐
│ Authority      │◄─HTTP──│ Sender SN-001    │──UDP: message pack─►│ Receiver ur-early│ :8472
│ (FastAPI,:8471)│  TCP   │ Sender SN-002    │   (one copy per     │ Receiver ur-late │ :8473
│ issuer, opener,│        │ Sender SN-003    │    receiver port)   │ Receiver tr      │ :8474
│ "HSM", audit   │◄─HTTP──┴──────────────────┘                     └────────┬─────────┘
│ log            │◄──────────────── HTTP (GET /epoch, POST /open, /responder/decrypt)┘
└────────────────┘
```

**Broadcast path (simulated radio): UDP, sender → receivers.**
- One datagram = one frame as it would go on air (radio headers aside):
  - Data pack: a standard ASTM F3411 message pack (Basic ID with Session ID + Location + System + 4 Auth pages = 178 B), the bytes that would sit in a Wi-Fi beacon vendor IE or a BLE advertisement.
  - Heartbeat frame (~588 B, CPBS-specific, not an F3411 message): the whole session Core plus a fresh Wrapper signature. On air it would be one chained BLE extended advertisement or a multi-IE Wi-Fi frame.
- Broadcast is emulated by unicasting a copy to every port in `config.receivers`. There is no reverse traffic.

**Infrastructure path: HTTP/JSON over TCP, to the authority.**
- Senders: enrolment (join protocol manager steps over `POST /enroll`), the current epoch, and the responder public key for sealing `C_enc`.
- Receivers: poll `GET /epoch` (1 s) for the group key, and fetch it immediately when a Core from a newer epoch arrives. The trusted receiver also calls `POST /open` and `POST /responder/decrypt`.
- Launcher: `POST /revoke/{id}` and `POST /rollover`.

| Process | Code | Role |
|---|---|---|
| Authority | `cpbs/authority/service.py` → `hsm.py` | Per-epoch groups, enrolment, opening, responder-tier decryption, revocation, hash-chained audit log. Manager keys never leave the process (simulated HSM). |
| Sender | `cpbs/sender/main.py` → `protocol/session.py`, `framing.py` | Enrols each epoch; random-walk trajectory; data pack at `data_rate_hz`, Core heartbeat every `heartbeat_interval_s`; new session every `session_lifetime_s` or on epoch change. A revoked sender keeps broadcasting with its old credentials. |
| Receiver | `cpbs/receiver/main.py` → `protocol/verifier.py` | Tiered verification (data pack: freshness → SeqNo → Ed25519; heartbeat: freshness → SessionID = H(pk) → Wrapper → epoch → rate limit → GroupVerify); session cache; `--trusted` opens every new session. |

Output: console overview lines (`cpbs/console.py`, `CPBS_QUIET=1` to silence),
plus per-process JSONL logs and receiver summaries in `results/<scenario>-<time>/`.

**Not modelled:**
- No radio framing (802.11/BLE headers, MAC addresses, pack counter).
- No loss, range or collisions.
- Receivers fetch group keys online; real untrusted receivers may need them distributed ahead of time.

## Build

Needs cmake, gcc, libgmp-dev, libssl-dev, libsodium and a non-conda Python ≥ 3.10.
Conda's older libstdc++ clashes with MCL.

```bash
/usr/bin/python3 -m venv .venv
.venv/bin/pip install -e ".[dev,eval]"
scripts/build_libgroupsig.sh .venv/bin/python   # libgroupsig + pinned MCL v1.51 + pygroupsig
bench/build_bench.sh                            # C benchmark + ODID reference checker
.venv/bin/pytest
```

## Run

```bash
.venv/bin/python bench/run_scenario.py scenarios/basic.json      # US model (per-drone membership)
.venv/bin/python bench/run_scenario.py scenarios/basic_eu.json   # EU model (per-operator membership)
.venv/bin/python bench/analyze.py results/basic-<timestamp>
```

Each scenario starts the authority, receivers (untrusted, a late joiner and a
trusted one that opens every session) and drones. Partway through, one drone is
revoked and the epoch rolled over; it keeps broadcasting with its old
credentials and must be rejected.

## Measure

```bash
bench/bench_groupsig bbs04 200 10,100,1000,10000        # raw C: setup/join/sign/verify/open
                                                        # (ps16 still accepted, for the comparison in the notes)
.venv/bin/python bench/bench_primitives.py --iters 500  # pipeline timings + byte overhead
```

## Layout

| Path | Content |
|---|---|
| `cpbs/odid/` | F3411 encoding (adapted from droneRemoteIDSpoofer), Auth pages, message packs, reference parser |
| `cpbs/crypto/` | libgroupsig wrapper, Ed25519 session keys, sealed box |
| `cpbs/protocol/` | Core, pack framing, sender session, receiver verifier |
| `cpbs/authority/` | issuer/opener/revocation ("HSM"), audit log, REST API and client |
| `cpbs/sender/`, `cpbs/receiver/` | processes |
| `bench/` | scenario launcher, benchmarks, analysis |
| `tests/` | unit, protocol, authority and reference-decoder tests |
