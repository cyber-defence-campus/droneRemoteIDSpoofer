# Conditionally Private Broadcasting Scheme (CPBS) for Remote ID

> Thesis design notes. Original draft preserved in `CONDITIONALLY_PRIVATE_BROADCASTING_SCHEME.original.MD`.

## 1. System Overview

CPBS is an ad-hoc broadcast authentication scheme for edge devices (drones, vehicles, smartphones), designed here for drone Remote ID (ASTM F3411 / ASD-STAN prEN 4709-002). It provides **conditional privacy**:

- **Towards the public:** senders are anonymous and unlinkable across sessions, but receivers can verify that a sender is a legitimate, registered group member and can follow its data within a single session.
- **Towards the authority:** any session can be cryptographically attributed to the exact registered member.

Core idea: authenticate a *session* once with an anonymous, openable group signature, then authenticate the high-rate data stream cheaply with a per-session Ed25519 key. This mirrors the pseudonym approach of V2X (IEEE 1609.2 / SCMS) and maps naturally onto existing F3411 fields (UA ID type *Specific Session ID*, Authentication type *Specific Authentication Method*).

### Actors

| Actor | Holds | Capabilities |
|---|---|---|
| **Sender** $S$ (drone / RID module) | Group secret key $GSK_S$ | Opens sessions, signs data stream |
| **Untrusted Receiver** $UR$ (public, phones, other drones) | Group public key $GPK$, current revocation list $RL_t$ | Verifies membership and session data; cannot identify or link sessions |
| **Trusted Receiver / Authority** $TR$ (CAA, ATC, law enforcement) | API access to the HSM holding the opening key $OK$ | Unmasks the member behind any session |
| **Authority** (issuer + opener) | Issuing key, $OK$, member registry | Enrols members, opens signatures, publishes revocation lists |

## 2. Trust Model

- **Single root of trust.** In aviation, and drone regulation in particular, a single trusted authority (the CAA / registration body) is an established and reasonable principle. The authority acts as both **issuer** and **opener**.
- Consequently, non-frameability *against the authority itself* (as formalised in the dynamic-group model of Bellare–Shi–Zhang 2005, BSZ05) is **explicitly out of scope**. Static schemes where the authority generates member keys are acceptable.
  - *Thesis note:* state this assumption explicitly. BSZ05-style dynamic schemes (member-generated keys, separated issuer/opener, verifiable opening) are the known extension if the assumption is relaxed.
- The opening key is protected by an HSM and its use is logged (Section 6).
- Out of scope: RF fingerprinting, physical capture of the drone's key material, relay/wormhole attacks (Section 8).

## 3. Cryptographic Requirements and Primitives

### 3.1 Required properties of the identity layer

The exact algorithm is interchangeable; the scheme requires a group signature with:

| Property | Meaning |
|---|---|
| **Anonymity / unlinkability** | Signatures reveal nothing about the signer and cannot be linked without $OK$ |
| **Traceability** | Every valid signature opens to a registered member; no member can produce a valid signature that evades opening |
| **Non-frameability among members** | A member (or coalition of members) cannot produce signatures that open to another honest member |
| **Openability** | Holder of $OK$ can recover the signer's identity |
| **Epoch-based Verifier-Local Revocation with backward unlinkability** | Receivers can reject revoked members locally; revoking a member in epoch $t$ does not link its signatures from earlier epochs (Section 7) |

Basic group-signature functionality (public membership verification, opening only with $OK$) is provided by any group signature scheme; the last row is the one that narrows the candidate set.

### 3.2 Primitives

- **Identity layer: pairing-based group signature** (BLS12-381).
  - *Note:* BBS+ is a signature / anonymous-credential scheme and has no `Open`. What is meant is a group signature in the BBS04 (Boneh–Boyen–Shacham) family, or a VLR variant.
  - Candidates: Boneh–Shacham VLR (2004), Nakanishi–Funabiki backward-unlinkable VLR variants; libraries such as IBM `libgroupsig` (check revocation support).
  - Size: a few hundred bytes. BBS04 on BLS12-381 is $3 \cdot 48 + 6 \cdot 32 = 336$ bytes (the ≈200-byte figure refers to older BN curves at lower security levels).
  - Computed **once per session** on the sender, verified **once per session** per receiver.
- **Session layer: Ed25519.** 32-byte public key, 64-byte signature, fast on both microcontrollers and phones.
- **Field encryption: HPKE / ECIES on X25519** to the authority's (or responder tier's) public key. Overhead ≈ 32 B ephemeral key + 16 B tag. Fresh randomness per session keeps ciphertexts unlinkable.

## 4. Protocol Mechanics

Transport assumption: **message packs only** (BT5 Long Range, Wi-Fi Beacon, Wi-Fi NAN; up to 9 × 25-byte messages per pack). BT4 legacy advertising is out of scope.

### 4.1 Phase 1: Session initialisation (two-tiered heartbeat)

At session start the sender generates a fresh ephemeral key pair $(sk_{sess}, pk_{sess})$ and sets

$$\text{SessionID} = H(pk_{sess}) \text{ (truncated)}$$

This binds the session identifier to the key, so an attacker cannot reuse a victim's SessionID with a different key. Receivers key their cache on SessionID (equivalently on $(\text{SessionID}, pk_{sess})$).

**Static Core (computed once per session):**

$$Core = \text{SessionID} \parallel pk_{sess} \parallel t_{epoch} \parallel C_{enc} \parallel \text{GroupSign}_{GSK_S}(\text{SessionID} \parallel pk_{sess} \parallel t_{epoch} \parallel C_{enc})$$

- $t_{epoch}$: current revocation epoch.
- $C_{enc}$: optional encrypted field blob (Section 5.2), bound to the session by the group signature.

**Dynamic Wrapper (computed every heartbeat):**

$$Wrapper = \text{Timestamp} \parallel \text{Sign}_{sk_{sess}}(\text{Timestamp} \parallel H(Core))$$

**Heartbeat:** $[\,Core \parallel Wrapper\,]$, every 2–5 s, so late-joining receivers can bootstrap.

Size estimate: SessionID (~16) + $pk_{sess}$ (32) + epoch (4) + $C_{enc}$ (~70–100) + group signature (~340) + timestamp (4) + Ed25519 signature (64) ≈ **500–550 bytes**. One F3411 Authentication message carries at most 255 bytes of auth data (1-byte length field; 17 B on page 0 + 23 B on each further page), so the Core does not fit a standard pack. The PoC therefore sends it in a **separate CPBS heartbeat frame** (Section 4.3).

### 4.2 Phase 2: Data payload transmission

Payload messages (Location/Vector, System, …) are sent in the clear and authenticated **once per message pack** with the session key:

$$Pack = \text{SessionID} \parallel M_1 \parallel \dots \parallel M_k \parallel \text{Sign}_{sk_{sess}}(\text{SessionID} \parallel \text{SeqNo} \parallel M_1 \parallel \dots \parallel M_k)$$

- **Freshness** comes from the timestamps already in the pack (Location message timestamp, Authentication page-0 timestamp), which are covered by the signature. This also prevents replaying earlier packets of the same session to a *late-joining* receiver, which a per-receiver SeqNo check alone does not.
- The 64-byte Ed25519 signature occupies ~4 Authentication pages of the 9-message pack; the remaining slots carry Basic ID (Session ID), Location, System, etc. Exact pack layout is a PoC design question.
- Low-overhead alternative for the stream: **TESLA** (hash-chain keys with delayed disclosure, short MACs per message), at the cost of delayed verification.

### 4.3 Wire format as implemented in the PoC

Implemented in `cpbs/protocol/` and checked against the opendroneid-core-c reference decoder.

- **Two frame types:** standard F3411 **data packs** (parsed by existing receivers) and a CPBS-specific **heartbeat frame** that carries the Core in one transmission (legacy receivers ignore it).
- **One Authentication message per pack.** Auth pages are numbered per message, so two Auth messages in one pack would collide.
- **Every pack** = Basic ID (UA ID type 4, Specific Session ID: session-ID-type byte + 19-byte SessionID, i.e. SHA-256(pk)[:19], the most the 20-byte UAS ID field allows) + payload messages + one Authentication message (type 5, SAM) with data
  `SAM type (1) | kind (1) | SeqNo (u16) | kind-specific | Ed25519 sig (64)`.
  The signature covers `"CPBS-PACK-v1" | Auth page-0 timestamp (u32, s since 2019) | auth data before the sig | all non-Auth messages of the pack`. The Basic ID is included, which binds the pack to its SessionID.
- **Data pack** (kind 1): Basic ID + Location + System + 4 Auth pages = 7 of 9 messages, **178 B**.
- **Heartbeat frame** (not an F3411 message): `"CPBS" | version | SessionID (19) | Timestamp (u32) | len (u16) | Core | Ed25519 sig (64)`, sig over `"CPBS-HB-v1" | SessionID | Timestamp | Core`. **573 B** with BBS04 (drone membership).
  - On air: one chained BLE extended advertisement (up to 1650 B of advertising data), or several vendor-specific IEs (≤ 255 B each) in one Wi-Fi beacon / NAN frame. Not tested with real receivers yet.
  - Earlier design: Core split into Auth pages across 5 standard packs, each signed (1090 B). Replaced because the per-chunk signatures and repeated Basic IDs were pure overhead.
- **Core as encoded:** `version | scheme | epoch (u32) | pk_sess (32) | len | C_enc | len (u16) | GroupSig`. The group signature covers the domain tag `"CPBS-CORE-v1"` plus every field before it. SessionID is *not* inside the Core; it is derived as SHA-256(pk)[:19] and compared with the Basic ID.
- **Wrapper:** the heartbeat frame's signature (fresh timestamp + Core under $sk_{sess}$). The receiver checks it (cheap) *before* GroupVerify (expensive), keeping the tiered order. For an already verified session, a heartbeat costs only this Ed25519 check.
- **Placeholders:** the SAM type and Session ID type are both `0xE1`, from the private experimental range 225–255 (values 1–224 are ICAO-managed). A deployment would need ICAO-assigned values.
- **$C_{enc}$:** libsodium sealed box over a TLV (`2` = serial, `3` = exact operator location), zero-padded to 32 B and sealed **freshly per session**. Reusing a ciphertext would link sessions; without padding the serial length would. No operator ID: opening already yields the registered identity.

## 5. Payload Content and Field Treatment

### 5.1 Field-by-field

| F3411 message | Treatment |
|---|---|
| **Basic ID** | Serial number replaced by SessionID (UA ID type 4, *Specific Session ID*) |
| **Operator ID** | Not broadcast: opening returns it (EU) or the authority's registry maps the serial to it (US). EU 2019/945 currently requires it in the clear |
| **System** (operator location, area, classification) | **Kept in the clear** for the PoC. Optional obfuscation, see Section 5.3 |
| **Self-ID** | Free text; dropped or user responsibility (can deanonymise) |
| **Location / Vector** | Clear: this is the purpose of Remote ID |
| **Authentication** | Carries Core (type 5, *Specific Authentication Method*, or private-use type) and pack signatures |

### 5.2 Recovering the drone serial and operator ID

The public must not see the serial, since that would break unlinkability. Recovery depends on the membership granularity, which follows the regulatory regime:

- **US (FAA Part 89 / Part 48):** registration lists the Remote ID serial number of each standard RID drone / broadcast module. Membership is **per drone**: enrolment = registration, and **opening directly returns the serial**. No extra fields needed. The FAA's Session ID option matches our SessionID.
- **EU (2019/947):** registration is **per operator**; the drone serial is not registered. Membership is per operator, opening returns the operator registration number, and the **serial travels in $C_{enc}$**. In the US model $C_{enc}$ also carries the serial, so responders get it without opening.

So one scheme covers both regimes; only membership granularity differs, and $C_{enc}$ has the same size in both.

**Optional tiered disclosure:** encrypt $C_{enc}$ (serial, exact operator location) to a *responder-tier* key (e.g. local police) distinct from $OK$. On-site responders can then locate or contact the pilot without full legal unmasking, while full opening stays behind the HSM and audit log. This gives three disclosure levels: public / responder / authority.

**Optional public hint:** the manufacturer code prefix of the CTA-2063 serial could be broadcast in clear. It is low entropy for big manufacturers, but a fingerprint for rare ones, so it should be configurable and off by default.

### 5.3 Location obfuscation (related work: OLO-RID)

Brighente et al., *Obfuscated Location Disclosure for Remote ID Enabled Drones* (IEEE TDSC 2026):

- Obfuscates the **drone position** with time-correlated geo-indistinguishability (Xiao et al.), plus an ECIES-encrypted true location per message for a trusted third party (112–188 B overhead per message, measured on a Raspberry Pi 3).
- Keeps the **UID and the control-station location $x_{CS}$ in the clear**. Without identity protection, the UID links all obfuscated positions.
- **Relation to CPBS: complementary.** OLO-RID hides *where*, CPBS hides *who*. OLO-RID can be layered on top as an optional extension, and its encrypted-location mechanism corresponds to our $C_{enc}$.
- Their mechanism *could be extended* to the operator location (not done in their paper). Caveat: an operator flying repeatedly from the same spot produces fresh noisy points that cluster around the true location, which limits the protection.
- Thesis position: the System message stays in the clear; OLO-RID is cited as an optional, compatible extension and is not part of the PoC.

## 6. Receiver Verification Logic

Receivers are fully passive. Processing order (cheap checks first):

1. **Wrapper / freshness guard:** drop if $T_{current} - \text{Timestamp} > \Delta$. $\Delta$ is **configurable** (default ~2 s; larger is acceptable). Assumes receiver clock sync (GNSS on the drone, NTP on phones). Then verify the Ed25519 Wrapper signature under $pk_{sess}$ and check $\text{SessionID} = H(pk_{sess})$.
2. **Core / membership guard:** if SessionID is cached, skip. Otherwise run $\text{GroupVerify}(GPK, Core)$ and the VLR check against $RL_{t_{epoch}}$; if valid, cache $pk_{sess}$ as an authenticated source.
3. **Pack verification:** verify the pack signature with the cached $pk_{sess}$, check timestamps are fresh and SeqNo is increasing.

**DoS caveat:** an attacker can create their own ephemeral key, attach a junk group signature and sign a perfectly valid Wrapper. The cheap check passes, forcing an expensive `GroupVerify` per fake session. The tiered logic only stops replays of *real* sessions. Mitigations to include in the PoC:
- rate-limit new-session group verifications per time window;
- prioritise by RSSI / proximity;
- verify lazily (only sessions the user inspects);
- optionally, a small proof-of-work in the Core (costly for senders).

## 7. Revocation: Epoch-based VLR

- **Plain VLR problem:** publishing a member's revocation token lets anyone link *all past* signatures of that member, so backward unlinkability (the "forward privacy" gap of the original draft) is lost. Verification also costs roughly one pairing per list entry.
- **Chosen design: epoch-based VLR with backward unlinkability.**
  - Time is divided into epochs; revocation tokens are **per epoch**, so revealing the token for epoch $t$ does not link signatures from epochs $< t$.
  - **Key expiry** (certificate-style lifetimes) keeps revocation lists short: a member only needs to stay on $RL$ until its key expires.
  - Epoch length is a trade-off between list size, re-provisioning frequency (drone re-keys via the operator app / registration portal) and linkability granularity; days to weeks rather than years. The required list size depends on the number of compromised drones.
- The Authority publishes $RL_t$; receivers fetch it when online (phones) or receive it with app updates.
- Opening in VLR-style schemes may require testing the signature against each member's token (linear in fleet size). That is acceptable for an authority-side, offline operation, but worth evaluating.
- Reference design for privacy-preserving PKI-style revocation: SCMS linkage values (US V2X).

## 8. HSM and Opening (Trusted Receiver Unmasking)

The opening key $OK$ is held in an HSM and never exported.

1. **Request:** TR software sends the target's Core plus an authorisation token (e.g. incident ticket) to the HSM controller API.
2. **Execution:** the HSM validates the group signature and computes $\text{Open}(OK, Core)$.
3. **Audit:** the controller appends a record (timestamp, operator ID, SessionID) to an **append-only transparency log** (Merkle tree, Certificate-Transparency style; "zero-knowledge ledger" in the original draft).
4. **Response:** the member identity (US: drone serial; EU: operator registration number).

Notes:
- Commercial FIPS 140-2/3 HSMs do not support pairing operations natively, so this needs custom firmware (e.g. Entrust CodeSafe) or a TEE. **For the PoC, the HSM is simulated as an isolated service.**
- Non-exportability does not stop misuse by whoever holds API access; the authorisation policy and the audit log are what provide accountability. Threshold opening (splitting $OK$) is a possible extension but not required under the single-root-of-trust model.

## 9. Threat Mitigation Summary

| Attack vector | Defence | Result |
|---|---|---|
| Outsider impersonation | Group signature verification | Fails: no valid Core without $GSK_S$ |
| Insider framing (member spoofing Alice) | Traceability / non-frameability among members | Fails: opening yields the attacker, not Alice |
| Framing by the authority | Out of scope (single root of trust) | Assumed trusted |
| Cross-session tracking by URs (crypto layer) | Ephemeral keys, SessionID = $H(pk_{sess})$, randomised Core and $C_{enc}$ | Fails at the crypto layer; see limitations |
| SessionID hijacking / cache poisoning | SessionID bound to $pk_{sess}$ | Fails |
| Wide-window replay | Timestamped Wrapper, configurable $\Delta$ | Fails outside $\Delta$ |
| Replay of earlier packs to late joiners | Signed pack timestamps | Fails outside $\Delta$ |
| Receiver CPU DoS via fake sessions | Rate limiting, prioritisation, lazy verification | **Mitigated only**, not prevented |
| Opening-key theft | HSM isolation | Mitigated |
| Opening-key misuse | Authorisation + append-only audit log | Detectable after the fact |
| Use of revoked keys | Epoch-based VLR + key expiry | Rejected by up-to-date receivers |

### Known limitations (state explicitly)

- **Trajectory linking:** the end of session $N$ and the start of session $N+1$ are spatially and temporally adjacent. Mitigate by rotating sessions on events (take-off / landing) and with silent periods / mix-zones as in V2X.
- **Clear System message:** the operator location is a quasi-identifier across sessions (e.g. a pilot flying from home). See Section 5.3.
- **Lower-layer identifiers:** the BLE random address / Wi-Fi MAC must rotate in lockstep with the session. RF fingerprinting is out of scope.
- **Relay / wormhole attacks:** live re-broadcast of genuine packs elsewhere passes all checks; inherent to broadcast authentication.
- **Lying insiders:** authenticity does not imply truthfulness. A member can broadcast false positions; the scheme gives *accountability after opening* (deterrence), not prevention. Plausibility checks (cf. GhostBuster) are complementary.
- **Clock dependence:** freshness relies on receiver time sync.
- **Regulatory deviation:** EU 2019/945 requires the operator registration number and pilot location in the clear; CPBS intentionally deviates for the former. The FAA Session ID option is a closer fit.

## 10. Related Work Pointers

- **OLO-RID** (Brighente, Conti, Schotsman, Sciancalepore, TDSC 2026): location obfuscation, complementary (Section 5.3).
- **V2X pseudonym PKIs** (IEEE 1609.2, ETSI C-ITS, SCMS): session/pseudonym keys, linkage-value revocation, pseudonym-change strategies.
- **TESLA**: low-overhead broadcast stream authentication.
- **BSZ05**: formal model of dynamic group signatures (relevant for the trust-model discussion).
- **Boneh–Shacham 2004; Nakanishi–Funabiki**: VLR group signatures, backward unlinkability.
- **GhostBuster**: detecting misbehaving RID drones (complements lying-insider limitation).
- **ARID** (Tedeschi, Sciancalepore, Di Pietro, ACSAC 2021): anonymous RID with *brokered* authentication. Observers must ask a TTP to verify messages. Superseded by A2RID.
- **A2RID** (Wisse, Tedeschi, Sciancalepore, Di Pietro, IEEE IoT-J 2023): the closest prior work, compared in detail in Section 10.1.

### 10.1 Comparison with A2RID

**Core difference.**
- **A2RID** puts a full group signature on **every** RID message. Requirement 1 of the paper is that observers cannot tell whether two messages come from the same drone.
- **CPBS** group-signs **once per session** and authenticates the stream with an ephemeral Ed25519 key. Messages within a session are deliberately linkable; sessions are unlinkable.
- A2RID itself concedes (Sec. VI-A) that broadcast locations let an observer link messages into a track anyway: "partial protection against tracking". It therefore pays per-message group-signature cost for an unlinkability that the clear-text location largely undoes. CPBS drops the per-message claim and spends the expensive cryptography once per session.

| | A2RID | CPBS |
|---|---|---|
| Group signature | Every message | Once per session (Core) |
| Stream authentication | Same group signature | Ed25519 per message pack |
| Linkability | Per message (in theory) | Within a session; unlinkable across sessions |
| Late joiners | No issue (self-contained messages) | Need heartbeat frames (Sec. 12.1) |
| Schemes | CS (Camenisch–Lysyanskaya + Cramer–Shoup), DS (Derler–Slamanig, SPS-EQ; CPA and CCA2 variants) | BBS04 via libgroupsig |
| Security level | CS: **80-bit** (PBC Type-A); DS: 128-bit (BN254) | 128-bit (BLS12-381) |
| Size on air | CS: **~1.3 kB per message** (base58-encoded) | 178 B data pack + 588 B heartbeat frame every 3 s ≈ 374 B/s |
| Wire format | Custom IEEE 802.11b raw frame (msg ID 0xa21d), not F3411 | Data: standard F3411 message packs (UA ID type 4, Auth type 5), checked against opendroneid-core-c. Heartbeat: separate CPBS frame |
| Signer cost | CS: 17 ms (i7); DS: 0.16–0.22 s on ESP8266 *with precomputation* (storage grows with flight time; MBs for CPA, far more for CCA2) | 1.23 ms per session + ~20 µs per pack (x86) |
| Verifier cost | CS: 15 ms **per message** | 49 µs per pack; 1.74 ms per new session |
| Replay | Message timestamp + threshold τ | Signed Auth timestamp + Δ, plus SeqNo |
| DoS | Explicitly out of scope | Tiered verification + rate limit on GroupVerify |
| Revocation | Not addressed | Per-epoch groups (VLR future work) |
| Disclosure | Observer forwards message → USS opens, returns only an ack | Authority/HSM opening with append-only audit log, plus responder tier ($C_{enc}$: operator ID / serial without full opening) |
| Regulatory model | Group ID in the message; not discussed further | US per-drone vs EU per-operator membership |
| Formal analysis | ProVerif (anonymity, authenticity) | None yet |
| Evaluation platform | Real drones (Holybro X500, ESPcopter), over the air | Local processes (x86); arm64 pending |

**Where A2RID is ahead**
- Formal verification in ProVerif. A ProVerif/Tamarin model of the CPBS session binding (Core ↔ SessionID ↔ pack signatures) is the obvious gap to fill.
- Measurements on real hardware, including a microcontroller signer (ESP8266).
- No receiver state: no session cache, instant verification for late joiners.
- The DS join binds the registration entry to the drone's own signature key ($\sigma_{ji}$). That is the ingredient that makes an opening attributable to a specific drone, which our libgroupsig setup does not provide (BBS04 has no opening proof; Sec. 12.3).

**Where CPBS is ahead**
- Data stays in standard F3411 framing: existing receivers still parse the data packs (the heartbeat is an extra, ignorable frame).
- Per-pack verification 2–3 orders of magnitude cheaper. Lower bandwidth than CS-A2RID despite heartbeats, at a higher security level than CS.
- System coverage: revocation, DoS handling, US/EU regulatory models, responder-tier disclosure, audit trail.

**Positioning statement.** A2RID achieves per-message unlinkability at per-message group-signature cost, but concedes that broadcast locations link messages anyway. CPBS accepts intra-session linkability and moves the group signature to session establishment. That reduces signing and verification cost by orders of magnitude, keeps standard F3411 framing, and adds revocation, DoS handling and an auditable disclosure path.

## 11. Decisions and Open Points for the PoC

**Decided / implemented** (see `README.md` for build and run)
- Single root of trust (authority = issuer + opener + revocation); HSM simulated inside the authority process.
- Group signatures: IBM **libgroupsig** (archived Sep 2026; pinned with MCL v1.51), **BBS04**. PS16 was evaluated and dropped: its opening tests every member (linear in group size, 4.9 s at 10k members), and KLAP20 opens the same way; BBS04 opens by decryption in ~0.2 ms. Cost of the choice: a 2× larger signature (373 vs 177 B) and no opening proof. Curve BLS12-381; no custom crypto.
- Session layer and $C_{enc}$: libsodium (Ed25519, sealed box).
- Membership per drone (US) / per operator (EU), with the serial in $C_{enc}$ for EU.
- $\text{SessionID} = H(pk_{sess})$; wire format as in Section 4.3.
- Message packs only; one Ed25519 signature per pack; freshness from the signed Auth timestamp; configurable $\Delta$.
- **Revocation in the PoC: one group per epoch.** Revoked members are not re-enrolled at rollover. This gives backward unlinkability for free, with revocation latency of up to one epoch. True (epoch-based) VLR is future work / an optional benchmark-only prototype.
- Receiver DoS mitigation: token-bucket rate limit on new-session GroupVerify.
- System message in clear; OLO-RID cited as an optional extension.
- Local only: processes over UDP on localhost, no radio, no attacker components (future work).

**Open**
- arm64 timings (build expected to work; not yet run, needs a Raspberry Pi or qemu).
- Heartbeat frame on real radio: does a chained BLE extended advertisement / multi-IE Wi-Fi frame of ~588 B work with existing hardware and receivers (Section 4.3)?
- ~~PS16 opening cost grows linearly with group size~~: resolved by using BBS04 only.
- Epoch length and distribution of group keys to offline receivers.
- Formal model (ProVerif/Tamarin) of the session binding, to match A2RID's analysis (Section 10.1).
- Opening attributable to a specific member (registration signed with the drone's own key, as in A2RID's DS join; Section 12.3).

## 12. PoC Results

Platform: AMD Ryzen 7 7840U (x86_64), single thread, Linux. Medians; full tables in `results/bench/`.

### 12.1 Byte and air-time overhead

BBS04, heartbeat frame every 3 s, data packs at 1 Hz. Baseline = unauthenticated pack once per second (US: Basic ID + Location + System; EU: + Operator ID).

| Membership | Group sig | $C_{enc}$ | Core | Heartbeat frame | Data pack | CPBS B/s | Baseline B/s | Frames/s |
|---|---|---|---|---|---|---|---|---|
| drone (US) | 373 B | 80 B | 494 B | 588 B | 178 B | 374 | 78 | 1.33 (vs 1) |
| operator (EU) | 373 B | 80 B | 494 B | 588 B | 178 B | 374 | 103 | 1.33 (vs 1) |

- **Data packs** cost 100 B/s extra each (4 Auth pages carrying the 64 B signature); **heartbeats** about 190 B/s.
- **History:** Core split over 5 signed standard packs (1090 B per heartbeat, 541 B/s), and PS16 at 398 B/s with 3 packs. The separate heartbeat frame beats both.
- **Levers:** a longer heartbeat interval (5 s → ~292 B/s, at the cost of late-joiner latency); TESLA-style MACs instead of a 64 B signature per data pack.

### 12.2 Timings

Raw C (libgroupsig, `bench/bench_groupsig.c`). PS16 kept for the comparison that led to dropping it:

| Op | PS16 (dropped) | BBS04 |
|---|---|---|
| sign | 0.75 ms | 1.19 ms |
| verify | 1.62 ms | 1.63 ms |
| join (authority + member) | 1.84 ms | 0.68 ms |
| setup | 0.35 ms | 1.9 ms |
| **open, 10 members** | **6.4 ms** | 0.12 ms |
| **open, 100 / 1k / 10k members** | **49 ms / 477 ms / 4.9 s** | 0.13 / 0.23 / 1.2 ms |

Pipeline (Python orchestration over C, `bench/bench_primitives.py`, BBS04):

| Step | Median |
|---|---|
| Sender: new session (keygen + seal + group sign) | 1.23 ms |
| Sender: data pack (encode + Ed25519) | 19 µs |
| Sender: heartbeat frame (Ed25519 Wrapper) | 18 µs |
| Receiver: verified data pack (parse + fresh + SeqNo + Ed25519) | 49 µs |
| Receiver: new session (heartbeat: Wrapper + GroupVerify) | 1.74 ms |
| Authority: open (decryption) | 0.18 ms |

From the scenario runs (3 drones, 3 receivers, 40 s):
- Late joiner (started at 10 s): first verified session ~1.5 s after start; heartbeat every 3 s bounds it.
- Opening via REST: ~5 ms round trip (BBS04). Audit chain valid.
- Revoked drone: refused at re-enrolment; its old-epoch sessions rejected by all receivers.

### 12.3 Observations for the thesis

- **Receiver capacity is not a bottleneck.** ~49 µs per steady-state pack ≈ 20k packs/s per core; a new session costs ~1.7 ms ≈ 575 new sessions/s per core. That bounds the fake-session DoS, together with the rate limit.
- **Sender cost** is ~1.2 ms per session and ~20 µs per pack or heartbeat on x86. Edge-device (arm64) numbers are still to be measured.
- **Opening cost trade-off (why BBS04).** PS16 opens by testing the signature against every GML entry, ≈ 0.49 ms per member. That extrapolates to ~8 min per opening for 1M drones (parallelisable, but notable). BBS04 opens by decryption, near-constant, but has no opening proof and a 2× larger signature.
- **What the PS16 opening proof does and does not show** (libgroupsig implementation; relevant because BBS04, the chosen scheme, has no opening proof at all).
  - It is a zero-knowledge proof that the opener knows the registration value $\tilde\tau$ that matches the signature: $e(\sigma_1, \tilde\tau) = e(\sigma_2, \tilde g) / e(\sigma_1, \tilde X)$. So the signature really belongs to *some* enrolled entry, and the opener found it rather than guessing.
  - It does **not** by itself show *which* member that entry belongs to: `open_verify` takes only the signature, the proof and the group key.
  - To convince a third party that it was member X, the judge must also check the proof against X's registration record. Either reveal $\tilde\tau_X$ (a public pairing check, but it links all of X's signatures in that epoch), or use a proof bound to X's public registration value. The judge must also trust that the record belongs to X; in the original PS16 design the member signs its registration with a personal key at join time.
  - Under the single-root-of-trust assumption this is acceptable. Without it, verifiable opening that names the member is required (BSZ05 "judge" algorithm).
  - The PoC's "proof ok" therefore means "the opening is consistent with an enrolled member", not "proved it was X".
- **Epoch rollover cost** = setup + one join per member: 10k members ≈ 19 s (PS16) / 7 s (BBS04) of authority CPU. Fine for daily/weekly epochs.
- **Air time, not CPU, is the main cost.** CPBS needs ~4.7× the bytes of plain RID (368 vs 78 B/s) and one extra frame every 3 s. The heartbeat interval is the main knob, trading against late-joiner latency.
