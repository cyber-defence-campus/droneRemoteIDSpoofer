Conditionally Private Broadcasting scheme
1. System Overview
This system provides a highly secure, ad-hoc broadcast architecture optimized for edge devices (drones, vehicles, smartphones). It guarantees Conditional Privacy: senders are completely anonymous and unlinkable across sessions to the public, but strictly identifiable by authorized entities.
System Actors
Sender ($S$): Edge device broadcasting telemetry/data. Possesses a Secret Group Key ($GSK_S$).
Untrusted Receiver ($UR$): Public listener (e.g., other drones, civilian smartphones). Can verify the sender is a legitimate group member and track data within a single session, but cannot identify the sender or link sessions. Possesses the Group Public Key ($GPK$).
Trusted Receiver / Authority ($TR$): Authorized tracking entity (e.g., Air Traffic Control, Law Enforcement). Can cryptographically unmask the exact identity of any sender. Possesses API access to the Hardware Security Module holding the Opening Key ($OK$).

2. Cryptographic Primitives
To balance mathematical security with the computational constraints of edge microcontrollers, the protocol uses a dual-cryptography approach:
Identity Layer (Pairing-Based Group Signatures): Utilizes algorithms like BBS+ over the BLS12-381 curve. Generates constant-size signatures ($\approx 200$ bytes) to prove group membership without revealing identity.
Session Layer (Edwards-Curve Signatures): Utilizes Ed25519. Generates ultra-fast, 64-byte ephemeral signatures ($\approx 0.5$ ms compute time) to secure the continuous data stream.

3. Protocol Mechanics
Phase 1: Session Initialization (The Two-Tiered Heartbeat)
To accommodate late-joining receivers while maintaining a strict defense against replay attacks, the sender broadcasts a dual-signed Heartbeat Message every 2 to 5 seconds.
At the start of a session, the Sender generates a fresh ephemeral key pair: $(sk_{sess}, pk_{sess})$.
The Static Core (Computed Once per Session):
The sender binds the session to their verified group identity using their heavy Group Secret Key ($GSK_S$).
$$Core = \text{SessionID} \parallel pk_{sess} \parallel \text{GroupSign}_{GSK_S}(\text{SessionID} \parallel pk_{sess})$$
The Dynamic Wrapper (Computed Every Heartbeat):
The sender updates the timestamp using the ultra-fast ephemeral private key ($sk_{sess}$).
$$Wrapper = \text{Timestamp} \parallel \text{Sign}_{sk_{sess}}(\text{Timestamp} \parallel Core)$$
Broadcast Packet: $\mathbf{[ Core \parallel Wrapper ]}$
Phase 2: Data Payload Transmission
Once the session is established, high-frequency payload data ($M$) is streamed entirely in the clear. The heavy group signature is dropped, and the sender signs the data using the ephemeral key.
$$PayloadPacket = \text{SessionID} \parallel \text{SeqNo} \parallel M \parallel \text{Sign}_{sk_{sess}}(\text{SessionID} \parallel \text{SeqNo} \parallel M)$$

4. Receiver Verification Logic
Receivers operate entirely passively. When an Untrusted Receiver ($UR$) captures a broadcast, it processes it in strict sequential order to minimize CPU drain and prevent Denial of Service (DoS) attacks.
Step 1: Wrapper Verification (Anti-Replay Guard)
The $UR$ checks the $Timestamp$ in the Wrapper. If $T_{current} - Timestamp > 2\text{ seconds}$, the packet is instantly dropped.
The $UR$ verifies the Ed25519 signature on the Wrapper using the $pk_{sess}$ provided in the Core.
Step 2: Core Verification (Membership Guard)
If the $UR$ already has the $\text{SessionID}$ cached locally, it skips this step (saving CPU).
If this is a new session (or the $UR$ is a late-joiner), it runs $\text{GroupVerify}(GPK, Core)$. If valid, it caches $pk_{sess}$ as an authenticated source.
Step 3: Payload Verification
For subsequent data packets, the $UR$ verifies the $\text{SeqNo}$ is strictly increasing and validates the payload using the cached $pk_{sess}$.

5. HSM API Architecture (Trusted Receiver Unmasking)
The Authority's Opening Key ($OK$) is never stored in software or accessible to human operators. It is permanently locked inside a FIPS 140-2 Level 3 Hardware Security Module (HSM).
When a Trusted Receiver ($TR$) needs to unmask a rogue drone or malicious sender, the process executes via a strict API flow:
The Request: The $TR$ software sends a RESTful API request to the HSM Controller containing the target's $Core$ packet and an authorization token (e.g., an incident ticket number).
Hardware Execution: The HSM ingests the $Core$, validates the Group Signature internally, and executes the mathematical $\text{Open}(OK, Core)$ function inside the secure silicon enclave.
Audit Trail Logging: The HSM appends an immutable record to a centralized Zero-Knowledge ledger, logging the exact timestamp, the operator ID, and the $\text{SessionID}$ that was opened.
The Response: The HSM returns the exact $\text{Identity}_S$ (e.g., a device serial number or VIN) to the API requester.

6. Threat Mitigation Summary
Attack Vector
System Defense Mechanism
Result
Outsider Impersonation
Group Signature Verification
Fails; attacker lacks $GSK_S$ to generate a valid $Core$.
Insider Framing (Spoofing Alice)
Cryptographic Unframeability
Fails; TR unmasking will reliably output the attacker's actual identity, not Alice's.
Cross-Session Tracking by URs
Ephemeral Keys ($sk_{sess}$)
Fails; each session uses a totally distinct, randomized $Core$ and $pk_{sess}$.
Wide-Window Replay Attacks
Two-Tiered Heartbeat
Fails; the dynamic Ed25519 wrapper enforces a strict 2-second limit without dropping late-joiners.
Receiver CPU DoS Attacks
Tiered Verification Logic
Mitigated; fast wrapper checks and caching prevent attackers from forcing heavy group signature math.
Opening Key Theft
HSM Isolation
Mitigated; the master key cannot be exported or copied from the hardware enclave.


This scheme satisfies all our requirements except forward privacy, which depends on the revocation scheme
Handling Revocations
On a high level there are 3 different ways of handling revocations in this scheme:
1 Verifier Local Revocation VLR
Part of the secret key gets published and this allows receivers to check if the sender is one of the revoked senders. 
2 Accumulators
Basically the drones always use a whitelist to transmit their messages and they have to change it when a key gets revoked.
3 Epoch based validity
Handed out keys to operators/drones are only valid for a certain period of time after which they expire. The keys have their expiration date baked in(basically a cert) and as long as the receiver has the correct time and date they can reject invalid certificates.

Probably it would be good to orient the revocation architecture on the way it is done in the internet, with revocation lists and key expiration combined:

Implement VLR:
Keeping revocation lists manageable:
Inspired by Certificate management:
Limit lifetimes: eg. mandatory key rollover every 2 years
Timeframe depends on # of compromised drones

