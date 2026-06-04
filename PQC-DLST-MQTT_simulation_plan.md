Pqc dlst mqtt software sim plan · MD
# PQC-DLST-MQTT — Software-Only Simulation Plan (for the Results Section)
 
Scope: a pure-software simulation, no hardware, that yields a defensible Section V-C. The guiding principle is **measure what software measures truthfully** and **reframe the claims to match**. Two categories are fully legitimate from software:
 
1. **Computational cost** — PQC primitive timings (KeyGen/Encaps/Decaps/Sign/Verify) and AEAD/MAC throughput. These are real CPU costs; you simply report the platform you ran on, not a constrained MCU.
2. **Communication cost** — handshake byte counts, per-message overhead, message-complexity vs. number of subscribers. These are **exact** (determined by the protocol and primitive sizes), not platform-dependent estimates — your strongest, least-attackable results.
What you **drop** (cannot be honestly claimed without hardware): constrained-MCU RAM ceilings, energy/power draw, and any "STM32 / Cortex-M" profiling. Remove those rows and sentences entirely.
 
---
 
## 1. Reframe the evaluation claims
 
| Old (hardware-implying) claim | Software-honest replacement |
|---|---|
| "RAM footprint 14.8 KB on STM32WB55" | **Drop**, or report process RSS on the stated test machine, labelled as such |
| "Energy savings on edge nodes" | **Drop** (or cite primitive cycle counts as a proxy, clearly labelled) |
| "Latency on Cortex-A7 / Cortex-M4" | "Latency on [your CPU], mean of N runs" |
| "97% faster key delivery" | A like-for-like comparison of equivalent operations (see §4) |
 
State the platform plainly in a methodology box: CPU model, OS/kernel, Python/OpenSSL/liboqs versions, trial count, averaging. A reviewer accepts "measured on an x86 reference host" — they do **not** accept fabricated embedded numbers.
 
---
 
## 2. Minimal software stack
 
- **liboqs ≥ 0.10.0** + **liboqs-python** — ML-KEM-512/768/1024, ML-DSA-44/65/87, FALCON-512.
- **OpenSSL 3.x** or **PyCryptodome** — AES-128/192/256-GCM, SHA3-256/384, SHAKE-256, KMAC-256.
- **Mosquitto 2.x** (unmodified, MQTT v5) + **paho-mqtt**.
- **aiocoap** for the out-of-band control plane (RFC 7959 block-wise for the ~3.5 KB handshakes).
- **Baseline:** **OpenSSL 3.x + oqs-provider** to stand up **PQC-TLS-MQTT** (the only fair comparison).
- Everything runs as **docker-compose** containers on one machine; client counts scaled by spawning processes.
You can run the *entire* thing — both protocols, all scenarios — on a laptop.
 
---
 
## 3. What to build (reuse the staged plan, software only)
 
Implement all six phases in Python (fastest path to a working protocol; primitive timings come from the C cores inside liboqs/OpenSSL anyway, so the language overhead sits only in glue code, not in the crypto you're measuring).
 
- **Phase I–VI** exactly as specified (KEM auth, transcript binding, control-plane `IV_ctrl = b_dir ∥ sn ∥ 0^56`, data-plane `IV = Salt ∥ ID_P ∥ Counter32`, KMAC Level-1 path, point-to-point Phase V, epoch/replay handling).
- **PQC-TLS baseline:** each publisher/subscriber opens its own PQC-TLS session to Mosquitto; broker terminates TLS and re-encrypts every payload into each subscriber's independent session. The broker's per-message symmetric fan-out cost (decrypt + N re-encrypts) is the honest baseline gap — not duplicated KEM handshakes (each client does only one KEM per connection).
(Functional correctness tests are the same as the full plan; they gate the measurements.)
 
---
 
## 4. The four results every reviewer will accept
 
These are all software-truthful and sufficient for a strong Section V-C:
 
**R1 — Cryptographic microbenchmarks (per level).** Time KeyGen/Encaps/Decaps, Sign/Verify, and AEAD/MAC for each of the six levels. Use `time.perf_counter_ns()` (or the liboqs `speed_*` tools), **≥1000 iterations**, report mean ± stdev, discard warm-up. *Truthful because CPU cost is real; just state the host.*
 
**R2 — Communication overhead (exact, your best result).** Count bytes per phase and per data message from the actual serialized frames (and confirm with a pcap). These follow deterministically from ML-KEM/ML-DSA sizes + your 9-byte header + 16-byte tag — they are **exact**, hardware-independent, and reproduce Table II precisely.
 
**R3 — Scalability vs. PQC-TLS (handshake bytes & message count vs. N subscribers).** Sweep N = 50/100/150/200. Plot aggregate control-plane bytes and number of asymmetric operations for PQC-DLST-MQTT vs PQC-TLS-MQTT. Because PQC-DLST eliminates broker re-encryption entirely (subscribers share a topic key and decrypt the same multicast ciphertext, while the broker relays without any crypto operations), the per-message cost curves diverge — this is the core contribution and it is **analytically and empirically exact**, no hardware needed. Note: asymmetric connection setup costs (1 KEM per client) are comparable between protocols; the divergence is in broker symmetric load and per-message wire bytes.
 
**R4 — End-to-end latency, like-for-like.** Measure wall-clock for *equivalent* operations on the same host: e.g., "full session setup to first secured message" for both protocols. **Fairness rule:** do not compare PQC-DLST's symmetric Phase V unwrap against a full asymmetric TLS handshake and call it a 97% win — say exactly what each number includes. A defensible framing: "Phase V symmetric key delivery costs X; the comparable PQC-TLS per-subscriber rekey costs Y."
 
---
 
## 5. Optional: lift "simulation" toward "verification"
 
If you want the results section to carry more weight without hardware, add a **network-model simulation** (the original DLST-MQTT used a discrete-event style campaign) and/or a **Tamarin/ProVerif** model of Phase I. The formal model is pure software, strengthens the security section, and justifies firmer wording than "analysis." Either is a stronger reviewer signal than embedded numbers you can't produce.
 
---
 
## 6. Honest framing of the network model
 
Run over localhost/containers, but emulate a realistic link with **tc/netem** (e.g., 1.5% loss, a bandwidth cap, added RTT). State that the transport is emulated. Byte/message-complexity results (R2, R3) are loss-independent and therefore fully general; latency (R1, R4) is reported for the emulated profile. This distinction is what keeps the claims clean.
 
---
 
## 7. Figures/tables for Section V-C
 
1. **Table — primitive timings per level** (R1), mean ± stdev.
2. **Table II (validated)** — exact byte overhead per phase/message (R2).
3. **Figure — aggregate handshake bytes vs N subscribers**, PQC-DLST vs PQC-TLS (R3). *Headline.*
4. **Figure — asymmetric-operation count vs N** (R3), reinforcing the broker-offload argument.
5. **Table — like-for-like latency** with explicit operation definitions (R4).
6. **Methodology box** — host CPU/OS, library versions, N trials, netem profile.
---
 
## 8. Integrity guardrail (do this)
 
Put the code + scripts in a repo with fixed seeds and a `make reproduce` target. Every number in the paper must regenerate from it. This is what converts "software-only" from a weakness into a credibility asset — reviewers can rerun it.
 
---
 
## 9. Timeline (~3–4 weeks, software only)
 
- **W1:** stack + `pqcrypto`/`pki` modules + header codec + unit tests.
- **W2:** Phases I–VI in containers; functional run green.
- **W3:** PQC-TLS baseline (oqs-provider); R1 + R2 measurements.
- **W4:** R3 + R4 sweeps; figures + methodology box + artifact repo.
- (Optional parallel: Tamarin/ProVerif model.)
---
