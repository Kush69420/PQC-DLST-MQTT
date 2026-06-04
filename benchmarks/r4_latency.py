"""
R4 — End-to-End Latency.
Measures wall-clock time for:
  "Time for a publisher's message to become readable by one subscriber, starting from no sessions"
Comparing PQC-DLST-MQTT and PQC-TLS-MQTT (Analytical Lower Bound).
All timings are compute-bound on localhost CPU and ignore network transit times.
Exports results to results/r4_latency.json.
"""

import json
import time
from pathlib import Path
import numpy as np

from src.pqcrypto.kem import KEMWrapper
from src.pqcrypto.sig import SigWrapper
from src.pqcrypto.aead import AEADWrapper
from src.pqcrypto.hash import HashWrapper
from src.pqcrypto.kdf import derive_channel_keys

# Timing configuration
TRIALS = 1000
WARMUP = 100

def run_dlst_flow(level: int, payload: bytes):
    """
    Simulates a full PQC-DLST-MQTT E2E setup and data transfer flow.
    Returns the elapsed time in microseconds.
    """
    kem = KEMWrapper(security_level=level)
    sig = SigWrapper(security_level=level)
    
    # 1. Publisher Phase I (mutual handshake)
    # Publisher Side: KeyGen + Sign request
    pub_ek, pub_dk = kem.keygen()
    pub_req_msg = pub_ek + b"nonce_client_pub" + b"pub123"
    pub_req_sig = sig.sign(pub_dk, pub_req_msg)  # Using dk as temp key/sig placeholder
    
    # TTA Side: Verify sig + Encaps
    sig.verify(pub_ek, pub_req_msg, pub_req_sig)  # Using ek as temp verification key
    pub_ss, pub_ct = kem.encaps(pub_ek)
    pub_resp_msg = pub_ct + b"nonce_tta_pub"
    pub_resp_sig = sig.sign(pub_dk, pub_resp_msg)
    
    # Publisher Side: Verify resp + Decaps + KDF
    sig.verify(pub_ek, pub_resp_msg, pub_resp_sig)
    kem.decaps(pub_dk, pub_ct)
    pub_k1, pub_k2 = derive_channel_keys(pub_ss, b"nonce_client_pub", b"nonce_tta_pub")

    # 2. Subscriber Phase I (mutual handshake)
    # Subscriber Side: KeyGen + Sign request
    sub_ek, sub_dk = kem.keygen()
    sub_req_msg = sub_ek + b"nonce_client_sub" + b"sub123"
    sub_req_sig = sig.sign(sub_dk, sub_req_msg)
    
    # TTA Side: Verify sig + Encaps
    sig.verify(sub_ek, sub_req_msg, sub_req_sig)
    sub_ss, sub_ct = kem.encaps(sub_ek)
    sub_resp_msg = sub_ct + b"nonce_tta_sub"
    sub_resp_sig = sig.sign(sub_dk, sub_resp_msg)
    
    # Subscriber Side: Verify resp + Decaps + KDF
    sig.verify(sub_ek, sub_resp_msg, sub_resp_sig)
    kem.decaps(sub_dk, sub_ct)
    sub_k1, sub_k2 = derive_channel_keys(sub_ss, b"nonce_client_sub", b"nonce_tta_sub")

    # 3. Publisher Phase II (TSA request/response)
    # Encrypt/Decrypt TSA Request & Response
    aead_ctrl = AEADWrapper(4)  # AES-256-GCM for control plane
    nonce = b"N" * 12
    aad = b"aad"
    
    # Request
    p2_req_ct, p2_req_tag = aead_ctrl.encrypt(pub_k1[:32], nonce, b"sensors/temp" + b"priority", aad)
    aead_ctrl.decrypt(pub_k1[:32], nonce, p2_req_ct, p2_req_tag, aad)
    # Response
    p2_resp_ct, p2_resp_tag = aead_ctrl.encrypt(pub_k2[:32], nonce, b"accepted_negotiated_levels", aad)
    aead_ctrl.decrypt(pub_k2[:32], nonce, p2_resp_ct, p2_resp_tag, aad)

    # 4. Publisher Phase III (Config Delivery)
    # Config Request
    p3_cfg_ct, p3_cfg_tag = aead_ctrl.encrypt(pub_k2[:32], nonce, b"config_seeds_keys_salt", aad)
    aead_ctrl.decrypt(pub_k2[:32], nonce, p3_cfg_ct, p3_cfg_tag, aad)
    # Config Ack
    p3_ack_ct, p3_ack_tag = aead_ctrl.encrypt(pub_k1[:32], nonce, b"ACK", aad)
    aead_ctrl.decrypt(pub_k1[:32], nonce, p3_ack_ct, p3_ack_tag, aad)

    # 5. Subscriber Phase V (Key Retrieval)
    # Key Request
    p5_req_ct, p5_req_tag = aead_ctrl.encrypt(sub_k1[:32], nonce, b"sensors/temp" + b"sub123", aad)
    aead_ctrl.decrypt(sub_k1[:32], nonce, p5_req_ct, p5_req_tag, aad)
    # Key Response
    p5_resp_ct, p5_resp_tag = aead_ctrl.encrypt(sub_k2[:32], nonce, b"subtopic_key_salt_epoch", aad)
    aead_ctrl.decrypt(sub_k2[:32], nonce, p5_resp_ct, p5_resp_tag, aad)

    # 6. Data Plane (Phase IV)
    # Publisher encrypt + Subscriber decrypt
    if level == 1:
        # Integrity-only KMAC path
        hash_lvl = HashWrapper(level)
        mac_key = b"K" * 32
        # Generation
        tag = hash_lvl.mac(mac_key, payload, custom=b"PQC-DLST-MQTT")
        # Verification
        hash_lvl.verify_mac(mac_key, payload, tag, custom=b"PQC-DLST-MQTT")
    else:
        # Encrypt-then-Decrypt
        aead_data = AEADWrapper(level)
        data_key = b"K" * aead_data.key_size
        ct, tag = aead_data.encrypt(data_key, nonce, payload, aad)
        aead_data.decrypt(data_key, nonce, ct, tag, aad)


def run_tls_flow(level: int, payload: bytes):
    """
    Simulates PQC-TLS-MQTT (Analytical Lower Bound) E2E setup and data transfer flow.
    Includes 2 full handshakes (Pub↔Broker, Sub↔Broker), broker decrypt/re-encrypt,
    and E2E record decryption.
    """
    kem = KEMWrapper(security_level=level)
    sig = SigWrapper(security_level=level)

    # --- Handshake 1: Publisher ↔ Broker ---
    # Client KeyGen + Server CertificateVerify sign + Client verification
    pub_ek, pub_dk = kem.keygen()
    pub_server_sig = sig.sign(pub_dk, pub_ek + b"handshake_data")
    sig.verify(pub_ek, pub_ek + b"handshake_data", pub_server_sig)
    # Server Encaps + Client Decaps
    pub_ss, pub_ct = kem.encaps(pub_ek)
    kem.decaps(pub_dk, pub_ct)
    # Client mTLS Signature + Server verification
    pub_client_sig = sig.sign(pub_dk, pub_ct + b"mtls_handshake_data")
    sig.verify(pub_ek, pub_ct + b"mtls_handshake_data", pub_client_sig)
    # KDF Channel derivation (symmetric keys)
    pub_k1, pub_k2 = derive_channel_keys(pub_ss, b"nonce_c", b"nonce_s")

    # --- Handshake 2: Subscriber ↔ Broker ---
    # Client KeyGen + Server CertificateVerify sign + Client verification
    sub_ek, sub_dk = kem.keygen()
    sub_server_sig = sig.sign(sub_dk, sub_ek + b"handshake_data")
    sig.verify(sub_ek, sub_ek + b"handshake_data", sub_server_sig)
    # Server Encaps + Client Decaps
    sub_ss, sub_ct = kem.encaps(sub_ek)
    kem.decaps(sub_dk, sub_ct)
    # Client mTLS Signature + Server verification
    sub_client_sig = sig.sign(sub_dk, sub_ct + b"mtls_handshake_data")
    sig.verify(sub_ek, sub_ct + b"mtls_handshake_data", sub_client_sig)
    # KDF Channel derivation (symmetric keys)
    sub_k1, sub_k2 = derive_channel_keys(sub_ss, b"nonce_c2", b"nonce_s2")

    # --- Per-Message Delivery (Data Plane) ---
    # TLS runs AES-GCM (equivalent to level config or level 4/5)
    # TLS 1.3 by default uses AES-256-GCM (equivalent to Level 4/5) or AES-128-GCM (Level 2).
    # We match the symmetric cipher strength of the corresponding security level.
    aead_lvl = level if level >= 2 else 2  # Level 1 uses AES-128-GCM in TLS
    aead = AEADWrapper(aead_lvl)
    key_size = aead.key_size
    
    nonce = b"N" * 12
    aad = b"aad"
    
    # 1. Publisher encrypts payload to Broker
    ct_pub, tag_pub = aead.encrypt(b"K" * key_size, nonce, payload, aad)
    # 2. Broker decrypts payload
    aead.decrypt(b"K" * key_size, nonce, ct_pub, tag_pub, aad)
    # 3. Broker re-encrypts for Subscriber
    ct_sub, tag_sub = aead.encrypt(b"K" * key_size, nonce, payload, aad)
    # 4. Subscriber decrypts payload
    aead.decrypt(b"K" * key_size, nonce, ct_sub, tag_sub, aad)


def run_benchmarks():
    payloads = {
        16: b"A" * 16,
        64: b"A" * 64,
        256: b"A" * 256,
        1024: b"A" * 1024
    }

    results = {}
    print("Running E2E wall-clock latency benchmarks (1000 trials, 100 warmup iterations)...")

    # We time each level and payload size combination
    for level in [1, 3, 5]:
        results[level] = {}
        for p_size, payload in payloads.items():
            results[level][p_size] = {}
            print(f"Benchmarking Level {level} with {p_size}B payload...")

            # --- DLST timing ---
            # Warmup
            for _ in range(WARMUP):
                run_dlst_flow(level, payload)
            # Run
            dlst_times = []
            for _ in range(TRIALS):
                start = time.perf_counter_ns()
                run_dlst_flow(level, payload)
                end = time.perf_counter_ns()
                dlst_times.append((end - start) / 1000.0)  # ms -> us

            # --- TLS timing ---
            # Warmup
            for _ in range(WARMUP):
                run_tls_flow(level, payload)
            # Run
            tls_times = []
            for _ in range(TRIALS):
                start = time.perf_counter_ns()
                run_tls_flow(level, payload)
                end = time.perf_counter_ns()
                tls_times.append((end - start) / 1000.0)

            results[level][p_size] = {
                "dlst": {"mean_us": np.mean(dlst_times), "std_us": np.std(dlst_times)},
                "tls": {"mean_us": np.mean(tls_times), "std_us": np.std(tls_times)},
            }
            print(f"  PQC-DLST-MQTT: {results[level][p_size]['dlst']['mean_us']:.2f} ± {results[level][p_size]['dlst']['std_us']:.2f} us")
            print(f"  PQC-TLS-MQTT (Bound): {results[level][p_size]['tls']['mean_us']:.2f} ± {results[level][p_size]['tls']['std_us']:.2f} us")

    # Export to JSON
    results_dir = Path("/media/nyx/WD Black/IoD Project/results")
    results_dir.mkdir(parents=True, exist_ok=True)
    with open(results_dir / "r4_latency.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults exported to {results_dir / 'r4_latency.json'}")

    # Generate Markdown Table output
    print("\n\n### R4 — E2E Wall-Clock Latency Table (Markdown)\n")
    print("*" * 90)
    print("Table Caption: End-to-end wall-clock latency (mean ± std dev) for a publisher's message to become readable by one subscriber starting from no sessions. PQC-TLS-MQTT is modeled using the analytical lower bound proxy (2 full handshakes + broker re-encryption + message transfer). Measured locally on host (compute-bound, TCP/localhost, no network latency).")
    print("*" * 90)
    print()
    print("| Level | Payload Size | PQC-DLST-MQTT (μs) | PQC-TLS-MQTT (Lower Bound) (μs) | Ratio (TLS / DLST) |")
    print("| :---: | :---: | :---: | :---: | :---: |")
    for lvl in [1, 3, 5]:
        for p_size in [16, 64, 256, 1024]:
            stats = results[lvl][p_size]
            dlst_str = f"{stats['dlst']['mean_us']:.1f} ± {stats['dlst']['std_us']:.1f}"
            tls_str = f"{stats['tls']['mean_us']:.1f} ± {stats['tls']['std_us']:.1f}"
            ratio = stats["tls"]["mean_us"] / stats["dlst"]["mean_us"]
            print(f"| L{lvl} | {p_size} B | {dlst_str} | {tls_str} | {ratio:.2f}x |")
    print()

if __name__ == "__main__":
    run_benchmarks()
