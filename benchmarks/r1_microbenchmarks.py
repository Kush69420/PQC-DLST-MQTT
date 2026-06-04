"""
R1 — Cryptographic Microbenchmarks.
Measures execution timings of PQC KEM, digital signatures, and symmetric primitives.
Exports results to results/r1_microbenchmarks.json and outputs a formatted Markdown table.
"""

import json
import time
import os
import gc
from pathlib import Path
import numpy as np

from src.pqcrypto.kem import KEMWrapper
from src.pqcrypto.sig import SigWrapper
from src.pqcrypto.aead import AEADWrapper
from src.pqcrypto.hash import HashWrapper

# Timing configuration
TRIALS = 1000
WARMUP = 100

def time_op(func, *args, **kwargs):
    """Run warmup, then time the operation over TRIALS iterations with GC disabled."""
    # Warmup
    for _ in range(WARMUP):
        func(*args, **kwargs)
    
    # Timing
    timings = []
    gc.disable()
    try:
        for _ in range(TRIALS):
            start = time.perf_counter_ns()
            func(*args, **kwargs)
            end = time.perf_counter_ns()
            timings.append((end - start) / 1000.0)  # Convert to microseconds (us)
    finally:
        gc.enable()
    
    median = np.median(timings)
    q75, q25 = np.percentile(timings, [75, 25])
    iqr = q75 - q25
    return median, iqr

def run_benchmarks():
    results = {}

    print(f"Running cryptographic microbenchmarks ({TRIALS} trials, {WARMUP} warmup iterations)...")

    # 1. KEM wrapper benchmarking (Levels 1-5)
    print("\n--- ML-KEM Benchmarks ---")
    results["KEM"] = {}
    for level in [1, 3, 5]:
        kem = KEMWrapper(security_level=level)
        alg = kem.alg_name
        print(f"Benchmarking KEM Level {level} ({alg})...")
        
        # KeyGen
        kg_med, kg_iqr = time_op(kem.keygen)
        
        # Setup for encaps/decaps
        ek, dk = kem.keygen()
        
        # Encaps
        enc_med, enc_iqr = time_op(kem.encaps, ek)
        
        # Setup for decaps
        ss, ct = kem.encaps(ek)
        
        # Decaps
        dec_med, dec_iqr = time_op(kem.decaps, dk, ct)
        
        results["KEM"][alg] = {
            "keygen": {"median_us": kg_med, "iqr_us": kg_iqr},
            "encaps": {"median_us": enc_med, "iqr_us": enc_iqr},
            "decaps": {"median_us": dec_med, "iqr_us": dec_iqr}
        }
        print(f"  KeyGen: {kg_med:.2f} ± {kg_iqr:.2f} us")
        print(f"  Encaps: {enc_med:.2f} ± {enc_iqr:.2f} us")
        print(f"  Decaps: {dec_med:.2f} ± {dec_iqr:.2f} us")

    # 2. Signature wrapper benchmarking
    print("\n--- ML-DSA Benchmarks ---")
    results["Sig"] = {}
    for level in [1, 4, 5]:
        sig = SigWrapper(security_level=level)
        alg = sig.alg_name
        print(f"Benchmarking Signature Level {level} ({alg})...")
        
        # KeyGen
        kg_med, kg_iqr = time_op(sig.keygen)
        
        # Setup for sign
        vk, sk = sig.keygen()
        msg = b"Hello, PQC-DLST-MQTT digital signature verification test payload!"
        
        # Sign
        sign_med, sign_iqr = time_op(sig.sign, sk, msg)
        
        # Setup for verify
        signature = sig.sign(sk, msg)
        
        # Verify
        verify_med, verify_iqr = time_op(sig.verify, vk, msg, signature)
        
        results["Sig"][alg] = {
            "keygen": {"median_us": kg_med, "iqr_us": kg_iqr},
            "sign": {"median_us": sign_med, "iqr_us": sign_iqr},
            "verify": {"median_us": verify_med, "iqr_us": verify_iqr}
        }
        print(f"  KeyGen: {kg_med:.2f} ± {kg_iqr:.2f} us")
        print(f"  Sign:   {sign_med:.2f} ± {sign_iqr:.2f} us")
        print(f"  Verify: {verify_med:.2f} ± {verify_iqr:.2f} us")

    # 3. AEAD wrapper benchmarking
    print("\n--- AES-GCM Benchmarks ---")
    results["AEAD"] = {}
    payload = b"A" * 64  # 64-byte payload (typical sensor message)
    nonce = b"N" * 12
    aad = b"Topic: sensors/temp"
    
    for level in [2, 3, 4]:
        aead = AEADWrapper(security_level=level)
        key_size = aead.key_size
        key = b"K" * key_size
        alg = f"AES-{key_size * 8}-GCM"
        print(f"Benchmarking AEAD Level {level} ({alg})...")
        
        # Encrypt
        enc_med, enc_iqr = time_op(aead.encrypt, key, nonce, payload, aad)
        
        # Setup for decrypt
        ct, tag = aead.encrypt(key, nonce, payload, aad)
        
        # Decrypt
        dec_med, dec_iqr = time_op(aead.decrypt, key, nonce, ct, tag, aad)
        
        results["AEAD"][alg] = {
            "encrypt": {"median_us": enc_med, "iqr_us": enc_iqr},
            "decrypt": {"median_us": dec_med, "iqr_us": dec_iqr}
        }
        print(f"  Encrypt: {enc_med:.2f} ± {enc_iqr:.2f} us")
        print(f"  Decrypt: {dec_med:.2f} ± {dec_iqr:.2f} us")

    # 4. Hash/MAC benchmarking
    print("\n--- Hash / MAC Benchmarks ---")
    results["Hash"] = {}
    
    # SHA3-256 (Levels 2-3)
    sha3_256_wrapper = HashWrapper(security_level=2)
    h256_med, h256_iqr = time_op(sha3_256_wrapper.hash, payload)
    results["Hash"]["SHA3-256"] = {"median_us": h256_med, "iqr_us": h256_iqr}
    print(f"  SHA3-256:  {h256_med:.2f} ± {h256_iqr:.2f} us")

    # SHA3-384 (Level 4)
    sha3_384_wrapper = HashWrapper(security_level=4)
    h384_med, h384_iqr = time_op(sha3_384_wrapper.hash, payload)
    results["Hash"]["SHA3-384"] = {"median_us": h384_med, "iqr_us": h384_iqr}
    print(f"  SHA3-384:  {h384_med:.2f} ± {h384_iqr:.2f} us")

    # SHAKE-256 (Level 5)
    shake_wrapper = HashWrapper(security_level=5)
    shake_med, shake_iqr = time_op(shake_wrapper.hash, payload)
    results["Hash"]["SHAKE-256"] = {"median_us": shake_med, "iqr_us": shake_iqr}
    print(f"  SHAKE-256: {shake_med:.2f} ± {shake_iqr:.2f} us")

    # KMAC-256 (Level 1)
    kmac_wrapper = HashWrapper(security_level=1)
    kmac_key = b"K" * 32
    kmac_med, kmac_iqr = time_op(kmac_wrapper.mac, kmac_key, payload, custom=b"PQC-DLST-MQTT")
    
    # Setup for verify mac
    tag = kmac_wrapper.mac(kmac_key, payload, custom=b"PQC-DLST-MQTT")
    kmac_v_med, kmac_v_iqr = time_op(kmac_wrapper.verify_mac, kmac_key, payload, tag, custom=b"PQC-DLST-MQTT")
    
    results["Hash"]["KMAC-256"] = {
        "mac": {"median_us": kmac_med, "iqr_us": kmac_iqr},
        "verify": {"median_us": kmac_v_med, "iqr_us": kmac_v_iqr}
    }
    print(f"  KMAC-256 Mac:    {kmac_med:.2f} ± {kmac_iqr:.2f} us")
    print(f"  KMAC-256 Verify: {kmac_v_med:.2f} ± {kmac_v_iqr:.2f} us")

    # Export to JSON
    results_dir = Path(os.environ.get("RESULTS_DIR", Path(__file__).resolve().parent.parent / "results"))
    results_dir.mkdir(parents=True, exist_ok=True)
    with open(results_dir / "r1_microbenchmarks.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults exported to {results_dir / 'r1_microbenchmarks.json'}")

    # Generate Markdown Table output
    print("\n\n### R1 — Cryptographic Microbenchmarks Table (Markdown)\n")
    print("| Primitive Class | Parameter Set | Operation | Median Latency (μs) | IQR (μs) |")
    print("| :--- | :--- | :--- | :---: | :---: |")
    
    for alg, ops in results["KEM"].items():
        for op, stats in ops.items():
            print(f"| ML-KEM (Asymmetric) | {alg} | {op.capitalize()} | {stats['median_us']:.2f} | {stats['iqr_us']:.2f} |")
            
    for alg, ops in results["Sig"].items():
        for op, stats in ops.items():
            print(f"| ML-DSA (Asymmetric) | {alg} | {op.capitalize()} | {stats['median_us']:.2f} | {stats['iqr_us']:.2f} |")
            
    for alg, ops in results["AEAD"].items():
        for op, stats in ops.items():
            print(f"| AES-GCM (Symmetric) | {alg} | {op.capitalize()} | {stats['median_us']:.2f} | {stats['iqr_us']:.2f} |")
            
    for alg, val in results["Hash"].items():
        if "median_us" in val:
            print(f"| Hash (Symmetric) | {alg} | Hash | {val['median_us']:.2f} | {val['iqr_us']:.2f} |")
        else:
            print(f"| MAC (Symmetric) | {alg} | Mac Generation | {val['mac']['median_us']:.2f} | {val['mac']['iqr_us']:.2f} |")
            print(f"| MAC (Symmetric) | {alg} | Mac Verification | {val['verify']['median_us']:.2f} | {val['verify']['iqr_us']:.2f} |")
    print()

if __name__ == "__main__":
    run_benchmarks()
