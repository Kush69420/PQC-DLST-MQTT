"""
R1 — Cryptographic Microbenchmarks.
Measures execution timings of PQC KEM, digital signatures, and symmetric primitives.
Exports results to results/r1_microbenchmarks.json and outputs a formatted Markdown table.
"""

import json
import time
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
    """Run warmup, then time the operation over TRIALS iterations."""
    # Warmup
    for _ in range(WARMUP):
        func(*args, **kwargs)
    
    # Timing
    timings = []
    for _ in range(TRIALS):
        start = time.perf_counter_ns()
        func(*args, **kwargs)
        end = time.perf_counter_ns()
        timings.append((end - start) / 1000.0)  # Convert to microseconds (us)
    
    mean = np.mean(timings)
    std = np.std(timings)
    return mean, std

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
        kg_mean, kg_std = time_op(kem.keygen)
        
        # Setup for encaps/decaps
        ek, dk = kem.keygen()
        
        # Encaps
        enc_mean, enc_std = time_op(kem.encaps, ek)
        
        # Setup for decaps
        ss, ct = kem.encaps(ek)
        
        # Decaps
        dec_mean, dec_std = time_op(kem.decaps, dk, ct)
        
        results["KEM"][alg] = {
            "keygen": {"mean_us": kg_mean, "std_us": kg_std},
            "encaps": {"mean_us": enc_mean, "std_us": enc_std},
            "decaps": {"mean_us": dec_mean, "std_us": dec_std}
        }
        print(f"  KeyGen: {kg_mean:.2f} ± {kg_std:.2f} us")
        print(f"  Encaps: {enc_mean:.2f} ± {enc_std:.2f} us")
        print(f"  Decaps: {dec_mean:.2f} ± {dec_std:.2f} us")

    # 2. Signature wrapper benchmarking
    print("\n--- ML-DSA Benchmarks ---")
    results["Sig"] = {}
    for level in [1, 4, 5]:
        sig = SigWrapper(security_level=level)
        alg = sig.alg_name
        print(f"Benchmarking Signature Level {level} ({alg})...")
        
        # KeyGen
        kg_mean, kg_std = time_op(sig.keygen)
        
        # Setup for sign
        vk, sk = sig.keygen()
        msg = b"Hello, PQC-DLST-MQTT digital signature verification test payload!"
        
        # Sign
        sign_mean, sign_std = time_op(sig.sign, sk, msg)
        
        # Setup for verify
        signature = sig.sign(sk, msg)
        
        # Verify
        verify_mean, verify_std = time_op(sig.verify, vk, msg, signature)
        
        results["Sig"][alg] = {
            "keygen": {"mean_us": kg_mean, "std_us": kg_std},
            "sign": {"mean_us": sign_mean, "std_us": sign_std},
            "verify": {"mean_us": verify_mean, "std_us": verify_std}
        }
        print(f"  KeyGen: {kg_mean:.2f} ± {kg_std:.2f} us")
        print(f"  Sign:   {sign_mean:.2f} ± {sign_std:.2f} us")
        print(f"  Verify: {verify_mean:.2f} ± {verify_std:.2f} us")

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
        enc_mean, enc_std = time_op(aead.encrypt, key, nonce, payload, aad)
        
        # Setup for decrypt
        ct, tag = aead.encrypt(key, nonce, payload, aad)
        
        # Decrypt
        dec_mean, dec_std = time_op(aead.decrypt, key, nonce, ct, tag, aad)
        
        results["AEAD"][alg] = {
            "encrypt": {"mean_us": enc_mean, "std_us": enc_std},
            "decrypt": {"mean_us": dec_mean, "std_us": dec_std}
        }
        print(f"  Encrypt: {enc_mean:.2f} ± {enc_std:.2f} us")
        print(f"  Decrypt: {dec_mean:.2f} ± {dec_std:.2f} us")

    # 4. Hash/MAC benchmarking
    print("\n--- Hash / MAC Benchmarks ---")
    results["Hash"] = {}
    
    # SHA3-256 (Levels 2-3)
    sha3_256_wrapper = HashWrapper(security_level=2)
    h256_mean, h256_std = time_op(sha3_256_wrapper.hash, payload)
    results["Hash"]["SHA3-256"] = {"mean_us": h256_mean, "std_us": h256_std}
    print(f"  SHA3-256:  {h256_mean:.2f} ± {h256_std:.2f} us")

    # SHA3-384 (Level 4)
    sha3_384_wrapper = HashWrapper(security_level=4)
    h384_mean, h384_std = time_op(sha3_384_wrapper.hash, payload)
    results["Hash"]["SHA3-384"] = {"mean_us": h384_mean, "std_us": h384_std}
    print(f"  SHA3-384:  {h384_mean:.2f} ± {h384_std:.2f} us")

    # SHAKE-256 (Level 5)
    shake_wrapper = HashWrapper(security_level=5)
    shake_mean, shake_std = time_op(shake_wrapper.hash, payload)
    results["Hash"]["SHAKE-256"] = {"mean_us": shake_mean, "std_us": shake_std}
    print(f"  SHAKE-256: {shake_mean:.2f} ± {shake_std:.2f} us")

    # KMAC-256 (Level 1)
    kmac_wrapper = HashWrapper(security_level=1)
    kmac_key = b"K" * 32
    kmac_mean, kmac_std = time_op(kmac_wrapper.mac, kmac_key, payload, custom=b"PQC-DLST-MQTT")
    
    # Setup for verify mac
    tag = kmac_wrapper.mac(kmac_key, payload, custom=b"PQC-DLST-MQTT")
    kmac_v_mean, kmac_v_std = time_op(kmac_wrapper.verify_mac, kmac_key, payload, tag, custom=b"PQC-DLST-MQTT")
    
    results["Hash"]["KMAC-256"] = {
        "mac": {"mean_us": kmac_mean, "std_us": kmac_std},
        "verify": {"mean_us": kmac_v_mean, "std_us": kmac_v_std}
    }
    print(f"  KMAC-256 Mac:    {kmac_mean:.2f} ± {kmac_std:.2f} us")
    print(f"  KMAC-256 Verify: {kmac_v_mean:.2f} ± {kmac_v_std:.2f} us")

    # Export to JSON
    results_dir = Path("/media/nyx/WD Black/IoD Project/results")
    results_dir.mkdir(parents=True, exist_ok=True)
    with open(results_dir / "r1_microbenchmarks.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults exported to {results_dir / 'r1_microbenchmarks.json'}")

    # Generate Markdown Table output
    print("\n\n### R1 — Cryptographic Microbenchmarks Table (Markdown)\n")
    print("| Primitive Class | Parameter Set | Operation | Mean Latency (μs) | Std Dev (μs) |")
    print("| :--- | :--- | :--- | :---: | :---: |")
    
    for alg, ops in results["KEM"].items():
        for op, stats in ops.items():
            print(f"| ML-KEM (Asymmetric) | {alg} | {op.capitalize()} | {stats['mean_us']:.2f} | {stats['std_us']:.2f} |")
            
    for alg, ops in results["Sig"].items():
        for op, stats in ops.items():
            print(f"| ML-DSA (Asymmetric) | {alg} | {op.capitalize()} | {stats['mean_us']:.2f} | {stats['std_us']:.2f} |")
            
    for alg, ops in results["AEAD"].items():
        for op, stats in ops.items():
            print(f"| AES-GCM (Symmetric) | {alg} | {op.capitalize()} | {stats['mean_us']:.2f} | {stats['std_us']:.2f} |")
            
    for alg, val in results["Hash"].items():
        if "mean_us" in val:
            print(f"| Hash (Symmetric) | {alg} | Hash | {val['mean_us']:.2f} | {val['std_us']:.2f} |")
        else:
            print(f"| MAC (Symmetric) | {alg} | Mac Generation | {val['mac']['mean_us']:.2f} | {val['mac']['std_us']:.2f} |")
            print(f"| MAC (Symmetric) | {alg} | Mac Verification | {val['verify']['mean_us']:.2f} | {val['verify']['std_us']:.2f} |")
    print()

if __name__ == "__main__":
    run_benchmarks()
