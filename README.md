# PQC-DLST-MQTT: Post-Quantum Secure Lightweight Multicast MQTT Simulator

A research-grade performance evaluation and verification harness for **PQC-DLST-MQTT**, comparing it against a post-quantum **TLS 1.3 baseline (PQC-TLS-MQTT)**. 

The protocol implements a 6-level hierarchical security architecture utilizing NIST-standardized Post-Quantum Cryptography (PQC) primitives:
* **Key Encapsulation**: ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
* **Digital Signatures**: ML-DSA-44, ML-DSA-65, and ML-DSA-87.
* **Symmetric Primitives**: AES-GCM (128/192/256-bit) and KMAC-256.

---

## Repository Structure

```
├── benchmarks/
│   ├── r1_microbenchmarks.py  # Cryptographic microbenchmarks
│   ├── r2_communication.py    # Serialized byte-overhead analyzer
│   ├── r3_scalability.py      # Analytical scalability cost model
│   ├── plot_r3.py             # Plotting utility for R3 figures
│   └── r4_latency.py          # E2E wall-clock latency benchmark (localhost socket)
├── src/
│   ├── pqcrypto/              # PQC & symmetric crypto wrappers (liboqs-python/PyCryptodome)
│   ├── protocol/              # Phase I–VI protocol codecs and frames
│   └── pki/                   # Light PKI & CRL logic
├── tests/
│   └── test_r3_scalability.py # Invariant unit tests
├── results/                   # Benchmark output datasets and figures (Git ignored)
├── Makefile                   # Automation entry point
├── requirements.txt           # Python library dependencies
└── README.md                  # This documentation
```

---

## Requirements

Ensure your system has the following installed:
1. **Python 3.12+**
2. **OpenSSL CLI** (available in your system path, used for dynamic localhost TLS certificate generation)
3. **liboqs** library (installed or compiled locally so that `liboqs-python` can access PQC algorithms)

---

## Setup and Running

The project comes with a fully automated `Makefile` to simplify virtual environment setup, package installation, verification, and benchmark execution.

### 1. Project Initialization
Set up the virtual environment (`venv`) and install all required Python packages (including `liboqs-python` and `PyCryptodome`):
```bash
make setup
```

### 2. Verify Functional Correctness
Before running benchmarks, verify the protocol invariants and cost models by running the unit tests:
```bash
make test
```

### 3. Run All Benchmarks (Reproduce All Results)
Execute the complete evaluation suite (R1, R2, R3, R4) in sequence:
```bash
make reproduce
```
This runs the full campaign, exports raw data to JSON, prints Markdown tables directly to stdout, and saves scalability plots to the `results/` folder.

### 4. Cleanup
Remove cached bytecode and temporary local certificate files:
```bash
make clean
```

---

## Evaluation Details

### R1 — Cryptographic Microbenchmarks
* **File**: `benchmarks/r1_microbenchmarks.py`
* **What it does**: Measures raw latency of KEM keygen/encaps/decaps, signature keygen/sign/verify, and symmetric AEAD encrypt/decrypt operations over **1,000 trials** with a **100-iteration warmup**. Results are saved to `results/r1_microbenchmarks.json`.

### R2 — Serialized Communication Overhead
* **File**: `benchmarks/r2_communication.py`
* **What it does**: Instantiates actual protocol messages to measure the exact serialized byte sizes across all five active phases (Phases I–V) swept across security levels 1–5 and payloads (16 B to 1024 B). Results are saved to `results/r2_communication.json`.

### R3 — Scalability vs. PQC-TLS-MQTT
* **Files**: `benchmarks/r3_scalability.py` and `benchmarks/plot_r3.py`
* **What it does**: Models performance across $N = 200$ subscribers under a Server-Only authenticated TLS baseline. DLST achieves a **$99.0\%$ wire-byte reduction** via multicast and **$100\%$ broker cryptographic offloading**. It generates 4 PNG plots and writes summary metrics to `results/r3_summary_stats.txt`.

### R4 — E2E Wall-Clock Latency
* **File**: `benchmarks/r4_latency.py`
* **What it does**: Measures clean-slate E2E latency. The TLS baseline is dynamically scaled by anchoring it to a **real loopback TCP/TLS 1.3 socket handshake** on localhost (which captures TCP round-trips, context initialization, and buffer allocations) combined with post-quantum signature and key exchange overheads. Results are saved to `results/r4_latency.json`.
