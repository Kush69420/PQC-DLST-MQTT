"""
Plotting script for R3 Scalability Benchmark.
Generates publication-quality figures comparing PQC-DLST-MQTT and PQC-TLS-MQTT.
Saves the figures as PNG artifacts in the results/ directory.
"""

import os
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

from benchmarks.r3_scalability import sweep, LEVEL_KEM, LEVEL_SIG

def main():
    # Ensure results directory exists
    results_dir = Path("/media/nyx/WD Black/IoD Project/results")
    results_dir.mkdir(parents=True, exist_ok=True)

    # 1. Sweep data
    # We sweep security levels 3 and 5, subscriber counts from 10 to 200
    subs_sweep = list(range(10, 201, 10))
    rows = sweep(levels=[3, 5], subscriber_counts=subs_sweep, payload_size=64, mutual_tls=False)

    # Group data by level
    data_by_level = {3: {"subs": [], "tls_hs": [], "dlst_hs": [], "tls_asym": [], "dlst_asym": [], "tls_msg_bytes": [], "dlst_msg_uni": [], "dlst_msg_mcast": [], "tls_broker_sym": [], "dlst_broker_sym": []},
                     5: {"subs": [], "tls_hs": [], "dlst_hs": [], "tls_asym": [], "dlst_asym": [], "tls_msg_bytes": [], "dlst_msg_uni": [], "dlst_msg_mcast": [], "tls_broker_sym": [], "dlst_broker_sym": []}}

    for row in rows:
        lvl = row.level
        data_by_level[lvl]["subs"].append(row.n_subscribers)
        # Handshake bytes (divided by 1024 to show KB)
        data_by_level[lvl]["tls_hs"].append(row.tls.handshake_bytes / 1024.0)
        data_by_level[lvl]["dlst_hs"].append(row.dlst.handshake_bytes / 1024.0)
        
        # Asymmetric operations
        # Each KEM = 1 encaps/decaps pair; Each Sig = 1 sign + 1 verify
        # Total asymmetric ops = KEM + Sig sign + Sig verify
        tls_asym_ops = row.tls.kem_operations + row.tls.sig_sign_operations + row.tls.sig_verify_operations
        dlst_asym_ops = row.dlst.kem_operations + row.dlst.sig_sign_operations + row.dlst.sig_verify_operations
        data_by_level[lvl]["tls_asym"].append(tls_asym_ops)
        data_by_level[lvl]["dlst_asym"].append(dlst_asym_ops)

        # Per-message wire bytes
        data_by_level[lvl]["tls_msg_bytes"].append(row.tls.per_message_wire_bytes)
        data_by_level[lvl]["dlst_msg_uni"].append(row.dlst.per_message_wire_bytes)
        data_by_level[lvl]["dlst_msg_mcast"].append(row.dlst.per_message_wire_bytes_multicast)

        # Broker symmetric ops
        data_by_level[lvl]["tls_broker_sym"].append(row.tls.broker_sym_ops_per_message)
        data_by_level[lvl]["dlst_broker_sym"].append(row.dlst.broker_sym_ops_per_message)

    # Use style options for rich, clean plots
    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 11,
        "axes.labelsize": 12,
        "axes.titlesize": 12,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.fontsize": 10,
        "figure.titlesize": 14,
        "grid.linestyle": "--",
        "grid.alpha": 0.6
    })

    # Plot 1: Cumulative Handshake Bytes vs N subscribers
    fig, axes = plt.subplots(1, 2, figsize=(12, 5.5), sharey=False)
    for i, lvl in enumerate([3, 5]):
        ax = axes[i]
        d = data_by_level[lvl]
        ax.plot(d["subs"], d["tls_hs"], "o-", label="PQC-TLS-MQTT (Server-Only)", color="#d62728", linewidth=2)
        ax.plot(d["subs"], d["dlst_hs"], "s-", label="PQC-DLST-MQTT", color="#1f77b4", linewidth=2)
        ax.set_title(f"Level {lvl} ({LEVEL_KEM[lvl]} / {LEVEL_SIG[lvl]})")
        ax.set_xlabel("Number of Subscribers (N)")
        if i == 0:
            ax.set_ylabel("Connection Setup Bytes (KB)")
        ax.grid(True)
        ax.legend()
    fig.suptitle("R3 — Connection Setup/Handshake Bytes vs. Subscriber Count", y=0.98)
    fig.tight_layout()
    plt.savefig(results_dir / "r3_handshake_bytes.png", dpi=300)
    plt.close()
    print("Generated r3_handshake_bytes.png")

    # Plot 2: Asymmetric Operation Count vs N subscribers
    fig, axes = plt.subplots(1, 2, figsize=(12, 5.5), sharey=True)
    for i, lvl in enumerate([3, 5]):
        ax = axes[i]
        d = data_by_level[lvl]
        ax.plot(d["subs"], d["tls_asym"], "o-", label="PQC-TLS-MQTT (Server-Only)", color="#d62728", linewidth=2)
        ax.plot(d["subs"], d["dlst_asym"], "s-", label="PQC-DLST-MQTT", color="#1f77b4", linewidth=2)
        ax.set_title(f"Level {lvl} ({LEVEL_KEM[lvl]} / {LEVEL_SIG[lvl]})")
        ax.set_xlabel("Number of Subscribers (N)")
        if i == 0:
            ax.set_ylabel("Total Asymmetric Operations (KEM + Signature)")
        ax.grid(True)
        ax.legend()
    fig.suptitle("R3 — Total Connection Asymmetric Operations vs. Subscriber Count", y=0.98)
    fig.tight_layout()
    plt.savefig(results_dir / "r3_asym_ops.png", dpi=300)
    plt.close()
    print("Generated r3_asym_ops.png")

    # Plot 3: Per-message Wire Bytes vs N subscribers (Unicast vs Multicast)
    fig, axes = plt.subplots(1, 2, figsize=(12, 5.5), sharey=True)
    for i, lvl in enumerate([3, 5]):
        ax = axes[i]
        d = data_by_level[lvl]
        ax.plot(d["subs"], d["tls_msg_bytes"], "o-", label="PQC-TLS (Unicast)", color="#d62728", linewidth=2)
        ax.plot(d["subs"], d["dlst_msg_uni"], "^--", label="PQC-DLST (Unicast/TCP)", color="#e377c2", linewidth=1.5)
        ax.plot(d["subs"], d["dlst_msg_mcast"], "s-", label="PQC-DLST (Multicast/UDP)", color="#2ca02c", linewidth=2.5)
        ax.set_title(f"Level {lvl} (Payload = 64B)")
        ax.set_xlabel("Number of Subscribers (N)")
        if i == 0:
            ax.set_ylabel("Per-Message Wire Bytes (Bytes)")
        ax.grid(True)
        ax.legend()
    fig.suptitle("R3 — Per-Message Wire Bytes: Unicast vs. Multicast Scalability", y=0.98)
    fig.tight_layout()
    plt.savefig(results_dir / "r3_per_msg_bytes.png", dpi=300)
    plt.close()
    print("Generated r3_per_msg_bytes.png")

    # Plot 4: Broker Symmetric Operations per Message vs N subscribers
    fig, axes = plt.subplots(1, 2, figsize=(12, 5.5), sharey=True)
    for i, lvl in enumerate([3, 5]):
        ax = axes[i]
        d = data_by_level[lvl]
        ax.plot(d["subs"], d["tls_broker_sym"], "o-", label="PQC-TLS-MQTT (N+1 ops)", color="#d62728", linewidth=2)
        ax.plot(d["subs"], d["dlst_broker_sym"], "s-", label="PQC-DLST-MQTT (0 ops)", color="#1f77b4", linewidth=2.5)
        ax.set_title(f"Level {lvl}")
        ax.set_xlabel("Number of Subscribers (N)")
        if i == 0:
            ax.set_ylabel("Broker Symmetric Ops per Message")
        ax.grid(True)
        ax.legend()
    fig.suptitle("R3 — Broker Cryptographic Symmetric Load per Message vs. Subscriber Count", y=0.98)
    fig.tight_layout()
    plt.savefig(results_dir / "r3_broker_sym_ops.png", dpi=300)
    plt.close()
    print("Generated r3_broker_sym_ops.png")

    # Export a text file containing key stats
    with open(results_dir / "r3_summary_stats.txt", "w") as f:
        f.write("R3 SCALABILITY SUMMARY STATISTICS\n")
        f.write("=================================\n\n")
        for lvl in [3, 5]:
            d = data_by_level[lvl]
            f.write(f"Level {lvl} ({LEVEL_KEM[lvl]} / {LEVEL_SIG[lvl]}):\n")
            
            # Handshake stats
            tls_hs_10, dlst_hs_10 = d['tls_hs'][0], d['dlst_hs'][0]
            if dlst_hs_10 < tls_hs_10:
                hs_diff_10_str = f"({(tls_hs_10 - dlst_hs_10) / tls_hs_10 * 100:.1f}% reduction)"
            else:
                hs_diff_10_str = f"({(dlst_hs_10 - tls_hs_10) / tls_hs_10 * 100:.1f}% increase - due to mandatory mutual auth)"
                
            tls_hs_200, dlst_hs_200 = d['tls_hs'][-1], d['dlst_hs'][-1]
            if dlst_hs_200 < tls_hs_200:
                hs_diff_200_str = f"({(tls_hs_200 - dlst_hs_200) / tls_hs_200 * 100:.1f}% reduction)"
            else:
                hs_diff_200_str = f"({(dlst_hs_200 - tls_hs_200) / tls_hs_200 * 100:.1f}% increase - due to mandatory mutual auth)"

            f.write(f"  Handshake Bytes at N=10:\n")
            f.write(f"    PQC-TLS:  {tls_hs_10:.2f} KB\n")
            f.write(f"    PQC-DLST: {dlst_hs_10:.2f} KB {hs_diff_10_str}\n")
            f.write(f"  Handshake Bytes at N=200:\n")
            f.write(f"    PQC-TLS:  {tls_hs_200:.2f} KB\n")
            f.write(f"    PQC-DLST: {dlst_hs_200:.2f} KB {hs_diff_200_str}\n")
            
            f.write(f"  Per-Message Wire Bytes at N=200 (64B payload):\n")
            f.write(f"    PQC-TLS (Unicast):       {d['tls_msg_bytes'][-1]} B\n")
            f.write(f"    PQC-DLST (Unicast):      {d['dlst_msg_uni'][-1]} B\n")
            f.write(f"    PQC-DLST (Multicast):    {d['dlst_msg_mcast'][-1]} B ({(d['tls_msg_bytes'][-1]-d['dlst_msg_mcast'][-1])/d['tls_msg_bytes'][-1]*100:.1f}% reduction)\n")
            
            f.write(f"  Broker Symmetric Crypto Ops at N=200:\n")
            f.write(f"    PQC-TLS:  {d['tls_broker_sym'][-1]} ops\n")
            f.write(f"    PQC-DLST: {d['dlst_broker_sym'][-1]} ops (100% offload)\n\n")
            
    print("Generated r3_summary_stats.txt")

if __name__ == "__main__":
    main()
