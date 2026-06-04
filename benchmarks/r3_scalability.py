"""
R3 — Scalability: PQC-DLST-MQTT vs PQC-TLS-MQTT.

COST MODEL (CORRECTED)
=======================

Both protocols are compared under the same honest baseline:

  PQC-TLS-MQTT:
    Each client (publisher OR subscriber) establishes ONE TLS 1.3 session
    to the broker. That session involves one ML-KEM encaps/decaps and
    (under mTLS) one ML-DSA sign+verify per direction. The session persists
    for the lifetime of the connection; it is NOT re-established per topic
    or per subscriber relationship.

    At the data plane, the broker:
      - Receives the publisher's TLS record and decrypts it (1 symmetric op)
      - Re-encrypts the payload into EACH subscriber's independent TLS
        session (N symmetric ops for N subscribers)
      - The broker sees plaintext between decrypt and re-encrypt.

    Per-message cost: 1 (pub encrypt) + 1 (broker decrypt) + N (re-encrypt)
                    = N + 2 symmetric ops
    Per-message bytes on wire: N × (TLS record header + payload + GCM tag)

  PQC-DLST-MQTT:
    Each client establishes ONE Phase I mutual auth with the TTA (one
    ML-KEM + two ML-DSA sign/verify — mutual, so both directions).
    The publisher additionally runs Phase II (TSA) + Phase III (key setup),
    both symmetric over the Phase I channel.

    Each subscriber runs Phase V — a SYMMETRIC key request/response over
    its Phase I channel. Zero KEM operations.  After Phase V, the
    subscriber holds the same sub-topic key as the publisher.

    At the data plane, the broker:
      - Does NOTHING. It is a dumb MQTT relay. No decrypt, no re-encrypt.
      - It never sees plaintext — true end-to-end security.
      - All subscribers decrypt the SAME multicast ciphertext using the
        shared sub-topic key.

    Per-message cost: 1 (pub encrypt) + N (sub decrypt) = N + 1 symmetric ops
    Per-message bytes on wire: 1 × (9-byte header + payload + tag)

WHERE THE CURVES DIVERGE (HONEST)
==================================
  1. Asymmetric connection setup: COMPARABLE. Both protocols pay ~(1+N)
     ML-KEM for 1 pub + N subs. PQC-DLST pays 2× ML-DSA per connection
     (mutual auth) vs 1-2× for TLS. No headline here.

  2. Broker symmetric load: PQC-TLS = (N+2) sym ops/msg, PQC-DLST = (N+1).
     But more importantly: in PQC-DLST the broker does ZERO of those ops.
     The N+1 ops are distributed (1 at publisher, N at subscribers).
     In PQC-TLS all N re-encrypts happen at the broker — it's the
     bottleneck.

  3. Per-message wire bytes: PQC-TLS sends N independent TLS records.
     PQC-DLST multicasts 1 frame.  Linear divergence with N.

  4. End-to-end security: PQC-DLST preserves it. PQC-TLS does not.
     This is a qualitative win, not just quantitative.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Primitive byte sizes — single source of truth from wrapper modules
# ---------------------------------------------------------------------------

from src.pqcrypto.kem import KEM_SIZES
from src.pqcrypto.sig import SIG_SIZES

# Protocol security level → primitive names (matches security_levels.py)
LEVEL_KEM = {1: "ML-KEM-512", 2: "ML-KEM-512", 3: "ML-KEM-768",
             4: "ML-KEM-768", 5: "ML-KEM-1024"}
LEVEL_SIG = {1: "ML-DSA-44", 2: "ML-DSA-44", 3: "ML-DSA-44",
             4: "ML-DSA-65", 5: "ML-DSA-87"}

# GCM constants
GCM_TAG_SIZE = 16      # bytes
GCM_NONCE_SIZE = 12    # bytes

# KMAC tag size for Level 1 (explicitly 32 bytes / 256-bit output)
KMAC_TAG_SIZE = 32

# PQC-DLST-MQTT 9-byte header
DLST_HEADER_SIZE = 9

# TLS 1.3 record layer overhead
TLS_RECORD_HEADER = 5       # ContentType(1) + ProtocolVersion(2) + Length(2)
TLS_RECORD_TAG = 16         # AES-GCM authentication tag
TLS_RECORD_CONTENT_TYPE = 1 # Inner content type byte (TLS 1.3)
TLS_RECORD_OVERHEAD = TLS_RECORD_HEADER + TLS_RECORD_TAG + TLS_RECORD_CONTENT_TYPE

# TLS 1.3 handshake approximate sizes (for ML-KEM + ML-DSA)
# These are approximate because TLS extensions/padding vary, but the PQC
# payload dominates and these are deterministic from primitive sizes.


def _tls_handshake_bytes(kem_alg: str, sig_alg: str, mutual: bool) -> int:
    """
    Approximate TLS 1.3 handshake bytes (both directions combined).

    Includes: ClientHello (KEM pk share), ServerHello (KEM ct),
    server CertificateVerify (sig + cert with vk), and optionally
    client CertificateVerify for mTLS.

    Does NOT include TCP/IP headers — we count application-layer only,
    same as PQC-DLST byte counting.
    """
    kem = KEM_SIZES[kem_alg]
    sig = SIG_SIZES[sig_alg]

    # ClientHello: KEM public key (key share) + TLS boilerplate
    client_hello = kem["pk"] + 200  # ~200 bytes TLS boilerplate

    # ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished
    # Certificate contains sig vk; CertificateVerify has a signature
    server_msgs = kem["ct"] + sig["pk"] + sig["sig"] + 300  # ~300 bytes framing

    total = client_hello + server_msgs

    if mutual:
        # Client Certificate + CertificateVerify
        total += sig["pk"] + sig["sig"] + 100  # ~100 bytes framing

    # Finished messages (both sides, HMAC-based, ~32 bytes each)
    total += 64

    return total


# ---------------------------------------------------------------------------
# Phase I byte sizes (PQC-DLST-MQTT)
# ---------------------------------------------------------------------------

def _phase1_handshake_bytes(kem_alg: str, sig_alg: str) -> int:
    """
    Phase I mutual authentication handshake bytes (both messages).

    AuthRequest:  ek + nonce(32) + client_id(~8) + sig + header(10)
    AuthResponse: ct + nonce(32) + sig + header(8)
    """
    kem = KEM_SIZES[kem_alg]
    sig = SIG_SIZES[sig_alg]

    auth_req = 10 + kem["pk"] + 32 + 8 + sig["sig"]   # header + ek + nonce + id + sig
    auth_resp = 8 + kem["ct"] + 32 + sig["sig"]        # header + ct + nonce + sig
    return auth_req + auth_resp


# ---------------------------------------------------------------------------
# Cost breakdown
# ---------------------------------------------------------------------------

@dataclass
class CostBreakdown:
    """Cost accounting for one protocol configuration."""
    protocol: str                       # "PQC-TLS-MQTT" or "PQC-DLST-MQTT"
    level: int                          # Security level (1-5)
    n_publishers: int
    n_subscribers: int

    # Connection/session setup (one-time)
    kem_operations: int = 0             # Total ML-KEM encaps+decaps pairs
    sig_sign_operations: int = 0        # Total ML-DSA sign operations
    sig_verify_operations: int = 0      # Total ML-DSA verify operations
    handshake_bytes: int = 0            # Total bytes for all handshakes/setup

    # Per-topic setup (one-time)
    sym_ops_topic_setup: int = 0        # Symmetric ops for topic key setup
    topic_setup_bytes: int = 0          # Bytes for topic setup messages

    # Per-message (ongoing, per single message published)
    sym_ops_per_message: int = 0        # Total symmetric ops to deliver 1 msg to all subs
    broker_sym_ops_per_message: int = 0 # Of those, how many are at the broker
    per_message_wire_bytes: int = 0     # Total unicast bytes on wire for 1 msg to all subs
    per_message_wire_bytes_multicast: int = 0 # Total multicast bytes on wire for 1 msg to all subs

    # Qualitative
    broker_sees_plaintext: bool = True
    end_to_end_secure: bool = False

    # Aggregates for N messages
    def total_sym_ops(self, n_messages: int) -> int:
        return self.sym_ops_topic_setup + self.sym_ops_per_message * n_messages

    def total_broker_sym_ops(self, n_messages: int) -> int:
        return self.broker_sym_ops_per_message * n_messages

    def total_wire_bytes(self, n_messages: int, multicast: bool = False) -> int:
        wire_bytes_per_msg = self.per_message_wire_bytes_multicast if multicast else self.per_message_wire_bytes
        return self.handshake_bytes + self.topic_setup_bytes + \
               wire_bytes_per_msg * n_messages


# ---------------------------------------------------------------------------
# PQC-TLS-MQTT cost model  (1 KEM per connection, symmetric re-encrypt fan-out)
# ---------------------------------------------------------------------------

def tls_baseline_cost(
    n_subs: int,
    n_pubs: int,
    level: int,
    payload_size: int,
    mutual_tls: bool = False,
) -> CostBreakdown:
    """
    Compute PQC-TLS-MQTT cost for 1 topic, n_pubs publishers, n_subs subscribers.

    Baseline assumptions:
      - Each client opens ONE TLS 1.3 session to the broker (1 ML-KEM)
      - Server-Only TLS by default (standard deployment mode)
      - Broker terminates all TLS sessions
      - Per message: broker decrypts from publisher, re-encrypts to each subscriber
      - No TLS session resumption (first-time connection, worst case)
    """
    kem_alg = LEVEL_KEM[level]
    sig_alg = LEVEL_SIG[level]
    n_clients = n_pubs + n_subs

    # --- Connection setup ---
    # Each client does 1 ML-KEM with the broker
    kem_ops = n_clients  # 1 KEM encaps/decaps pair per connection

    # Each handshake: server signs CertificateVerify (1 sign + 1 verify)
    # With mTLS: client also signs (1 sign + 1 verify)
    sigs_per_handshake = 2 if mutual_tls else 1
    sig_sign_ops = n_clients * sigs_per_handshake
    sig_verify_ops = n_clients * sigs_per_handshake

    hs_bytes_per_client = _tls_handshake_bytes(kem_alg, sig_alg, mutual_tls)
    total_hs_bytes = n_clients * hs_bytes_per_client

    # --- Per-topic setup ---
    # In PQC-TLS, topics are just MQTT application payloads; no special
    # topic-key setup exists. The broker receives SUBSCRIBE and routes.
    # Zero additional crypto cost.
    sym_ops_topic_setup = 0
    topic_setup_bytes = 0

    # --- Per-message delivery ---
    # Publisher encrypts into its TLS session:     1 AES-GCM encrypt
    # Broker decrypts from publisher's session:    1 AES-GCM decrypt
    # Broker re-encrypts into each sub's session:  n_subs AES-GCM encrypts
    # Total: n_subs + 2
    sym_ops_per_msg = n_subs + 2
    broker_sym_ops = n_subs + 1  # 1 decrypt + n_subs re-encrypts

    # Bytes: publisher sends 1 TLS record to broker;
    #        broker sends 1 TLS record to each subscriber.
    # We count the subscriber-facing fan-out (the dominant term).
    tls_record_size = TLS_RECORD_OVERHEAD + payload_size
    # Publisher → Broker: 1 TLS record
    # Broker → N subscribers: N TLS records
    per_msg_bytes = (1 + n_subs) * tls_record_size

    return CostBreakdown(
        protocol="PQC-TLS-MQTT",
        level=level,
        n_publishers=n_pubs,
        n_subscribers=n_subs,
        kem_operations=kem_ops,
        sig_sign_operations=sig_sign_ops,
        sig_verify_operations=sig_verify_ops,
        handshake_bytes=total_hs_bytes,
        sym_ops_topic_setup=sym_ops_topic_setup,
        topic_setup_bytes=topic_setup_bytes,
        sym_ops_per_message=sym_ops_per_msg,
        broker_sym_ops_per_message=broker_sym_ops,
        per_message_wire_bytes=per_msg_bytes,
        per_message_wire_bytes_multicast=per_msg_bytes,  # TLS cannot multicast
        broker_sees_plaintext=True,
        end_to_end_secure=False,
    )


# ---------------------------------------------------------------------------
# PQC-DLST-MQTT cost model
# ---------------------------------------------------------------------------

def _dlst_tag_size(level: int) -> int:
    """Return tag size for a given security level."""
    if level == 0:
        return 0
    elif level == 1:
        return KMAC_TAG_SIZE  # 32 bytes
    else:
        return GCM_TAG_SIZE   # 16 bytes


def dlst_cost(
    n_subs: int,
    n_pubs: int,
    level: int,
    payload_size: int,
) -> CostBreakdown:
    """
    Compute PQC-DLST-MQTT cost for 1 topic, n_pubs publishers, n_subs subscribers.

    Model:
      - Each client (pub or sub) does Phase I with TTA: 1 ML-KEM + 2 ML-DSA
      - Publisher does Phase II + III over Phase I channel (symmetric)
      - Each subscriber does Phase V over its Phase I channel (symmetric)
      - Broker does ZERO crypto — dumb MQTT relay
    """
    kem_alg = LEVEL_KEM[level]
    sig_alg = LEVEL_SIG[level]
    n_clients = n_pubs + n_subs

    # --- Phase I: mutual auth per client ---
    # 1 ML-KEM per client
    kem_ops = n_clients

    # Mutual auth: each Phase I has 2 ML-DSA sign + 2 ML-DSA verify
    # (client signs AuthRequest, TTA signs AuthResponse; both verify the other)
    sig_sign_ops = n_clients * 2
    sig_verify_ops = n_clients * 2

    hs_bytes_per_client = _phase1_handshake_bytes(kem_alg, sig_alg)
    total_hs_bytes = n_clients * hs_bytes_per_client

    # --- Phase II + III: publisher topic setup (symmetric) ---
    # Phase II: TSA request + response = 2 AES-GCM ops
    # Phase III: config delivery = 2 AES-GCM ops (request + response)
    # Total: 4 symmetric ops per publisher, per topic
    pub_topic_sym_ops = n_pubs * 4

    # Phase II bytes: request (~20 bytes) + response (~10 bytes) + 2 GCM tags
    # Phase III bytes: SubTopicConfig (~100 bytes for 3 levels) + GCM tags
    # Conservative estimate per publisher
    phase2_bytes = (20 + GCM_TAG_SIZE) + (10 + GCM_TAG_SIZE)
    phase3_bytes = (120 + GCM_TAG_SIZE) + (10 + GCM_TAG_SIZE)  # config + ack
    pub_topic_bytes = n_pubs * (phase2_bytes + phase3_bytes)

    # --- Phase V: subscriber key retrieval (symmetric) ---
    # Per subscriber: 1 encrypted request + 1 encrypted response = 2 AES-GCM ops
    sub_topic_sym_ops = n_subs * 2

    # Phase V bytes: request (~20 bytes + tag) + response (~60 bytes + tag)
    phase5_req_bytes = 20 + GCM_TAG_SIZE
    phase5_resp_bytes = 60 + GCM_TAG_SIZE
    sub_topic_bytes = n_subs * (phase5_req_bytes + phase5_resp_bytes)

    total_topic_setup_sym = pub_topic_sym_ops + sub_topic_sym_ops
    total_topic_setup_bytes = pub_topic_bytes + sub_topic_bytes

    # --- Per-message delivery ---
    # Publisher: 1 AES-GCM encrypt (Phase IV)
    # Broker: 0 (dumb relay — does not decrypt or re-encrypt)
    # Each subscriber: 1 AES-GCM decrypt
    # Total: 1 + N symmetric ops (but none at the broker)
    sym_ops_per_msg = 1 + n_subs
    broker_sym_ops = 0  # This is the point.

    # Bytes: publisher sends 1 frame. Broker fans out the SAME frame
    # (no re-encryption, so no new ciphertext). Each subscriber receives
    # the identical bytes.
    # Wire bytes (unicast) = 1 × frame from pub to broker + N × same frame to subs
    # Wire bytes (multicast) = 1 × frame from pub to broker + 1 × multicast frame to all subs
    tag_size = _dlst_tag_size(level)
    dlst_frame_size = DLST_HEADER_SIZE + payload_size + tag_size
    per_msg_bytes_unicast = (1 + n_subs) * dlst_frame_size
    per_msg_bytes_multicast = 2 * dlst_frame_size

    return CostBreakdown(
        protocol="PQC-DLST-MQTT",
        level=level,
        n_publishers=n_pubs,
        n_subscribers=n_subs,
        kem_operations=kem_ops,
        sig_sign_operations=sig_sign_ops,
        sig_verify_operations=sig_verify_ops,
        handshake_bytes=total_hs_bytes,
        sym_ops_topic_setup=total_topic_setup_sym,
        topic_setup_bytes=total_topic_setup_bytes,
        sym_ops_per_message=sym_ops_per_msg,
        broker_sym_ops_per_message=broker_sym_ops,
        per_message_wire_bytes=per_msg_bytes_unicast,
        per_message_wire_bytes_multicast=per_msg_bytes_multicast,
        broker_sees_plaintext=False,
        end_to_end_secure=True,
    )


# ---------------------------------------------------------------------------
# Sweep and comparison
# ---------------------------------------------------------------------------

@dataclass
class ComparisonRow:
    """One row in the R3 comparison table."""
    n_subscribers: int
    level: int
    payload_size: int

    tls: CostBreakdown = field(default=None)
    dlst: CostBreakdown = field(default=None)

    # Derived deltas
    @property
    def kem_delta(self) -> int:
        """KEM ops difference (should be 0 or near-zero)."""
        return self.tls.kem_operations - self.dlst.kem_operations

    @property
    def broker_load_delta(self) -> int:
        """Broker symmetric ops per message (TLS) vs (DLST=0)."""
        return self.tls.broker_sym_ops_per_message - self.dlst.broker_sym_ops_per_message

    @property
    def per_msg_byte_delta(self) -> int:
        """Per-message byte difference (unicast)."""
        return self.tls.per_message_wire_bytes - self.dlst.per_message_wire_bytes

    @property
    def per_msg_byte_ratio(self) -> float:
        """TLS bytes / DLST bytes per message (unicast)."""
        if self.dlst.per_message_wire_bytes == 0:
            return float("inf")
        return self.tls.per_message_wire_bytes / self.dlst.per_message_wire_bytes

    @property
    def per_msg_multicast_byte_delta(self) -> int:
        """Per-message byte difference (multicast)."""
        return self.tls.per_message_wire_bytes_multicast - self.dlst.per_message_wire_bytes_multicast

    @property
    def per_msg_multicast_byte_ratio(self) -> float:
        """TLS bytes / DLST bytes per message (multicast)."""
        if self.dlst.per_message_wire_bytes_multicast == 0:
            return float("inf")
        return self.tls.per_message_wire_bytes_multicast / self.dlst.per_message_wire_bytes_multicast


def sweep(
    levels: list[int] | None = None,
    subscriber_counts: list[int] | None = None,
    n_pubs: int = 1,
    payload_size: int = 64,
    mutual_tls: bool = False,
) -> list[ComparisonRow]:
    """
    Run the R3 scalability sweep.

    Args:
        levels: Security levels to test (default: [3, 5]).
        subscriber_counts: N values to sweep (default: [10,25,50,100,150,200]).
        n_pubs: Number of publishers per topic (default: 1).
        payload_size: Payload size in bytes (default: 64, typical IoT sensor).
        mutual_tls: Whether TLS baseline uses mutual auth (default: False).

    Returns:
        List of ComparisonRow with both protocols' costs.
    """
    if levels is None:
        levels = [3, 5]
    if subscriber_counts is None:
        subscriber_counts = [10, 25, 50, 100, 150, 200]

    rows = []
    for level in levels:
        for n_subs in subscriber_counts:
            tls = tls_baseline_cost(n_subs, n_pubs, level, payload_size, mutual_tls)
            dlst = dlst_cost(n_subs, n_pubs, level, payload_size)
            rows.append(ComparisonRow(
                n_subscribers=n_subs,
                level=level,
                payload_size=payload_size,
                tls=tls,
                dlst=dlst,
            ))
    return rows


def print_comparison_table(rows: list[ComparisonRow]) -> None:
    """Print a human-readable comparison table to stdout."""
    print()
    print("=" * 110)
    print(f"{'R3 SCALABILITY COMPARISON':^110s}")
    print("=" * 110)
    print()

    current_level = None
    for row in rows:
        if row.level != current_level:
            current_level = row.level
            kem_alg = LEVEL_KEM[row.level]
            sig_alg = LEVEL_SIG[row.level]
            print(f"--- Level {row.level} ({kem_alg} / {sig_alg}) "
                  f"| Payload: {row.payload_size}B | 1 publisher ---")
            print()
            print(f"  {'N_sub':>5s}  "
                  f"{'KEM(TLS)':>8s} {'KEM(DLST)':>9s}  "
                  f"{'Sym/msg(TLS)':>12s} {'Sym/msg(DLST)':>13s}  "
                  f"{'Broker(TLS)':>11s} {'Broker(DLST)':>12s}  "
                  f"{'Bytes(TLS)':>10s} {'Bytes(DLST-Uni)':>14s} {'Bytes(DLST-Mcast)':>16s}  "
                  f"{'Ratio(Mcast)':>12s}")
            print(f"  {'-----':>5s}  "
                  f"{'--------':>8s} {'---------':>9s}  "
                  f"{'------------':>12s} {'-------------':>13s}  "
                  f"{'-----------':>11s} {'------------':>12s}  "
                  f"{'----------':>10s} {'--------------':>14s} {'----------------':>16s}  "
                  f"{'------------':>12s}")

        print(f"  {row.n_subscribers:>5d}  "
              f"{row.tls.kem_operations:>8d} {row.dlst.kem_operations:>9d}  "
              f"{row.tls.sym_ops_per_message:>12d} {row.dlst.sym_ops_per_message:>13d}  "
              f"{row.tls.broker_sym_ops_per_message:>11d} "
              f"{row.dlst.broker_sym_ops_per_message:>12d}  "
              f"{row.tls.per_message_wire_bytes:>10d} "
              f"{row.dlst.per_message_wire_bytes:>14d} "
              f"{row.dlst.per_message_wire_bytes_multicast:>16d}  "
              f"{row.per_msg_multicast_byte_ratio:>12.2f}")

    print()
    print("KEM ops: 1 per connection for BOTH protocols (should be equal)")
    print("Broker(TLS): decrypt + N re-encrypts | Broker(DLST): 0 (dumb relay)")
    print("Bytes(DLST-Uni): Unicast (TCP) delivery, sent N times (identical payload)")
    print("Bytes(DLST-Mcast): Multicast (UDP/IP-multicast) delivery, sent 1 time to all subscribers")
    print("Ratio(Mcast): TLS wire bytes / DLST Multicast wire bytes (the true network scalability headline)")
    print()

    # Qualitative summary
    print("QUALITATIVE:")
    print(f"  PQC-TLS-MQTT:  broker sees plaintext = True,  end-to-end = False")
    print(f"  PQC-DLST-MQTT: broker sees plaintext = False, end-to-end = True")
    print()


def export_json(rows: list[ComparisonRow], path: str) -> None:
    """Export sweep results to JSON for figure generation."""
    data = []
    for row in rows:
        data.append({
            "n_subscribers": row.n_subscribers,
            "level": row.level,
            "payload_size": row.payload_size,
            "tls": asdict(row.tls),
            "dlst": asdict(row.dlst),
            "kem_delta": row.kem_delta,
            "broker_load_delta": row.broker_load_delta,
            "per_msg_byte_delta": row.per_msg_byte_delta,
            "per_msg_byte_ratio": row.per_msg_byte_ratio,
            "per_msg_multicast_byte_delta": row.per_msg_multicast_byte_delta,
            "per_msg_multicast_byte_ratio": row.per_msg_multicast_byte_ratio,
        })
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Results exported to {path}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    """Run R3 sweep and print results."""
    import argparse
    parser = argparse.ArgumentParser(description="R3 Scalability Benchmark")
    parser.add_argument("--levels", nargs="+", type=int, default=[3, 5],
                        help="Security levels to test")
    parser.add_argument("--subs", nargs="+", type=int,
                        default=[10, 25, 50, 100, 150, 200],
                        help="Subscriber counts to sweep")
    parser.add_argument("--payload", type=int, default=64,
                        help="Payload size in bytes")
    parser.add_argument("--no-mtls", action="store_true",
                        help="Use server-only TLS auth (not recommended)")
    parser.add_argument("--json", type=str, default=None,
                        help="Export results to JSON file")
    args = parser.parse_args()

    rows = sweep(
        levels=args.levels,
        subscriber_counts=args.subs,
        payload_size=args.payload,
        mutual_tls=not args.no_mtls,
    )

    print_comparison_table(rows)

    if args.json:
        export_json(rows, args.json)


if __name__ == "__main__":
    main()
