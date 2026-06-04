"""
R2 — Communication Overhead.
Calculates the exact serialized bytes for all five core phases of PQC-DLST-MQTT.
Sweeps payload sizes (16, 64, 256, 1024 bytes) and exports results to results/r2_communication.json.
"""

import json
import os
from pathlib import Path

from src.protocol.security_levels import Priority
from src.protocol.common import HeaderCodec
from src.protocol.phase1_auth import AuthRequest, AuthResponse
from src.protocol.phase2_tsa import TSARequest, TSAResponse
from src.protocol.phase3_agreement import SubTopicConfig
from src.protocol.phase5_retrieval import KeyRequest, KeyResponse
from benchmarks.r3_scalability import LEVEL_KEM, LEVEL_SIG, KEM_SIZES, SIG_SIZES, GCM_TAG_SIZE, KMAC_TAG_SIZE, DLST_HEADER_SIZE

def _dlst_tag_size(level: int) -> int:
    if level == 1:
        return KMAC_TAG_SIZE
    else:
        return GCM_TAG_SIZE

def run_communication_analysis():
    # We sweep security levels 1 to 5
    levels = [1, 2, 3, 4, 5]
    payload_sizes = [16, 64, 256, 1024]
    
    results = {}

    print("Running communication overhead analysis (exact serialized byte sizes)...")

    for level in levels:
        results[level] = {}
        kem_alg = LEVEL_KEM[level]
        sig_alg = LEVEL_SIG[level]
        
        kem_pk_size = KEM_SIZES[kem_alg]["pk"]
        kem_ct_size = KEM_SIZES[kem_alg]["ct"]
        sig_size = SIG_SIZES[sig_alg]["sig"]
        
        # --- Phase I ---
        p1_req = AuthRequest(
            encapsulation_key=b"\x00" * kem_pk_size,
            nonce_client=b"\x00" * 32,
            client_id=b"client123",
            sequence_number=1,
            signature=b"\x00" * sig_size
        )
        p1_resp = AuthResponse(
            ciphertext=b"\x00" * kem_ct_size,
            nonce_tta=b"\x00" * 32,
            sequence_number=1,
            signature=b"\x00" * sig_size
        )
        p1_req_bytes = len(p1_req.serialize())
        p1_resp_bytes = len(p1_resp.serialize())
        
        # --- Phase II ---
        # Publisher support range is defined from Level 1 up to 'level'
        p2_req = TSARequest(topic="sensors/temp", priority=Priority.MEDIUM, level_min=1, level_max=level)
        p2_resp = TSAResponse(accepted=True, negotiated_level_min=1, negotiated_level_max=level, reason="")
        # These are encrypted over Phase I, so they add GCM_TAG_SIZE (16B)
        p2_req_bytes = len(p2_req.serialize()) + GCM_TAG_SIZE
        p2_resp_bytes = len(p2_resp.serialize()) + GCM_TAG_SIZE
        
        # --- Phase III ---
        subtopic_keys = {l: b"\x00" * 32 for l in range(1, level + 1)}
        seed_per_level = {l: b"\x00" * 32 for l in range(1, level + 1)}
        p3_config = SubTopicConfig(
            topic="sensors/temp",
            publisher_id=1,
            epoch_id=1,
            level_min=1,
            level_max=level,
            current_level=level,
            subtopic_keys=subtopic_keys,
            salt_epoch=b"\x00" * 6,
            seed_per_level=seed_per_level
        )
        # Config delivery is encrypted (+16B GCM tag)
        p3_config_bytes = len(p3_config.serialize()) + GCM_TAG_SIZE
        # Ack is modeled as a 10-byte message encrypted (+16B GCM tag)
        p3_ack_bytes = 10 + GCM_TAG_SIZE
        
        # --- Phase V ---
        p5_req = KeyRequest(topic="sensors/temp", subscriber_id=b"client123")
        p5_resp = KeyResponse(
            accepted=True,
            topic="sensors/temp",
            epoch_id=1,
            current_level=level,
            level_min=1,
            level_max=level,
            subtopic_key=b"\x00" * 32,
            salt_epoch=b"\x00" * 6,
            reason=""
        )
        # Encrypted over Phase I (+16B GCM tag)
        p5_req_bytes = len(p5_req.serialize()) + GCM_TAG_SIZE
        p5_resp_bytes = len(p5_resp.serialize()) + GCM_TAG_SIZE
        
        results[level]["static_phases"] = {
            "phase1_request": p1_req_bytes,
            "phase1_response": p1_resp_bytes,
            "phase1_total": p1_req_bytes + p1_resp_bytes,
            "phase2_request": p2_req_bytes,
            "phase2_response": p2_resp_bytes,
            "phase2_total": p2_req_bytes + p2_resp_bytes,
            "phase3_config": p3_config_bytes,
            "phase3_ack": p3_ack_bytes,
            "phase3_total": p3_config_bytes + p3_ack_bytes,
            "phase5_request": p5_req_bytes,
            "phase5_response": p5_resp_bytes,
            "phase5_total": p5_req_bytes + p5_resp_bytes,
        }
        
        # --- Phase IV (Data Plane) Sweep ---
        results[level]["data_plane"] = {}
        for p_size in payload_sizes:
            tag_size = _dlst_tag_size(level)
            frame_size = DLST_HEADER_SIZE + p_size + tag_size
            results[level]["data_plane"][p_size] = {
                "header_bytes": DLST_HEADER_SIZE,
                "payload_bytes": p_size,
                "tag_bytes": tag_size,
                "total_bytes": frame_size,
                "overhead_percent": (DLST_HEADER_SIZE + tag_size) / frame_size * 100.0
            }

    # Export to JSON
    results_dir = Path(os.environ.get("RESULTS_DIR", Path(__file__).resolve().parent.parent / "results"))
    results_dir.mkdir(parents=True, exist_ok=True)
    with open(results_dir / "r2_communication.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results exported to {results_dir / 'r2_communication.json'}")

    # Generate Markdown Table outputs
    print("\n\n### R2 — Control Plane Communication Overhead (Markdown)\n")
    print("| Level | Phase I Request | Phase I Response | Phase II Request | Phase II Response | Phase III Config | Phase III Ack | Phase V Request | Phase V Response |")
    print("| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
    for lvl in levels:
        sp = results[lvl]["static_phases"]
        print(f"| L{lvl} | {sp['phase1_request']} B | {sp['phase1_response']} B | {sp['phase2_request']} B | {sp['phase2_response']} B | {sp['phase3_config']} B | {sp['phase3_ack']} B | {sp['phase5_request']} B | {sp['phase5_response']} B |")
    
    print("\nNote: Epoch rotation (Phase VI) is executed as a single Phase V retrieval flow (KeyRequest + KeyResponse) on demand.")
    
    print("\n\n### R2 — Data Plane Per-Message Overhead Sweep (Markdown)\n")
    print("| Level | Payload Size | Header Bytes | Tag Bytes | Total Frame Bytes | Overhead (%) |")
    print("| :---: | :---: | :---: | :---: | :---: | :---: |")
    for lvl in levels:
        for p_size in payload_sizes:
            dp = results[lvl]["data_plane"][p_size]
            print(f"| L{lvl} | {p_size} B | {dp['header_bytes']} B | {dp['tag_bytes']} B | {dp['total_bytes']} B | {dp['overhead_percent']:.1f}% |")
    print()

if __name__ == "__main__":
    run_communication_analysis()
