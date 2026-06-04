"""
End-to-End Integration Tests for PQC-DLST-MQTT.

Verifies:
  1. Phase I: Client (Pub/Sub) and TTA Mutual Authentication handshake.
  2. Phase II: TSA level negotiation.
  3. Phase III: SubTopic configuration delivery and acknowledgment.
  4. Phase V: Subscriber key retrieval.
  5. Phase IV: Data Plane payload encryption, Broker transmission, and decryption.
  6. ReplayGuard: Rejection of replayed and duplicate data frames.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
import struct
from src.pqcrypto.kem import KEMWrapper
from src.pqcrypto.sig import SigWrapper
from src.pqcrypto.aead import AEADWrapper
from src.pqcrypto.kdf import derive_data_iv

from src.protocol.common import HeaderCodec, SequenceNumberState, ReplayGuard
from src.protocol.phase1_auth import (
    AuthResponse,
    Phase1Client,
    transcript as phase1_transcript,
)
from src.protocol.phase2_tsa import TSARequest, TSAResponse
from src.protocol.phase3_agreement import SubTopicConfig
from src.protocol.phase5_retrieval import (
    KeyRequest,
    KeyResponse,
    encrypt_key_request,
    decrypt_key_request,
    encrypt_key_response,
    decrypt_key_response,
)
from src.protocol.security_levels import Priority


class TestEndToEndProtocolFlow:
    """Complete E2E integration verification representing standard protocol flows."""

    def test_complete_e2e_campaign(self):
        security_level = 3  # Level 3: ML-KEM-768, ML-DSA-44, AES-192-GCM, SHA3-384
        topic = "sensors/temp"
        payload = b"{\"temp\": 22.5, \"humidity\": 45.2}"

        # -----------------------------------------------------------------------
        # Setup CA & TTA
        # -----------------------------------------------------------------------
        sig = SigWrapper(security_level=security_level)
        kem = KEMWrapper(security_level=security_level)

        # TTA Key pair for signing Phase I responses
        tta_vk, tta_sk = sig.keygen()

        # -----------------------------------------------------------------------
        # Setup Publisher & Subscriber identities
        # -----------------------------------------------------------------------
        pub_id = b"pub_node_001"
        pub_vk, pub_sk = sig.keygen()

        sub_id = b"sub_node_002"
        sub_vk, sub_sk = sig.keygen()

        # -----------------------------------------------------------------------
        # Phase I: Publisher Mutual Authentication Handshake
        # -----------------------------------------------------------------------
        pub_client = Phase1Client(
            client_id=pub_id,
            security_level=security_level,
            signing_key=pub_sk,
            verification_key=pub_vk,
        )
        pub_req = pub_client.create_auth_request(sequence_number=0)

        # TTA verifies Publisher request signature
        assert sig.verify(pub_vk, pub_req.signable_content(), pub_req.signature)

        # TTA encapsulates to Publisher's ephemeral key
        pub_ss, pub_ct = kem.encaps(pub_req.encapsulation_key)

        # TTA signs Phase I response (nonce_tta must be 32 bytes)
        pub_nonce_tta = b"TTA_PUB_NONCE_32_BYTES_LONG_VAL_"
        pub_resp_sn = 1
        pub_trans = phase1_transcript(
            pub_nonce_tta,
            pub_req.nonce_client,
            pub_id,
            pub_resp_sn,
            pub_ct,
        )
        pub_resp_sig = sig.sign(tta_sk, pub_trans)

        pub_resp = AuthResponse(
            ciphertext=pub_ct,
            nonce_tta=pub_nonce_tta,
            sequence_number=pub_resp_sn,
            signature=pub_resp_sig,
        )

        # Publisher processes response and derives channel keys
        pub_k1, pub_k2 = pub_client.process_auth_response(pub_resp, tta_vk)
        assert pub_k1 is not None
        assert pub_k2 is not None

        # -----------------------------------------------------------------------
        # Phase I: Subscriber Mutual Authentication Handshake
        # -----------------------------------------------------------------------
        sub_client = Phase1Client(
            client_id=sub_id,
            security_level=security_level,
            signing_key=sub_sk,
            verification_key=sub_vk,
        )
        sub_req = sub_client.create_auth_request(sequence_number=0)

        # TTA verifies Subscriber request signature
        assert sig.verify(sub_vk, sub_req.signable_content(), sub_req.signature)

        # TTA encapsulates to Subscriber's ephemeral key
        sub_ss, sub_ct = kem.encaps(sub_req.encapsulation_key)

        # TTA signs Phase I response (nonce_tta must be 32 bytes)
        sub_nonce_tta = b"TTA_SUB_NONCE_32_BYTES_LONG_VAL_"
        sub_resp_sn = 1
        sub_trans = phase1_transcript(
            sub_nonce_tta,
            sub_req.nonce_client,
            sub_id,
            sub_resp_sn,
            sub_ct,
        )
        sub_resp_sig = sig.sign(tta_sk, sub_trans)

        sub_resp = AuthResponse(
            ciphertext=sub_ct,
            nonce_tta=sub_nonce_tta,
            sequence_number=sub_resp_sn,
            signature=sub_resp_sig,
        )

        # Subscriber processes response and derives channel keys
        sub_k1, sub_k2 = sub_client.process_auth_response(sub_resp, tta_vk)
        assert sub_k1 is not None
        assert sub_k2 is not None

        # -----------------------------------------------------------------------
        # Phase II: TSA Level Negotiation (Publisher)
        # -----------------------------------------------------------------------
        # Publisher requests access to topic Temp with Medium Priority
        p2_req = TSARequest(
            topic=topic,
            priority=Priority.MEDIUM,
            level_min=1,
            level_max=security_level,
        )

        # Encrypted over Phase I (K1)
        aead_ctrl = AEADWrapper(4)
        nonce = b"N" * 12
        aad = b"aad"
        p2_req_ct, p2_req_tag = aead_ctrl.encrypt(pub_k1[:32], nonce, p2_req.serialize(), aad)

        # TTA decrypts and processes
        p2_req_dec = TSARequest.deserialize(aead_ctrl.decrypt(pub_k1[:32], nonce, p2_req_ct, p2_req_tag, aad))
        assert p2_req_dec.topic == topic

        # TTA grants request with negotiated level
        p2_resp = TSAResponse(
            accepted=True,
            negotiated_level_min=2,
            negotiated_level_max=security_level,
            reason="",
        )
        p2_resp_ct, p2_resp_tag = aead_ctrl.encrypt(pub_k2[:32], nonce, p2_resp.serialize(), aad)

        # Publisher decrypts TSA Response
        p2_resp_dec = TSAResponse.deserialize(aead_ctrl.decrypt(pub_k2[:32], nonce, p2_resp_ct, p2_resp_tag, aad))
        assert p2_resp_dec.accepted is True
        assert p2_resp_dec.negotiated_level_max == security_level

        # -----------------------------------------------------------------------
        # Phase III: Epoch Configuration Delivery
        # -----------------------------------------------------------------------
        # TTA generates topic keys and distributes config to Publisher
        subtopic_keys = {l: b"KEY_ST_LEVEL_" + struct.pack("!B", l) + b"_" * 19 for l in range(1, security_level + 1)}
        seed_per_level = {l: b"SEED_ST_LEVEL_" + struct.pack("!B", l) + b"_" * 18 for l in range(1, security_level + 1)}
        salt_epoch = b"SALT01"

        p3_config = SubTopicConfig(
            topic=topic,
            publisher_id=101,  # Assigned 16-bit publisher ID
            epoch_id=1,
            level_min=2,
            level_max=security_level,
            current_level=security_level,
            subtopic_keys=subtopic_keys,
            salt_epoch=salt_epoch,
            seed_per_level=seed_per_level,
        )

        p3_cfg_ct, p3_cfg_tag = aead_ctrl.encrypt(pub_k2[:32], nonce, p3_config.serialize(), aad)

        # Publisher decrypts config
        p3_config_dec = SubTopicConfig.deserialize(aead_ctrl.decrypt(pub_k2[:32], nonce, p3_cfg_ct, p3_cfg_tag, aad))
        assert p3_config_dec.topic == topic
        assert p3_config_dec.epoch_id == 1

        # Publisher extracts key for active level
        active_subtopic_key = p3_config_dec.subtopic_keys[security_level]

        # -----------------------------------------------------------------------
        # Phase V: Subscriber SA Retrieval (Key Retrieval)
        # -----------------------------------------------------------------------
        # Subscriber requests the key for topic
        p5_req = KeyRequest(topic=topic, subscriber_id=sub_id)
        sub_sn_state = SequenceNumberState()
        p5_req_ct, p5_req_tag, p5_req_iv = encrypt_key_request(p5_req, sub_k1, 0, sub_sn_state)

        # TTA decrypts request
        p5_req_dec = decrypt_key_request(p5_req_ct, p5_req_tag, p5_req_iv, sub_k1)
        assert p5_req_dec.topic == topic

        # TTA builds KeyResponse (symmetric unwrap) containing the target subtopic key
        p5_resp = KeyResponse(
            accepted=True,
            topic=topic,
            epoch_id=1,
            current_level=security_level,
            level_min=2,
            level_max=security_level,
            subtopic_key=subtopic_keys[security_level],
            salt_epoch=salt_epoch,
            reason="",
        )
        p5_resp_ct, p5_resp_tag, p5_resp_iv = encrypt_key_response(p5_resp, sub_k2, 1, sub_sn_state)

        # Subscriber decrypts response and retrieves subtopic key
        p5_resp_dec = decrypt_key_response(p5_resp_ct, p5_resp_tag, p5_resp_iv, sub_k2)
        assert p5_resp_dec.accepted is True
        recovered_subtopic_key = p5_resp_dec.subtopic_key
        assert recovered_subtopic_key == active_subtopic_key

        # -----------------------------------------------------------------------
        # Phase IV: Data Plane Payload Transfer (Unicast/Multicast Relay)
        # -----------------------------------------------------------------------
        # Publisher publishes message. Construct 9-byte header.
        msg_counter = 1000
        publisher_id = 101
        epoch_id = 1
        salt_epoch = b"\xab\xcd\xef\x01\x23\x45"  # 6-byte epoch salt
        hdr = HeaderCodec.encode(
            max_level=security_level,
            min_level=2,
            int_conf_flag=True,
            hash_name="SHA3-384",
            cipher_name="AES-192-GCM",
            publisher_id=publisher_id,
            counter=msg_counter,
            epoch_id=epoch_id,
        )

        aead_data = AEADWrapper(security_level)
        data_nonce = derive_data_iv(salt_epoch, publisher_id, msg_counter)
        ct_data, tag_data = aead_data.encrypt(recovered_subtopic_key[:aead_data.key_size], data_nonce, payload, hdr)

        # Complete frame = header + ciphertext + tag
        data_frame = hdr + ct_data + tag_data

        # --- Broker acts as dumb relay (relays unmodified frame to subscriber) ---
        received_frame = data_frame

        # Subscriber processes frame
        recv_hdr_raw = received_frame[:9]
        recv_ct_tag = received_frame[9:]
        recv_hdr = HeaderCodec.decode(recv_hdr_raw)

        assert recv_hdr.publisher_id == 101
        assert recv_hdr.counter == msg_counter
        assert recv_hdr.epoch_id == 1

        # ReplayGuard checks for freshness
        replay_guard = ReplayGuard()
        is_fresh = replay_guard.check_and_accept(
            publisher_id=recv_hdr.publisher_id,
            epoch_id=recv_hdr.epoch_id,
            counter=recv_hdr.counter,
        )
        assert is_fresh is True

        # Subscriber derives IV from header fields (same path as publisher)
        recv_nonce = derive_data_iv(salt_epoch, recv_hdr.publisher_id, recv_hdr.counter)

        # Decrypt tags size: 16 bytes for GCM
        ct_recv = recv_ct_tag[:-16]
        tag_recv = recv_ct_tag[-16:]

        recovered_payload = aead_data.decrypt(recovered_subtopic_key[:aead_data.key_size], recv_nonce, ct_recv, tag_recv, recv_hdr_raw)
        assert recovered_payload == payload

        # -----------------------------------------------------------------------
        # ReplayGuard Test
        # -----------------------------------------------------------------------
        # Replaying the exact same message counter must trigger a replay guard rejection
        is_fresh_replay = replay_guard.check_and_accept(
            publisher_id=recv_hdr.publisher_id,
            epoch_id=recv_hdr.epoch_id,
            counter=recv_hdr.counter,
        )
        assert is_fresh_replay is False

        # Older counter message within window is accepted if not seen yet (out-of-order tolerance)
        is_fresh_old = replay_guard.check_and_accept(
            publisher_id=recv_hdr.publisher_id,
            epoch_id=recv_hdr.epoch_id,
            counter=msg_counter - 5,
        )
        assert is_fresh_old is True

        # Replaying that older counter message should be rejected
        is_fresh_old_replay = replay_guard.check_and_accept(
            publisher_id=recv_hdr.publisher_id,
            epoch_id=recv_hdr.epoch_id,
            counter=msg_counter - 5,
        )
        assert is_fresh_old_replay is False

        # Older counter message behind the window size (64) is rejected as too old
        is_fresh_very_old = replay_guard.check_and_accept(
            publisher_id=recv_hdr.publisher_id,
            epoch_id=recv_hdr.epoch_id,
            counter=msg_counter - 100,
        )
        assert is_fresh_very_old is False
