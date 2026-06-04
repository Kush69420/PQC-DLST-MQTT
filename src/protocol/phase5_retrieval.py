"""
Phase V — SA Retrieval and Key Delivery.

THE CORE NOVELTY: subscriber gets the sub-topic key via a SYMMETRIC
unwrap over the pre-established Phase I channel. NO per-subscriber KEM.

This is Eq. (7) from the paper. The marginal cost of adding a subscriber
is one AES-GCM decrypt — not a lattice KEM. Combined with the publisher's
shared topic key, this means the broker never re-encrypts: it relays the
same ciphertext to all subscribers. In PQC-TLS, the broker must
decrypt-then-re-encrypt into each subscriber's independent TLS session.
This broker fan-out asymmetry is why PQC-DLST-MQTT's R3 scalability
curves diverge.

Protocol flow:
  1. Subscriber authenticates with TTA via Phase I
     → gets (K_SBR→TTA, K_TTA→SBR) symmetric channel keys
  2. Subscriber sends key request over channel:
     AES-GCM(K_SBR→TTA, {topic, sub_topic_id}, IV_ctrl)
  3. TTA checks CRL, checks access rights
  4. TTA responds with sub-topic context:
     AES-GCM(K_TTA→SBR, {K_st_l ∥ Salt_epoch ∥ EpochID ∥ level_config}, IV_ctrl)
  5. Subscriber decrypts → obtains sub-topic key → can decrypt Phase IV frames

The subscriber also re-runs this phase when it detects an EpochID mismatch
in a received data frame header (Phase VI trigger).
"""

import struct
from dataclasses import dataclass

from ..pqcrypto.aead import AEADWrapper
from ..pqcrypto.kdf import derive_control_iv


@dataclass
class KeyRequest:
    """Phase V key request (Subscriber → TTA)."""
    topic: str                  # Topic the subscriber wants to access
    subscriber_id: bytes        # Subscriber identifier

    def serialize(self) -> bytes:
        topic_bytes = self.topic.encode("utf-8")
        id_len = len(self.subscriber_id)
        return struct.pack("!HH", len(topic_bytes), id_len) + topic_bytes + self.subscriber_id

    @classmethod
    def deserialize(cls, data: bytes) -> "KeyRequest":
        topic_len, id_len = struct.unpack("!HH", data[:4])
        topic = data[4:4 + topic_len].decode("utf-8")
        sub_id = data[4 + topic_len:4 + topic_len + id_len]
        return cls(topic=topic, subscriber_id=sub_id)

    def byte_size(self) -> int:
        return len(self.serialize())


@dataclass
class KeyResponse:
    """
    Phase V key delivery (TTA → Subscriber).

    This is the symmetric unwrap payload — Eq. (7).
    Contains everything the subscriber needs to decrypt Phase IV frames.
    """
    accepted: bool
    topic: str
    epoch_id: int               # 8-bit current epoch
    current_level: int          # Active security level
    level_min: int
    level_max: int
    subtopic_key: bytes         # K_st_l for current level
    salt_epoch: bytes           # 6-byte epoch salt
    reason: str                 # Rejection reason (empty if accepted)

    def serialize(self) -> bytes:
        topic_bytes = self.topic.encode("utf-8")
        reason_bytes = self.reason.encode("utf-8")
        key_len = len(self.subtopic_key)
        header = struct.pack("!?HBBBBHH",
                             self.accepted,
                             len(topic_bytes),
                             self.epoch_id,
                             self.current_level,
                             self.level_min,
                             self.level_max,
                             key_len,
                             len(reason_bytes))
        return header + topic_bytes + self.subtopic_key + self.salt_epoch + reason_bytes

    @classmethod
    def deserialize(cls, data: bytes) -> "KeyResponse":
        accepted, topic_len, epoch, cur_level, lmin, lmax, key_len, reason_len = \
            struct.unpack("!?HBBBBHH", data[:10])
        offset = 10
        topic = data[offset:offset + topic_len].decode("utf-8"); offset += topic_len
        key = data[offset:offset + key_len]; offset += key_len
        salt = data[offset:offset + 6]; offset += 6
        reason = data[offset:offset + reason_len].decode("utf-8")
        return cls(
            accepted=accepted, topic=topic, epoch_id=epoch,
            current_level=cur_level, level_min=lmin, level_max=lmax,
            subtopic_key=key, salt_epoch=salt, reason=reason,
        )

    def byte_size(self) -> int:
        return len(self.serialize())


def encrypt_key_request(req: KeyRequest, key_sbr_to_tta: bytes,
                        direction: int, sn_state) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt a Phase V key request over the Phase I channel.

    Args:
        req: KeyRequest to encrypt.
        key_sbr_to_tta: Subscriber→TTA channel key from Phase I.
        direction: 0 for subscriber→TTA.
        sn_state: SequenceNumberState.

    Returns:
        (ciphertext, tag, iv)
    """
    sn = sn_state.next()
    iv = derive_control_iv(direction, sn)
    aead = AEADWrapper(4)  # AES-256-GCM for control plane
    ct, tag = aead.encrypt(key_sbr_to_tta[:32], iv, req.serialize())
    return ct, tag, iv


def decrypt_key_request(ciphertext: bytes, tag: bytes, iv: bytes,
                        key_sbr_to_tta: bytes) -> KeyRequest:
    """Decrypt a Phase V key request."""
    aead = AEADWrapper(4)
    plaintext = aead.decrypt(key_sbr_to_tta[:32], iv, ciphertext, tag)
    return KeyRequest.deserialize(plaintext)


def encrypt_key_response(resp: KeyResponse, key_tta_to_sbr: bytes,
                         direction: int, sn_state) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt a Phase V key delivery response.

    This is the symmetric unwrap — Eq. (7):
    AES-GCM(K_TTA→SBR, {K_st_l ∥ Salt_epoch ∥ EpochID ∥ config}, IV_ctrl)

    The cost is ONE symmetric AEAD operation, NOT a lattice KEM.

    Args:
        resp: KeyResponse containing sub-topic keying material.
        key_tta_to_sbr: TTA→Subscriber channel key from Phase I.
        direction: 1 for TTA→subscriber.
        sn_state: SequenceNumberState.

    Returns:
        (ciphertext, tag, iv)
    """
    sn = sn_state.next()
    iv = derive_control_iv(direction, sn)
    aead = AEADWrapper(4)  # AES-256-GCM for control plane
    ct, tag = aead.encrypt(key_tta_to_sbr[:32], iv, resp.serialize())
    return ct, tag, iv


def decrypt_key_response(ciphertext: bytes, tag: bytes, iv: bytes,
                         key_tta_to_sbr: bytes) -> KeyResponse:
    """
    Decrypt a Phase V key delivery response (subscriber side).

    After this, the subscriber has K_st_l and Salt_epoch and can
    decrypt Phase IV data frames.
    """
    aead = AEADWrapper(4)
    plaintext = aead.decrypt(key_tta_to_sbr[:32], iv, ciphertext, tag)
    return KeyResponse.deserialize(plaintext)


def phase5_byte_overhead() -> dict:
    """
    Calculate Phase V byte overhead for R2.

    This is the cost of adding one subscriber — the key number for R3.
    """
    # Sample sizes (Level 3 as representative)
    sample_req = KeyRequest(topic="sensors/temp", subscriber_id=b"sub001")
    sample_resp = KeyResponse(
        accepted=True, topic="sensors/temp", epoch_id=1,
        current_level=3, level_min=2, level_max=4,
        subtopic_key=b"\x00" * 32, salt_epoch=b"\x00" * 6, reason=""
    )

    req_plaintext = sample_req.byte_size()
    resp_plaintext = sample_resp.byte_size()

    return {
        "request_plaintext_bytes": req_plaintext,
        "request_encrypted_bytes": req_plaintext + 16,  # + GCM tag
        "response_plaintext_bytes": resp_plaintext,
        "response_encrypted_bytes": resp_plaintext + 16,  # + GCM tag
        "total_phase5_bytes": (req_plaintext + 16) + (resp_plaintext + 16),
        "asymmetric_operations": 0,  # Zero! This is the point.
        "symmetric_operations": 2,   # One encrypt + one decrypt
    }
