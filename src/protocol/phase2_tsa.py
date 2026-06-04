"""
Phase II — Topic Security Association.

Publisher → TTA over the Phase I symmetric channel.
Publisher declares what topic it wants to publish on, at what priority,
and what security level range it supports.

Protocol flow:
  1. Publisher builds TSA request: {topic, priority, level_min, level_max}
  2. Publisher encrypts with AES-GCM(K_cli→TTA, payload, IV_ctrl)
  3. TTA decrypts, validates priority ↔ level range mapping
  4. TTA sends ACK/NACK encrypted with AES-GCM(K_TTA→cli, response, IV_ctrl)

No algorithmic change from original DLST-MQTT — just the transport
encryption now uses keys derived from ML-KEM instead of ECDHE.
"""

import struct
from dataclasses import dataclass

from .security_levels import Priority, PRIORITY_LEVEL_RANGES
from ..pqcrypto.aead import AEADWrapper, GCM_NONCE_SIZE, GCM_TAG_SIZE
from ..pqcrypto.kdf import derive_control_iv


@dataclass
class TSARequest:
    """Phase II Topic Security Association request."""
    topic: str                  # MQTT topic string
    priority: Priority          # Topic priority
    level_min: int              # Minimum security level client supports
    level_max: int              # Maximum security level client supports

    def serialize(self) -> bytes:
        """Serialize for encryption."""
        topic_bytes = self.topic.encode("utf-8")
        return struct.pack("!HBBb",
                           len(topic_bytes),
                           self.priority.value,
                           self.level_min,
                           self.level_max) + topic_bytes

    @classmethod
    def deserialize(cls, data: bytes) -> "TSARequest":
        topic_len, priority_val, level_min, level_max = struct.unpack("!HBBb", data[:5])
        topic = data[5:5 + topic_len].decode("utf-8")
        return cls(topic=topic, priority=Priority(priority_val),
                   level_min=level_min, level_max=level_max)

    def byte_size(self) -> int:
        return len(self.serialize())


@dataclass
class TSAResponse:
    """Phase II TTA response."""
    accepted: bool
    negotiated_level_min: int   # Agreed minimum level
    negotiated_level_max: int   # Agreed maximum level
    reason: str                 # Rejection reason (empty if accepted)

    def serialize(self) -> bytes:
        reason_bytes = self.reason.encode("utf-8")
        return struct.pack("!?BBH",
                           self.accepted,
                           self.negotiated_level_min,
                           self.negotiated_level_max,
                           len(reason_bytes)) + reason_bytes

    @classmethod
    def deserialize(cls, data: bytes) -> "TSAResponse":
        accepted, neg_min, neg_max, reason_len = struct.unpack("!?BBH", data[:5])
        reason = data[5:5 + reason_len].decode("utf-8")
        return cls(accepted=accepted, negotiated_level_min=neg_min,
                   negotiated_level_max=neg_max, reason=reason)

    def byte_size(self) -> int:
        return len(self.serialize())


def validate_tsa_request(req: TSARequest) -> TSAResponse:
    """
    Validate a TSA request against priority ↔ level range policy.

    The TTA checks that the requested level range intersects with
    the allowed range for the topic's priority.
    """
    allowed_min, allowed_max = PRIORITY_LEVEL_RANGES[req.priority]

    # Compute intersection
    neg_min = max(req.level_min, allowed_min)
    neg_max = min(req.level_max, allowed_max)

    if neg_min > neg_max:
        return TSAResponse(
            accepted=False,
            negotiated_level_min=0,
            negotiated_level_max=0,
            reason=f"Level range [{req.level_min},{req.level_max}] does not "
                   f"intersect priority {req.priority.name} range [{allowed_min},{allowed_max}]"
        )

    return TSAResponse(
        accepted=True,
        negotiated_level_min=neg_min,
        negotiated_level_max=neg_max,
        reason=""
    )


def encrypt_tsa_message(payload: bytes, key: bytes, direction: int,
                        sn_state) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt a Phase II message over the Phase I channel.

    Args:
        payload: Serialized TSARequest or TSAResponse.
        key: Channel key (K_cli→TTA or K_TTA→cli).
        direction: 0 for client→TTA, 1 for TTA→client.
        sn_state: SequenceNumberState for IV construction.

    Returns:
        (ciphertext, tag, iv): Encrypted payload with authentication.
    """
    sn = sn_state.next()
    iv = derive_control_iv(direction, sn)
    # Use AES-256-GCM for control plane (keys are 32 bytes from KDF)
    aead = AEADWrapper(4)  # Level 4 = AES-256-GCM
    ct, tag = aead.encrypt(key[:32], iv, payload)
    return ct, tag, iv


def decrypt_tsa_message(ciphertext: bytes, tag: bytes, iv: bytes,
                        key: bytes) -> bytes:
    """Decrypt a Phase II message."""
    aead = AEADWrapper(4)
    return aead.decrypt(key[:32], iv, ciphertext, tag)
