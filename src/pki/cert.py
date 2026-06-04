"""
Lightweight PQC Certificate for PQC-DLST-MQTT.

Binds identity to vk_sign (verification key) ONLY.
KEM keys in Phase I are EPHEMERAL — they are NOT in the certificate.

Fields:
  - entity_id: Unique identifier (bytes)
  - vk_sign: ML-DSA verification (public) key
  - issuer_id: CA identifier
  - not_before: Validity start (Unix timestamp)
  - not_after: Validity end (Unix timestamp)
  - signature: CA's ML-DSA signature over the above fields
"""

import struct
import time
from dataclasses import dataclass


@dataclass
class Certificate:
    """Lightweight PQC certificate binding identity → vk_sign."""
    entity_id: bytes            # Entity identifier
    vk_sign: bytes              # ML-DSA verification key
    issuer_id: bytes            # CA identifier
    not_before: int             # Validity start (Unix timestamp)
    not_after: int              # Validity end (Unix timestamp)
    signature: bytes = b""      # CA's ML-DSA signature

    def signable_content(self) -> bytes:
        """Content that gets signed by the CA."""
        return struct.pack("!HH QQ",
                           len(self.entity_id), len(self.vk_sign),
                           self.not_before, self.not_after) + \
               self.entity_id + self.vk_sign + self.issuer_id

    def serialize(self) -> bytes:
        """Compact binary serialization for transmission/byte counting."""
        signable = self.signable_content()
        return struct.pack("!IH",
                           len(signable),
                           len(self.signature)) + signable + self.signature

    @classmethod
    def deserialize(cls, data: bytes) -> "Certificate":
        signable_len, sig_len = struct.unpack("!IH", data[:6])
        signable = data[6:6 + signable_len]
        sig = data[6 + signable_len:6 + signable_len + sig_len]

        # Parse signable content
        id_len, vk_len, not_before, not_after = struct.unpack("!HH QQ", signable[:20])
        offset = 20
        entity_id = signable[offset:offset + id_len]; offset += id_len
        vk_sign = signable[offset:offset + vk_len]; offset += vk_len
        issuer_id = signable[offset:]

        return cls(
            entity_id=entity_id, vk_sign=vk_sign, issuer_id=issuer_id,
            not_before=not_before, not_after=not_after, signature=sig,
        )

    def is_valid_time(self, now: int = None) -> bool:
        """Check if certificate is within validity period."""
        if now is None:
            now = int(time.time())
        return self.not_before <= now <= self.not_after

    def byte_size(self) -> int:
        """Total serialized size for R2 byte counting."""
        return len(self.serialize())
