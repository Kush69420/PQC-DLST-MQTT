"""
Phase IV — Encrypt-then-Send (Data Plane).

Publisher encrypts payload and publishes to MQTT sub-topic.

Security levels:
  Level 0: Plaintext (no security)
  Level 1: Integrity-only — KMAC-256 tag (32 bytes, 256-bit output)
  Levels 2-5: AES-GCM — ciphertext + 16-byte tag

Data frame format:
  [9-byte header][payload/ciphertext][tag]

Where:
  - Header: as defined in common.py (matches paper's Table exactly)
  - Tag: 32 bytes for KMAC-256 (Level 1), 16 bytes for AES-GCM (Levels 2-5)

IV construction (Levels 2-5):
  IV = Salt_epoch(48 bits) ∥ ID_P(16 bits) ∥ Counter32(32 bits) = 96 bits = 12 bytes

KMAC-256 construction (Level 1):
  tag = KMAC-256(K_st_l, Plaintext ∥ ID_P ∥ Counter32 ∥ EpochID, mac_len=32)
  The mac_len=32 (256-bit output) is an explicit choice documented for R2 reconciliation.
"""

import struct
from dataclasses import dataclass

from .common import HeaderCodec, DataHeader
from ..pqcrypto.aead import AEADWrapper, GCM_TAG_SIZE
from ..pqcrypto.hash import HashWrapper
from ..pqcrypto.kdf import derive_data_iv


# KMAC tag size: explicitly 32 bytes (256-bit output)
# This is a parameter choice, not inherent to KMAC-256.
# Stated explicitly so R2 byte counts reconcile with Table II.
KMAC_TAG_SIZE = 32


@dataclass
class DataFrameContext:
    """Context needed by a publisher to create Phase IV frames."""
    publisher_id: int          # 16-bit ID_P
    epoch_id: int              # 8-bit EpochID
    current_level: int         # Active security level
    level_min: int             # Negotiated minimum
    level_max: int             # Negotiated maximum (= header max_level)
    subtopic_key: bytes        # K_st_l for current level
    salt_epoch: bytes          # 6-byte epoch salt
    counter: int = 0           # 32-bit message counter

    def next_counter(self) -> int:
        """Increment and return counter. Raises on overflow."""
        c = self.counter
        self.counter += 1
        if self.counter > 0xFFFFFFFF:
            raise OverflowError(
                "Counter32 overflow — must trigger re-authentication "
                "(new epoch) before reaching 2^32 - 1"
            )
        return c


def create_data_frame(plaintext: bytes, ctx: DataFrameContext) -> bytes:
    """
    Create a Phase IV data frame (encrypt-then-send).

    Args:
        plaintext: Raw payload to protect.
        ctx: DataFrameContext with keying material and counter state.

    Returns:
        Complete data frame: [9-byte header][payload/ciphertext][tag]
        For Level 0: [9-byte header][plaintext] (no tag)
    """
    counter = ctx.next_counter()
    level = ctx.current_level

    # Build 9-byte header
    header = HeaderCodec.encode_for_level(
        level=level,
        publisher_id=ctx.publisher_id,
        counter=counter,
        epoch_id=ctx.epoch_id,
        min_level=ctx.level_min,
    )

    if level == 0:
        # No security
        return header + plaintext

    elif level == 1:
        # Integrity-only: KMAC-256 tag over (Plaintext ∥ ID_P ∥ Counter32 ∥ EpochID)
        mac_input = (plaintext +
                     struct.pack("!IB", counter, ctx.epoch_id) +
                     struct.pack("!H", ctx.publisher_id))
        hasher = HashWrapper(1)
        tag = hasher.mac(
            key=ctx.subtopic_key,
            data=mac_input,
            custom=b"PQC-DLST-MQTT-L1",
            mac_len=KMAC_TAG_SIZE,  # Explicitly 32 bytes (256-bit)
        )
        return header + plaintext + tag

    else:
        # Levels 2-5: AES-GCM
        iv = derive_data_iv(ctx.salt_epoch, ctx.publisher_id, counter)
        aead = AEADWrapper(level)
        # Truncate key to match level's required key size
        key = ctx.subtopic_key[:aead.get_key_size()]
        # AAD = header (binds security metadata to ciphertext)
        ciphertext, tag = aead.encrypt(key, iv, plaintext, aad=header)
        return header + ciphertext + tag


def parse_data_frame(frame: bytes) -> tuple[DataHeader, bytes, bytes]:
    """
    Parse a received data frame into header, payload, and tag.

    Args:
        frame: Complete received frame bytes.

    Returns:
        (header, payload_or_ciphertext, tag)
        For Level 0: tag is empty bytes.
        For Level 1: tag is 32 bytes (KMAC).
        For Levels 2-5: tag is 16 bytes (GCM).
    """
    header = HeaderCodec.decode(frame[:9])

    if header.max_level == 0:
        return header, frame[9:], b""
    elif header.max_level == 1:
        # Integrity-only: plaintext + 32-byte KMAC tag
        payload = frame[9:-KMAC_TAG_SIZE]
        tag = frame[-KMAC_TAG_SIZE:]
        return header, payload, tag
    else:
        # Levels 2-5: ciphertext + 16-byte GCM tag
        ciphertext = frame[9:-GCM_TAG_SIZE]
        tag = frame[-GCM_TAG_SIZE:]
        return header, ciphertext, tag


def decrypt_data_frame(frame: bytes, subtopic_key: bytes,
                       salt_epoch: bytes) -> tuple[DataHeader, bytes]:
    """
    Decrypt and verify a Phase IV data frame.

    Args:
        frame: Complete received frame.
        subtopic_key: K_st_l for the frame's security level.
        salt_epoch: 6-byte epoch salt.

    Returns:
        (header, plaintext)

    Raises:
        ValueError: If integrity check fails (KMAC mismatch or GCM auth failure).
    """
    header, payload, tag = parse_data_frame(frame)

    if header.max_level == 0:
        return header, payload

    elif header.max_level == 1:
        # Verify KMAC-256 tag
        mac_input = (payload +
                     struct.pack("!IB", header.counter, header.epoch_id) +
                     struct.pack("!H", header.publisher_id))
        hasher = HashWrapper(1)
        if not hasher.verify_mac(
            key=subtopic_key,
            data=mac_input,
            tag=tag,
            custom=b"PQC-DLST-MQTT-L1",
            mac_len=KMAC_TAG_SIZE,
        ):
            raise ValueError("KMAC-256 integrity check failed — data tampered")
        return header, payload

    else:
        # AES-GCM decrypt
        iv = derive_data_iv(salt_epoch, header.publisher_id, header.counter)
        aead = AEADWrapper(header.max_level)
        key = subtopic_key[:aead.get_key_size()]
        header_bytes = frame[:9]  # AAD
        plaintext = aead.decrypt(key, iv, payload, tag, aad=header_bytes)
        return header, plaintext


def data_frame_overhead(level: int, payload_size: int = 0) -> dict:
    """
    Calculate exact per-message byte overhead for R2 benchmarking.

    Args:
        level: Security level (0-5).
        payload_size: Size of plaintext payload.

    Returns:
        Dict with header_bytes, tag_bytes, total_overhead, total_frame_size.
    """
    header_bytes = 9
    if level == 0:
        tag_bytes = 0
    elif level == 1:
        tag_bytes = KMAC_TAG_SIZE  # 32 bytes
    else:
        tag_bytes = GCM_TAG_SIZE   # 16 bytes

    return {
        "level": level,
        "header_bytes": header_bytes,
        "tag_bytes": tag_bytes,
        "total_overhead": header_bytes + tag_bytes,
        "total_frame_size": header_bytes + payload_size + tag_bytes,
        "payload_encrypted": level >= 2,
        "tag_algorithm": {0: "none", 1: "KMAC-256 (256-bit)", 2: "AES-128-GCM",
                          3: "AES-192-GCM", 4: "AES-256-GCM", 5: "AES-256-GCM"}.get(level),
    }
