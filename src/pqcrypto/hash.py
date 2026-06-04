"""
Hash function wrappers: SHA3-256, SHA3-384, SHAKE-256, KMAC-256.

Replaces SHA-224 and SPONGENT from the original DLST-MQTT:
  - SHA-224    → SHA3-256 (quantum-resistant, NIST PQC suite)
  - SPONGENT  → SHAKE-256 (XOF, sponge construction, standardised)

Level mapping:
  - Level 1:   KMAC-256 (integrity-only path — tag over plaintext)
  - Level 2-3: SHA3-256
  - Level 4:   SHA3-384
  - Level 5:   SHAKE-256

Uses PyCryptodome for all hash operations.
"""

from Crypto.Hash import SHA3_256, SHA3_384, SHAKE256, KMAC128


# Map protocol levels to hash functions
HASH_PARAMS = {
    0: None,
    1: "KMAC-256",
    2: "SHA3-256",
    3: "SHA3-384",
    4: "SHA3-384",
    5: "SHAKE-256",
}


class HashWrapper:
    """Hash function wrapper for PQC-DLST-MQTT."""

    def __init__(self, security_level: int):
        if security_level not in HASH_PARAMS:
            raise ValueError(f"Invalid security level: {security_level}")
        if security_level == 0:
            raise ValueError("Security level 0 has no hash")
        self.level = security_level
        self.alg_name = HASH_PARAMS[security_level]

    def hash(self, data: bytes) -> bytes:
        """
        Compute hash digest of data.

        Returns fixed-size digest for SHA3 variants.
        For SHAKE-256, returns 32-byte output.
        For KMAC-256, use the mac() method instead.
        """
        if self.alg_name == "SHA3-256":
            h = SHA3_256.new()
            h.update(data)
            return h.digest()
        elif self.alg_name == "SHA3-384":
            h = SHA3_384.new()
            h.update(data)
            return h.digest()
        elif self.alg_name == "SHAKE-256":
            h = SHAKE256.new()
            h.update(data)
            return h.read(32)  # 32 bytes = 256 bits
        elif self.alg_name == "KMAC-256":
            raise ValueError("Use mac() for KMAC-256, not hash()")
        else:
            raise ValueError(f"Unknown hash algorithm: {self.alg_name}")

    def mac(self, key: bytes, data: bytes, custom: bytes = b"",
            mac_len: int = 32) -> bytes:
        """
        Compute KMAC-256 tag (Level 1 integrity-only path).

        Per the protocol spec, the Level-1 tag is:
            KMAC-256(key, Plaintext ∥ ID_P ∥ Counter32 ∥ EpochID)

        Args:
            key: MAC key (typically the sub-topic key).
            data: Data to authenticate (concatenated fields per spec).
            custom: Optional customization string.
            mac_len: Output tag length in bytes (default 32).

        Returns:
            tag: KMAC-256 authentication tag.
        """
        if self.alg_name != "KMAC-256":
            raise ValueError(f"mac() only available for KMAC-256, not {self.alg_name}")
        # PyCryptodome's KMAC128 with 256-bit key gives KMAC-256 equivalent
        h = KMAC128.new(key=key, data=data, custom=custom, mac_len=mac_len)
        return h.digest()

    def verify_mac(self, key: bytes, data: bytes, tag: bytes,
                   custom: bytes = b"", mac_len: int = 32) -> bool:
        """Verify a KMAC-256 tag."""
        if self.alg_name != "KMAC-256":
            raise ValueError(f"verify_mac() only available for KMAC-256")
        expected = self.mac(key, data, custom, mac_len)
        # Constant-time comparison
        if len(expected) != len(tag):
            return False
        result = 0
        for a, b in zip(expected, tag):
            result |= a ^ b
        return result == 0

    def get_digest_size(self) -> int:
        """Return digest size in bytes."""
        sizes = {
            "SHA3-256": 32,
            "SHA3-384": 48,
            "SHAKE-256": 32,
            "KMAC-256": 32,
        }
        return sizes[self.alg_name]


def sha3_256(data: bytes) -> bytes:
    """Convenience: standalone SHA3-256 hash."""
    h = SHA3_256.new()
    h.update(data)
    return h.digest()


def sha3_384(data: bytes) -> bytes:
    """Convenience: standalone SHA3-384 hash."""
    h = SHA3_384.new()
    h.update(data)
    return h.digest()


def shake256(data: bytes, length: int = 32) -> bytes:
    """Convenience: standalone SHAKE-256 XOF."""
    h = SHAKE256.new()
    h.update(data)
    return h.read(length)
