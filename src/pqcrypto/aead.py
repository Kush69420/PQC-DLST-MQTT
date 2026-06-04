"""
AES-GCM Authenticated Encryption with Associated Data wrapper.

AES is quantum-resistant (Grover halves effective key length):
  - AES-128-GCM → 64-bit quantum security (Low priority, short-lived data)
  - AES-192-GCM → 96-bit quantum security (Medium priority)
  - AES-256-GCM → 128-bit quantum security (High/Critical priority)

Uses PyCryptodome for all symmetric operations.
"""

from Crypto.Cipher import AES


# Map protocol security levels to AES key sizes (bytes)
AEAD_KEY_SIZES = {
    0: None,   # Level 0: no encryption
    1: None,   # Level 1: integrity only (KMAC), no AEAD
    2: 16,     # Level 2: AES-128-GCM
    3: 24,     # Level 3: AES-192-GCM
    4: 32,     # Level 4: AES-256-GCM
    5: 32,     # Level 5: AES-256-GCM
}

# GCM tag size (always 16 bytes / 128 bits)
GCM_TAG_SIZE = 16

# GCM nonce size (12 bytes / 96 bits — standard for AES-GCM)
GCM_NONCE_SIZE = 12


class AEADWrapper:
    """AES-GCM wrapper for data-plane encryption in PQC-DLST-MQTT."""

    def __init__(self, security_level: int):
        """
        Initialize AEAD for a given protocol security level.

        Args:
            security_level: Protocol security level (2-5).
                            Levels 0-1 have no AEAD.

        Raises:
            ValueError: If level has no AEAD.
        """
        if security_level < 2:
            raise ValueError(f"Security level {security_level} has no AEAD (use KMAC for level 1)")
        if security_level not in AEAD_KEY_SIZES:
            raise ValueError(f"Invalid security level: {security_level}")

        self.level = security_level
        self.key_size = AEAD_KEY_SIZES[security_level]

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes,
                aad: bytes = b"") -> tuple[bytes, bytes]:
        """
        Encrypt with AES-GCM.

        Args:
            key: Symmetric key (16/24/32 bytes depending on level).
            nonce: 12-byte nonce (IV). MUST be unique per (key, nonce) pair.
            plaintext: Data to encrypt.
            aad: Additional Authenticated Data (authenticated but not encrypted).

        Returns:
            (ciphertext, tag): Encrypted data and 16-byte authentication tag.

        Raises:
            ValueError: If key size doesn't match level or nonce is wrong size.
        """
        if len(key) != self.key_size:
            raise ValueError(
                f"Key must be {self.key_size} bytes for level {self.level}, got {len(key)}"
            )
        if len(nonce) != GCM_NONCE_SIZE:
            raise ValueError(f"Nonce must be {GCM_NONCE_SIZE} bytes, got {len(nonce)}")

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext, tag

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes,
                tag: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt and verify with AES-GCM.

        Args:
            key: Symmetric key.
            nonce: 12-byte nonce used during encryption.
            ciphertext: Encrypted data.
            tag: 16-byte authentication tag from encryption.
            aad: Additional Authenticated Data (must match encryption).

        Returns:
            plaintext: Decrypted data.

        Raises:
            ValueError: On authentication failure (tampered data).
        """
        if len(key) != self.key_size:
            raise ValueError(
                f"Key must be {self.key_size} bytes for level {self.level}, got {len(key)}"
            )
        if len(nonce) != GCM_NONCE_SIZE:
            raise ValueError(f"Nonce must be {GCM_NONCE_SIZE} bytes, got {len(nonce)}")

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            raise ValueError(f"AEAD authentication failed: {e}") from e
        return plaintext

    def get_key_size(self) -> int:
        """Return required key size in bytes."""
        return self.key_size

    @staticmethod
    def get_overhead() -> int:
        """Return per-message overhead in bytes (GCM tag only; nonce is in header)."""
        return GCM_TAG_SIZE
