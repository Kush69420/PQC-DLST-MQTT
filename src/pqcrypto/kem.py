"""
ML-KEM (CRYSTALS-Kyber) Key Encapsulation Mechanism wrapper.

Replaces ECDHE in the original DLST-MQTT protocol.
Uses liboqs for the actual PQC operations.

Level mapping:
  - Security Levels 1-2 (Low priority)    → ML-KEM-512  (NIST Level 1)
  - Security Levels 3-4 (Medium/High)     → ML-KEM-768  (NIST Level 3)
  - Security Level 5   (Critical)         → ML-KEM-1024 (NIST Level 5)
"""

import oqs


# Map protocol security levels to ML-KEM parameter sets
KEM_PARAMS = {
    0: None,                  # Level 0: no security
    1: "ML-KEM-512",          # Level 1: Low
    2: "ML-KEM-512",          # Level 2: Low-Med
    3: "ML-KEM-768",          # Level 3: Medium
    4: "ML-KEM-768",          # Level 4: High
    5: "ML-KEM-1024",         # Level 5: Critical
}

# Public key / ciphertext sizes for byte-counting (R2)
KEM_SIZES = {
    "ML-KEM-512":  {"pk": 800,  "sk": 1632, "ct": 768,  "ss": 32},
    "ML-KEM-768":  {"pk": 1184, "sk": 2400, "ct": 1088, "ss": 32},
    "ML-KEM-1024": {"pk": 1568, "sk": 3168, "ct": 1568, "ss": 32},
}


class KEMWrapper:
    """Wrapper around liboqs ML-KEM for the PQC-DLST-MQTT protocol."""

    def __init__(self, security_level: int):
        """
        Initialize KEM for a given protocol security level (1-5).

        Args:
            security_level: Protocol security level (1-5).
                            Level 0 has no KEM.

        Raises:
            ValueError: If security_level is 0 (no KEM at that level).
        """
        if security_level == 0:
            raise ValueError("Security level 0 has no KEM")
        if security_level not in KEM_PARAMS:
            raise ValueError(f"Invalid security level: {security_level}")

        self.level = security_level
        self.alg_name = KEM_PARAMS[security_level]
        self.sizes = KEM_SIZES[self.alg_name]

    def keygen(self) -> tuple[bytes, bytes]:
        """
        Generate a KEM keypair.

        Returns:
            (encapsulation_key, decapsulation_key): The public (ek) and secret (dk) keys.
        """
        with oqs.KeyEncapsulation(self.alg_name) as kem:
            ek = kem.generate_keypair()   # public key (encapsulation key)
            dk = kem.export_secret_key()  # secret key (decapsulation key)
        return ek, dk

    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulate: generate a shared secret locked to the given public key.

        This is called by the TTA (or the party initiating key agreement).
        In MQTT pub/sub, the TTA encapsulates to the subscriber's ek.

        Args:
            ek: Encapsulation (public) key of the recipient.

        Returns:
            (shared_secret, ciphertext): K and c such that Decaps(dk, c) = K.
        """
        with oqs.KeyEncapsulation(self.alg_name) as kem:
            ciphertext, shared_secret = kem.encap_secret(ek)
        return shared_secret, ciphertext

    def decaps(self, dk: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate: recover the shared secret from a ciphertext.

        Args:
            dk: Decapsulation (secret) key.
            ciphertext: Ciphertext from Encaps.

        Returns:
            shared_secret: The same K that Encaps produced.
        """
        with oqs.KeyEncapsulation(self.alg_name, dk) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret

    def get_sizes(self) -> dict:
        """Return public key, ciphertext, and shared secret sizes in bytes."""
        return self.sizes.copy()

    @staticmethod
    def get_algorithm_for_level(level: int) -> str | None:
        """Return the ML-KEM algorithm name for a given security level."""
        return KEM_PARAMS.get(level)
