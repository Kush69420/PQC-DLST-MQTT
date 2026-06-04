"""
ML-DSA (CRYSTALS-Dilithium) Digital Signature wrapper.

Replaces ECDSA in the original DLST-MQTT protocol.
Uses liboqs for the actual PQC operations.

Level mapping:
  - Security Levels 1-3              → ML-DSA-44 (NIST Level 2)
  - Security Levels 4-5              → ML-DSA-65 (NIST Level 3)
  - CA root certificates only        → ML-DSA-87 (NIST Level 5)
"""

import oqs


# Map protocol security levels to ML-DSA parameter sets
SIG_PARAMS = {
    0: None,                  # Level 0: no signatures
    1: "ML-DSA-44",           # Level 1
    2: "ML-DSA-44",           # Level 2
    3: "ML-DSA-44",           # Level 3
    4: "ML-DSA-65",           # Level 4
    5: "ML-DSA-87",           # Level 5 — maximum, same as CA
    "ca": "ML-DSA-87",        # CA root — maximum strength
    "falcon512": "Falcon-512", # Falcon-512 (Level 1/2) support
}

# Sizes for byte-counting (R2)
SIG_SIZES = {
    "ML-DSA-44": {"pk": 1312, "sk": 2560, "sig": 2420},
    "ML-DSA-65": {"pk": 1952, "sk": 4032, "sig": 3293},
    "ML-DSA-87": {"pk": 2592, "sk": 4896, "sig": 4595},
    "Falcon-512": {"pk": 897, "sk": 1281, "sig": 666},
}


class SigWrapper:
    """Wrapper around liboqs ML-DSA and Falcon digital signatures."""

    def __init__(self, security_level: int | str):
        """
        Initialize signature scheme for a given protocol security level.

        Args:
            security_level: Protocol security level (1-5) or "ca" for root CA.
                            Level 0 has no signatures.

        Raises:
            ValueError: If security_level is 0 or invalid.
        """
        if security_level == 0:
            raise ValueError("Security level 0 has no signatures")
        if security_level not in SIG_PARAMS:
            raise ValueError(f"Invalid security level: {security_level}")

        self.level = security_level
        self.alg_name = SIG_PARAMS[security_level]
        self.sizes = SIG_SIZES[self.alg_name]

    def keygen(self) -> tuple[bytes, bytes]:
        """
        Generate a signing keypair.

        Returns:
            (verification_key, signing_key): The public (vk) and secret (sk) keys.
        """
        with oqs.Signature(self.alg_name) as sig:
            vk = sig.generate_keypair()     # public key (verification key)
            sk = sig.export_secret_key()    # secret key (signing key)
        return vk, sk

    def sign(self, sk: bytes, message: bytes) -> bytes:
        """
        Sign a message.

        Args:
            sk: Signing (secret) key.
            message: Message bytes to sign.

        Returns:
            signature: The digital signature.
        """
        with oqs.Signature(self.alg_name, sk) as sig:
            signature = sig.sign(message)
        return signature

    def verify(self, vk: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature.

        Args:
            vk: Verification (public) key.
            message: Original message bytes.
            signature: Signature to verify.

        Returns:
            True if valid, False otherwise.
        """
        with oqs.Signature(self.alg_name) as sig:
            try:
                is_valid = sig.verify(message, signature, vk)
                return is_valid
            except oqs.MechanismNotSupportedError:
                return False
            except Exception:
                return False

    def get_sizes(self) -> dict:
        """Return public key, secret key, and signature sizes in bytes."""
        return self.sizes.copy()

    @staticmethod
    def get_algorithm_for_level(level: int | str) -> str | None:
        """Return the ML-DSA algorithm name for a given security level."""
        return SIG_PARAMS.get(level)
