"""
Unit tests for pqcrypto wrapper components (SigWrapper, KEMWrapper, HashWrapper, AEADWrapper).
Specifically tests Falcon-512 and ML-DSA signature algorithms, ML-KEM, hash, and AEAD.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
import oqs
from src.pqcrypto.sig import SigWrapper
from src.pqcrypto.kem import KEMWrapper
from src.pqcrypto.aead import AEADWrapper
from src.pqcrypto.hash import HashWrapper


class TestSigWrapper:
    """Verify digital signature scheme wrappers."""

    @pytest.mark.parametrize(
        "level_or_name",
        [1, 2, 3, 4, 5, "ca", "falcon512"],
    )
    def test_signature_schemes_functional(self, level_or_name):
        """Test keygen, sign, and verify across all levels and named algorithms."""
        sig = SigWrapper(level_or_name)
        
        # Test keygen
        vk, sk = sig.keygen()
        assert len(vk) == sig.sizes["pk"]
        assert len(sk) == sig.sizes["sk"]

        # Test sign & verify
        msg = b"This is a message to sign and verify."
        signature = sig.sign(sk, msg)
        assert len(signature) <= sig.sizes["sig"]

        # Test valid verification
        assert sig.verify(vk, msg, signature) is True

        # Test verification failure on modified message
        assert sig.verify(vk, msg + b"tamper", signature) is False

        # Test verification failure on modified signature
        bad_sig = bytearray(signature)
        bad_sig[0] ^= 0xFF
        assert sig.verify(vk, msg, bytes(bad_sig)) is False

    def test_unsupported_mechanism_raises_error(self):
        """SigWrapper with invalid algorithm must raise MechanismNotSupportedError or ValueError."""
        with pytest.raises(ValueError):
            SigWrapper(0)  # Level 0 is invalid

        with pytest.raises(ValueError):
            SigWrapper(6)  # Level 6 is invalid

        with pytest.raises(ValueError):
            SigWrapper("invalid_scheme")


class TestKEMWrapper:
    """Verify KEM wrappers."""

    @pytest.mark.parametrize("level", [1, 2, 3, 4, 5])
    def test_kem_schemes_functional(self, level):
        """Test keygen, encaps, and decaps for ML-KEM on all supported levels."""
        kem = KEMWrapper(level)

        # Test keygen
        ek, dk = kem.keygen()
        assert len(ek) == kem.sizes["pk"]
        assert len(dk) == kem.sizes["sk"]

        # Test encaps & decaps
        ss_enc, ct = kem.encaps(ek)
        assert len(ss_enc) == kem.sizes["ss"]
        assert len(ct) == kem.sizes["ct"]

        ss_dec = kem.decaps(dk, ct)
        assert ss_dec == ss_enc


class TestAEADWrapper:
    """Verify AES-GCM wrappers."""

    @pytest.mark.parametrize("level", [2, 3, 4, 5])
    def test_aead_encrypt_decrypt(self, level):
        aead = AEADWrapper(level)
        key_size = aead.get_key_size()
        key = b"k" * key_size
        nonce = b"n" * 12
        plaintext = b"Highly confidential payload"
        aad = b"associated data"

        # Encrypt
        ct, tag = aead.encrypt(key, nonce, plaintext, aad)
        assert len(tag) == 16

        # Decrypt
        decrypted = aead.decrypt(key, nonce, ct, tag, aad)
        assert decrypted == plaintext

        # Decrypt with bad tag should raise ValueError
        with pytest.raises(ValueError):
            aead.decrypt(key, nonce, ct, b"w" * 16, aad)


class TestHashWrapper:
    """Verify Hash function wrappers."""

    def test_kmac_integrity_only(self):
        hasher = HashWrapper(1)
        assert hasher.alg_name == "KMAC-256"

        key = b"k" * 32
        data = b"authenticated payload"
        tag = hasher.mac(key, data, custom=b"test")
        assert len(tag) == 32

        assert hasher.verify_mac(key, data, tag, custom=b"test") is True
        assert hasher.verify_mac(key, data + b"x", tag, custom=b"test") is False
