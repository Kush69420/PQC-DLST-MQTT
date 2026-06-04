"""
Root Certificate Authority for PQC-DLST-MQTT.

Uses ML-DSA-87 (NIST Level 5) for maximum quantum resistance on CA signatures.
Issues certificates binding entity_id → vk_sign.
"""

import time
from ..pqcrypto.sig import SigWrapper
from .cert import Certificate


class CertificateAuthority:
    """Root CA using ML-DSA-87."""

    def __init__(self, ca_id: bytes = b"PQC-DLST-ROOT-CA"):
        """Initialize CA with fresh ML-DSA-87 keypair."""
        self.ca_id = ca_id
        self.sig = SigWrapper("ca")  # ML-DSA-87
        self.vk_ca, self.sk_ca = self.sig.keygen()
        self._issued: dict[bytes, Certificate] = {}

    def issue_cert(self, entity_id: bytes, vk_sign: bytes,
                   validity_days: int = 365) -> Certificate:
        """
        Issue a certificate for an entity.

        Args:
            entity_id: Unique entity identifier.
            vk_sign: Entity's ML-DSA verification key.
            validity_days: Certificate validity period.

        Returns:
            Signed Certificate.
        """
        now = int(time.time())
        cert = Certificate(
            entity_id=entity_id,
            vk_sign=vk_sign,
            issuer_id=self.ca_id,
            not_before=now,
            not_after=now + (validity_days * 86400),
        )
        # Sign with CA's ML-DSA-87 key
        cert.signature = self.sig.sign(self.sk_ca, cert.signable_content())
        self._issued[entity_id] = cert
        return cert

    def verify_cert(self, cert: Certificate) -> bool:
        """
        Verify a certificate's signature and validity.

        Args:
            cert: Certificate to verify.

        Returns:
            True if signature valid AND within validity period.
        """
        if not cert.is_valid_time():
            return False
        return self.sig.verify(self.vk_ca, cert.signable_content(), cert.signature)

    def get_ca_cert(self) -> Certificate:
        """Get the CA's self-signed certificate."""
        return self.issue_cert(self.ca_id, self.vk_ca)

    @property
    def verification_key(self) -> bytes:
        return self.vk_ca
