"""
Certificate Revocation List for PQC-DLST-MQTT.

TTA checks CRL before Phase V key delivery.
Simple in-memory CRL — sufficient for simulation.
"""

import threading
from dataclasses import dataclass, field


@dataclass
class CertificateRevocationList:
    """Thread-safe CRL."""
    _revoked: set[bytes] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def revoke(self, entity_id: bytes):
        """Revoke a certificate by entity ID."""
        with self._lock:
            self._revoked.add(entity_id)

    def is_revoked(self, entity_id: bytes) -> bool:
        """Check if an entity's certificate is revoked."""
        with self._lock:
            return entity_id in self._revoked

    def unrevoke(self, entity_id: bytes):
        """Remove revocation (for testing)."""
        with self._lock:
            self._revoked.discard(entity_id)

    @property
    def count(self) -> int:
        return len(self._revoked)
