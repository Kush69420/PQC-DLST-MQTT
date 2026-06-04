"""
PQC-DLST-MQTT Security Level Definitions and SLSI Scoring.

Defines the 6-level (0–5) hierarchy mapping topic priority to
PQC parameter sets, with the weighted SLSI metric from the paper.

Level | ML-KEM      | ML-DSA    | AES         | Hash       | Priority
------|-------------|-----------|-------------|------------|----------
  0   | None        | None      | None        | None       | —
  1   | ML-KEM-512  | ML-DSA-44 | None(KMAC)  | SHA3-256   | Low
  2   | ML-KEM-512  | ML-DSA-44 | AES-128-GCM | SHA3-256   | Low–Med
  3   | ML-KEM-768  | ML-DSA-44 | AES-192-GCM | SHA3-384   | Medium
  4   | ML-KEM-768  | ML-DSA-65 | AES-256-GCM | SHA3-384   | High
  5   | ML-KEM-1024 | ML-DSA-87 | AES-256-GCM | SHAKE-256  | Critical
"""

from dataclasses import dataclass
from enum import IntEnum


class Priority(IntEnum):
    """Topic priority levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# Priority → allowed security level range
PRIORITY_LEVEL_RANGES = {
    Priority.LOW:      (1, 2),
    Priority.MEDIUM:   (2, 3),
    Priority.HIGH:     (3, 4),
    Priority.CRITICAL: (4, 5),
}


@dataclass(frozen=True)
class SecurityLevelConfig:
    """Configuration for a single security level."""
    level: int
    kem_alg: str | None         # ML-KEM parameter set name
    sig_alg: str | None         # ML-DSA parameter set name
    aes_key_bits: int | None    # AES key size in bits (None = no AEAD)
    hash_alg: str | None        # Hash function name
    nist_kem_level: int         # NIST security level for KEM (0,1,3,5)
    nist_sig_level: int         # NIST security level for signature (0,2,3,5)
    has_confidentiality: bool
    has_integrity: bool
    has_authentication: bool

    # Per-primitive normalized scores for SLSI computation
    # Φ (KEM strength), Ψ (Signature strength), Ω (Cipher strength), Γ (Hash strength)
    phi: float = 0.0    # KEM
    psi: float = 0.0    # Signature
    omega: float = 0.0  # Cipher
    gamma: float = 0.0  # Hash


# The six security levels
SECURITY_LEVELS = {
    0: SecurityLevelConfig(
        level=0, kem_alg=None, sig_alg=None, aes_key_bits=None,
        hash_alg=None, nist_kem_level=0, nist_sig_level=0,
        has_confidentiality=False, has_integrity=False, has_authentication=False,
        phi=0.0, psi=0.0, omega=0.0, gamma=0.0,
    ),
    1: SecurityLevelConfig(
        level=1, kem_alg="ML-KEM-512", sig_alg="ML-DSA-44", aes_key_bits=None,
        hash_alg="SHA3-256", nist_kem_level=1, nist_sig_level=2,
        has_confidentiality=False, has_integrity=True, has_authentication=True,
        phi=0.2, psi=0.4, omega=0.5, gamma=0.8,
    ),
    2: SecurityLevelConfig(
        level=2, kem_alg="ML-KEM-512", sig_alg="ML-DSA-44", aes_key_bits=128,
        hash_alg="SHA3-256", nist_kem_level=1, nist_sig_level=2,
        has_confidentiality=True, has_integrity=True, has_authentication=True,
        phi=0.2, psi=0.4, omega=0.5, gamma=0.8,
    ),
    3: SecurityLevelConfig(
        level=3, kem_alg="ML-KEM-768", sig_alg="ML-DSA-44", aes_key_bits=192,
        hash_alg="SHA3-384", nist_kem_level=3, nist_sig_level=2,
        has_confidentiality=True, has_integrity=True, has_authentication=True,
        phi=0.6, psi=0.4, omega=0.75, gamma=0.9,
    ),
    4: SecurityLevelConfig(
        level=4, kem_alg="ML-KEM-768", sig_alg="ML-DSA-65", aes_key_bits=256,
        hash_alg="SHA3-384", nist_kem_level=3, nist_sig_level=3,
        has_confidentiality=True, has_integrity=True, has_authentication=True,
        phi=0.6, psi=0.6, omega=1.0, gamma=0.9,
    ),
    5: SecurityLevelConfig(
        level=5, kem_alg="ML-KEM-1024", sig_alg="ML-DSA-87", aes_key_bits=256,
        hash_alg="SHAKE-256", nist_kem_level=5, nist_sig_level=5,
        has_confidentiality=True, has_integrity=True, has_authentication=True,
        phi=1.0, psi=1.0, omega=1.0, gamma=1.0,
    ),
}


class SecurityLevel:
    """Accessor for security level configurations."""

    @staticmethod
    def get(level: int) -> SecurityLevelConfig:
        if level not in SECURITY_LEVELS:
            raise ValueError(f"Invalid security level: {level}")
        return SECURITY_LEVELS[level]

    @staticmethod
    def get_range_for_priority(priority: Priority) -> tuple[int, int]:
        """Return (min_level, max_level) for a topic priority."""
        return PRIORITY_LEVEL_RANGES[priority]

    @staticmethod
    def all_levels() -> list[SecurityLevelConfig]:
        return [SECURITY_LEVELS[i] for i in range(6)]


class SLSI:
    """
    Security Level Score Index — the paper's weighted metric.

    SLSI_L = w_K · Φ + w_S · Ψ + w_E · Ω + w_H · Γ

    Where:
      Φ = KEM strength score (0.0 to 1.0)
      Ψ = Signature strength score (0.0 to 1.0)
      Ω = Cipher strength score (0.0 to 1.0)
      Γ = Hash strength score (0.0 to 1.0)
      Σw = 1.0

    Default weights are equal (0.25 each). The paper allows
    tuning weights based on deployment requirements.
    """

    def __init__(self, w_kem: float = 0.25, w_sig: float = 0.25,
                 w_cipher: float = 0.25, w_hash: float = 0.25):
        """
        Args:
            w_kem: Weight for KEM strength.
            w_sig: Weight for signature strength.
            w_cipher: Weight for cipher strength.
            w_hash: Weight for hash strength.

        Raises:
            ValueError: If weights don't sum to 1.0.
        """
        total = w_kem + w_sig + w_cipher + w_hash
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Weights must sum to 1.0, got {total}")
        self.w_kem = w_kem
        self.w_sig = w_sig
        self.w_cipher = w_cipher
        self.w_hash = w_hash

    def score(self, level: int) -> float:
        """
        Compute SLSI for a given security level.

        Returns:
            Score in [0.0, 1.0]. Level 0 = 0.0, Level 5 = 1.0.
        """
        config = SecurityLevel.get(level)
        return (
            self.w_kem * config.phi +
            self.w_sig * config.psi +
            self.w_cipher * config.omega +
            self.w_hash * config.gamma
        )

    def weighted_average_security_score(
            self, level_time_pairs: list[tuple[int, float]]) -> float:
        """
        Compute Weighted Average Security Score (WASS) over time.

        WASS = Σ(SLSI_L_i · t_i) / Σ(t_i)

        Used to evaluate HPD-HPU vs LPD-LPU heuristics.

        Args:
            level_time_pairs: List of (level, duration_seconds) tuples
                              representing time spent at each security level.

        Returns:
            WASS score in [0.0, 1.0].
        """
        if not level_time_pairs:
            return 0.0
        total_time = sum(t for _, t in level_time_pairs)
        if total_time == 0:
            return 0.0
        weighted_sum = sum(self.score(level) * t for level, t in level_time_pairs)
        return weighted_sum / total_time
