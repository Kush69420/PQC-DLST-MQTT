"""
Phase VI — Dynamic Security Update.

Implements the HPD-HPU and LPD-LPU heuristics for dynamic security
level switching, and the epoch rotation mechanism.

Heuristics:
  HPD-HPU (High Priority Downgrade, High Priority Upgrade):
    - Downgrades high-priority topics first when resources are scarce
    - Upgrades high-priority topics first when resources recover
    - Rationale: high-priority topics have wider level ranges

  LPD-LPU (Low Priority Downgrade, Low Priority Upgrade):
    - Downgrades low-priority topics first
    - Upgrades low-priority topics first
    - Rationale: protect high-priority topics longer

Epoch rotation:
  - TTA generates new EpochID, re-derives keys from stored seeds
  - Publisher detects level change → re-derives key from new seed
  - Subscriber detects EpochID mismatch in header → pauses, re-runs Phase V
  - Re-keying is SYMMETRIC (PRG derivation), not a fresh KEM encapsulation

WASS tracking:
  Records (level, duration) pairs for benchmark evaluation of heuristic quality.
"""

import time
from dataclasses import dataclass, field
from enum import Enum

from .security_levels import Priority, SLSI, PRIORITY_LEVEL_RANGES


class Heuristic(Enum):
    HPD_HPU = "HPD-HPU"
    LPD_LPU = "LPD-LPU"


@dataclass
class TopicSecurityState:
    """Runtime security state for a topic."""
    topic: str
    priority: Priority
    level_min: int
    level_max: int
    current_level: int
    epoch_id: int
    # WASS tracking
    level_history: list[tuple[int, float]] = field(default_factory=list)
    _last_level_change_time: float = field(default_factory=time.monotonic)

    def record_level_change(self, new_level: int):
        """Record time spent at current level before changing."""
        now = time.monotonic()
        duration = now - self._last_level_change_time
        self.level_history.append((self.current_level, duration))
        self.current_level = new_level
        self._last_level_change_time = now

    def finalize_history(self):
        """Record final segment (call at end of simulation)."""
        now = time.monotonic()
        duration = now - self._last_level_change_time
        self.level_history.append((self.current_level, duration))


class DynamicSecurityManager:
    """
    Manages dynamic security level updates across all topics.

    Implements HPD-HPU and LPD-LPU heuristics and tracks WASS.
    """

    def __init__(self, heuristic: Heuristic = Heuristic.HPD_HPU):
        self.heuristic = heuristic
        self.slsi = SLSI()  # Default equal weights
        self._topics: dict[str, TopicSecurityState] = {}

    def register_topic(self, topic: str, priority: Priority,
                       level_min: int, level_max: int,
                       initial_level: int, epoch_id: int):
        """Register a topic for dynamic management."""
        self._topics[topic] = TopicSecurityState(
            topic=topic, priority=priority,
            level_min=level_min, level_max=level_max,
            current_level=initial_level, epoch_id=epoch_id,
        )

    def trigger_downgrade(self, resource_pressure: float = 0.0) -> list[tuple[str, int, int]]:
        """
        Trigger a downgrade across managed topics.

        Args:
            resource_pressure: 0.0-1.0 indicating how much to downgrade.

        Returns:
            List of (topic, old_level, new_level) for topics that changed.
        """
        # Sort topics by priority for downgrade order
        topics = sorted(self._topics.values(),
                        key=lambda t: t.priority.value,
                        reverse=(self.heuristic == Heuristic.HPD_HPU))

        changes = []
        for state in topics:
            if state.current_level > state.level_min:
                old_level = state.current_level
                new_level = max(state.level_min, state.current_level - 1)
                state.record_level_change(new_level)
                changes.append((state.topic, old_level, new_level))

        return changes

    def trigger_upgrade(self) -> list[tuple[str, int, int]]:
        """
        Trigger an upgrade across managed topics.

        Returns:
            List of (topic, old_level, new_level) for topics that changed.
        """
        topics = sorted(self._topics.values(),
                        key=lambda t: t.priority.value,
                        reverse=(self.heuristic == Heuristic.HPD_HPU))

        changes = []
        for state in topics:
            if state.current_level < state.level_max:
                old_level = state.current_level
                new_level = min(state.level_max, state.current_level + 1)
                state.record_level_change(new_level)
                changes.append((state.topic, old_level, new_level))

        return changes

    def get_wass(self, topic: str) -> float:
        """Compute WASS for a topic."""
        state = self._topics.get(topic)
        if state is None:
            return 0.0
        # Include current segment
        history = list(state.level_history)
        now = time.monotonic()
        history.append((state.current_level, now - state._last_level_change_time))
        return self.slsi.weighted_average_security_score(history)

    def get_all_wass(self) -> dict[str, float]:
        """Compute WASS for all topics."""
        return {topic: self.get_wass(topic) for topic in self._topics}

    def finalize_all(self):
        """Finalize all topic histories (call at end of simulation)."""
        for state in self._topics.values():
            state.finalize_history()


def detect_epoch_mismatch(received_epoch_id: int,
                          expected_epoch_id: int) -> bool:
    """
    Detect epoch mismatch in a received Phase IV header.

    When a subscriber receives a frame with a different EpochID than
    expected, it must pause data processing and re-run Phase V to
    obtain the new sub-topic key.

    Args:
        received_epoch_id: EpochID from the received data frame header.
        expected_epoch_id: Subscriber's current expected EpochID.

    Returns:
        True if mismatch detected (must re-run Phase V).
    """
    return received_epoch_id != expected_epoch_id
