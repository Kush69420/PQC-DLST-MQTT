"""
Phase III — Security Agreement on Topic.

TTA creates sub-topics on the broker and generates per-level keying material.

Protocol flow:
  1. TTA generates per-level Seed_L (one per security level in range)
  2. TTA derives K_st_l = PRG(Seed_L ∥ EpochID) — Eq. 5
  3. TTA derives Salt_epoch = PRG(salt_seed ∥ EpochID) — 48-bit
  4. TTA assigns 16-bit ID_P to publisher
  5. TTA creates sub-topics on broker: {base_topic}/L{level}
  6. TTA sends SubTopicConfig to publisher over Phase I channel

Seed_L is generated ONCE per topic and stored in the TTA's topic registry.
It is NOT re-derived per call — this ensures PRG output is deterministic
for the same (Seed_L, EpochID) pair across epoch rotations.
"""

import os
import struct
from dataclasses import dataclass, field

from ..pqcrypto.kdf import derive_subtopic_key, derive_salt


@dataclass
class SubTopicConfig:
    """
    Per-sub-topic keying material sent to publisher after Phase III.

    This is what the publisher needs to encrypt Phase IV data frames.
    """
    topic: str                     # Base MQTT topic
    publisher_id: int              # 16-bit ID_P assigned by TTA
    epoch_id: int                  # 8-bit current epoch
    level_min: int                 # Negotiated minimum level
    level_max: int                 # Negotiated maximum level
    current_level: int             # Currently active level
    subtopic_keys: dict[int, bytes]  # {level: K_st_l} for each level in range
    salt_epoch: bytes              # 6-byte epoch salt
    seed_per_level: dict[int, bytes] # {level: Seed_L} — stored for re-derivation

    def serialize(self) -> bytes:
        """Serialize for encrypted transmission."""
        topic_bytes = self.topic.encode("utf-8")
        header = struct.pack("!HHBBBB",
                             len(topic_bytes),
                             self.publisher_id,
                             self.epoch_id,
                             self.level_min,
                             self.level_max,
                             self.current_level)
        # Keys: count + (level, key_len, key_bytes) per entry
        keys_data = struct.pack("!B", len(self.subtopic_keys))
        for level, key in sorted(self.subtopic_keys.items()):
            keys_data += struct.pack("!BH", level, len(key)) + key

        # Seeds: count + (level, seed_len, seed_bytes) per entry
        seeds_data = struct.pack("!B", len(self.seed_per_level))
        for level, seed in sorted(self.seed_per_level.items()):
            seeds_data += struct.pack("!BH", level, len(seed)) + seed

        return header + topic_bytes + self.salt_epoch + keys_data + seeds_data

    @classmethod
    def deserialize(cls, data: bytes) -> "SubTopicConfig":
        topic_len, pub_id, epoch_id, lmin, lmax, cur = struct.unpack(
            "!HHBBBB", data[:8])
        offset = 8
        topic = data[offset:offset + topic_len].decode("utf-8")
        offset += topic_len
        salt = data[offset:offset + 6]
        offset += 6

        # Keys
        key_count = data[offset]; offset += 1
        keys = {}
        for _ in range(key_count):
            level, klen = struct.unpack("!BH", data[offset:offset + 3])
            offset += 3
            keys[level] = data[offset:offset + klen]
            offset += klen

        # Seeds
        seed_count = data[offset]; offset += 1
        seeds = {}
        for _ in range(seed_count):
            level, slen = struct.unpack("!BH", data[offset:offset + 3])
            offset += 3
            seeds[level] = data[offset:offset + slen]
            offset += slen

        return cls(
            topic=topic, publisher_id=pub_id, epoch_id=epoch_id,
            level_min=lmin, level_max=lmax, current_level=cur,
            subtopic_keys=keys, salt_epoch=salt, seed_per_level=seeds,
        )

    def byte_size(self) -> int:
        return len(self.serialize())


class TopicRegistry:
    """
    TTA-side registry of topic security associations.

    Stores per-topic seeds (generated once), epoch state, and
    publisher assignments. This is the authoritative source for
    sub-topic keying material.
    """

    def __init__(self):
        # {topic: TopicEntry}
        self._topics: dict[str, TopicEntry] = {}
        self._next_publisher_id: int = 1

    def create_topic_association(
            self, topic: str, level_min: int, level_max: int,
            initial_level: int, epoch_id: int = 1) -> SubTopicConfig:
        """
        Create a new topic security association (Phase III).

        Generates seeds, derives keys, assigns publisher ID.
        Seeds are generated ONCE and stored — not re-derived per call.

        Args:
            topic: MQTT topic string.
            level_min: Negotiated minimum security level.
            level_max: Negotiated maximum security level.
            initial_level: Starting security level.
            epoch_id: Initial epoch (default 1).

        Returns:
            SubTopicConfig for the publisher.
        """
        # Generate per-level seeds (ONCE per topic)
        seed_per_level = {}
        for level in range(level_min, level_max + 1):
            if level == 0:
                continue
            seed_per_level[level] = os.urandom(32)  # 256-bit seed

        # Salt derivation seed (separate from key seeds)
        salt_seed = os.urandom(32)

        # Derive keys and salt for current epoch
        subtopic_keys = {}
        for level, seed in seed_per_level.items():
            subtopic_keys[level] = derive_subtopic_key(seed, epoch_id)

        salt_epoch = derive_salt(salt_seed, epoch_id)

        # Assign publisher ID
        pub_id = self._next_publisher_id
        self._next_publisher_id += 1
        if self._next_publisher_id > 0xFFFF:
            raise OverflowError("Publisher ID space exhausted")

        # Store in registry
        entry = TopicEntry(
            topic=topic,
            level_min=level_min,
            level_max=level_max,
            current_level=initial_level,
            epoch_id=epoch_id,
            seed_per_level=seed_per_level,
            salt_seed=salt_seed,
            salt_epoch=salt_epoch,
            subtopic_keys=subtopic_keys,
            publisher_ids=[pub_id],
        )
        self._topics[topic] = entry

        return SubTopicConfig(
            topic=topic,
            publisher_id=pub_id,
            epoch_id=epoch_id,
            level_min=level_min,
            level_max=level_max,
            current_level=initial_level,
            subtopic_keys=subtopic_keys,
            salt_epoch=salt_epoch,
            seed_per_level=seed_per_level,
        )

    def get_topic_entry(self, topic: str) -> "TopicEntry | None":
        return self._topics.get(topic)

    def rotate_epoch(self, topic: str) -> int:
        """
        Rotate epoch for a topic — generates new keys from stored seeds.

        Returns the new epoch_id.
        """
        entry = self._topics.get(topic)
        if entry is None:
            raise ValueError(f"Topic not found: {topic}")

        entry.epoch_id = (entry.epoch_id + 1) % 256  # 8-bit wrap
        # Re-derive keys from STORED seeds (seeds don't change)
        for level, seed in entry.seed_per_level.items():
            entry.subtopic_keys[level] = derive_subtopic_key(seed, entry.epoch_id)
        entry.salt_epoch = derive_salt(entry.salt_seed, entry.epoch_id)

        return entry.epoch_id

    def get_subscriber_context(self, topic: str) -> SubTopicConfig | None:
        """
        Get the current sub-topic context for a subscriber (Phase V).

        Returns the same SubTopicConfig structure but for the current epoch.
        """
        entry = self._topics.get(topic)
        if entry is None:
            return None

        return SubTopicConfig(
            topic=topic,
            publisher_id=0,  # Not relevant for subscriber
            epoch_id=entry.epoch_id,
            level_min=entry.level_min,
            level_max=entry.level_max,
            current_level=entry.current_level,
            subtopic_keys=dict(entry.subtopic_keys),
            salt_epoch=entry.salt_epoch,
            seed_per_level={},  # Subscribers don't get seeds
        )


@dataclass
class TopicEntry:
    """Internal TTA registry entry for a topic."""
    topic: str
    level_min: int
    level_max: int
    current_level: int
    epoch_id: int
    seed_per_level: dict[int, bytes]   # Generated ONCE, stored
    salt_seed: bytes                    # Generated ONCE, stored
    salt_epoch: bytes                   # Derived per epoch
    subtopic_keys: dict[int, bytes]    # Derived per epoch
    publisher_ids: list[int]


def generate_subtopic_names(base_topic: str, level_min: int,
                            level_max: int) -> dict[int, str]:
    """
    Generate MQTT sub-topic names for each security level.

    E.g., "sensors/temp" → {"sensors/temp/L1", "sensors/temp/L2", ...}
    """
    return {
        level: f"{base_topic}/L{level}"
        for level in range(level_min, level_max + 1)
        if level > 0
    }
