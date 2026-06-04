"""
PQC-DLST-MQTT Header Codec, Replay Guard, and Sequence Number State.

9-byte data-plane header (matches the final paper's Table exactly):
  Byte 1:   Max level (4 bits) | Min level (4 bits)
  Byte 2:   IntConf flag (1b) | Hash ID (3b) | Cipher ID (4b)
  Bytes 3-4: ID_P (16-bit publisher identifier)
  Bytes 5-8: Counter32 (32-bit message counter)
  Byte 9:   EpochID (8-bit epoch identifier)

Total: 9 bytes header + payload + tag (16 bytes for GCM / 32 bytes for KMAC)
"""

import struct
import threading
from dataclasses import dataclass, field


# --- Hash ID encoding (3 bits → 8 possible values) ---
HASH_IDS = {
    "SHA3-256":  0b001,
    "SHA3-384":  0b010,
    "SHAKE-256": 0b011,
    "KMAC-256":  0b100,
}
HASH_IDS_REV = {v: k for k, v in HASH_IDS.items()}

# --- Cipher ID encoding (4 bits → 16 possible values) ---
CIPHER_IDS = {
    None:           0b0000,  # No cipher (Level 0-1)
    "AES-128-GCM":  0b0001,
    "AES-192-GCM":  0b0010,
    "AES-256-GCM":  0b0011,
}
CIPHER_IDS_REV = {v: k for k, v in CIPHER_IDS.items()}

# Map security levels to cipher names for header encoding
LEVEL_TO_CIPHER = {
    0: None, 1: None,
    2: "AES-128-GCM", 3: "AES-192-GCM",
    4: "AES-256-GCM", 5: "AES-256-GCM",
}

LEVEL_TO_HASH = {
    0: None, 1: "KMAC-256", 2: "SHA3-256",
    3: "SHA3-384", 4: "SHA3-384", 5: "SHAKE-256",
}


@dataclass
class DataHeader:
    """Parsed 9-byte data-plane header."""
    max_level: int          # 4 bits: negotiated maximum security level
    min_level: int          # 4 bits: negotiated minimum security level
    int_conf_flag: bool     # 1 bit: True=confidentiality, False=integrity-only
    hash_id: int            # 3 bits: hash algorithm identifier
    cipher_id: int          # 4 bits: cipher algorithm identifier
    publisher_id: int       # 16 bits: publisher identifier
    counter: int            # 32 bits: message counter
    epoch_id: int           # 8 bits: epoch identifier

    HEADER_SIZE = 9

    @property
    def hash_name(self) -> str | None:
        return HASH_IDS_REV.get(self.hash_id)

    @property
    def cipher_name(self) -> str | None:
        return CIPHER_IDS_REV.get(self.cipher_id)


class HeaderCodec:
    """Encode/decode the 9-byte PQC-DLST-MQTT data-plane header."""

    HEADER_SIZE = 9

    @staticmethod
    def encode(max_level: int, min_level: int, int_conf_flag: bool,
               hash_name: str, cipher_name: str | None,
               publisher_id: int, counter: int, epoch_id: int) -> bytes:
        """
        Encode a 9-byte data header.

        Args:
            max_level: Negotiated maximum security level (0-5).
            min_level: Negotiated minimum security level (0-5).
            int_conf_flag: True if confidentiality is enabled.
            hash_name: Hash algorithm name (e.g., "SHA3-256").
            cipher_name: Cipher name or None for no cipher.
            publisher_id: 16-bit publisher ID.
            counter: 32-bit message counter.
            epoch_id: 8-bit epoch ID.

        Returns:
            9-byte header.
        """
        # Byte 1: max_level(4b) | min_level(4b)
        byte1 = ((max_level & 0x0F) << 4) | (min_level & 0x0F)

        # Byte 2: int_conf_flag(1b) | hash_id(3b) | cipher_id(4b)
        hash_id = HASH_IDS.get(hash_name, 0)
        cipher_id = CIPHER_IDS.get(cipher_name, 0)
        byte2 = ((1 if int_conf_flag else 0) << 7) | ((hash_id & 0x07) << 4) | (cipher_id & 0x0F)

        return struct.pack("!BBHIB",
                           byte1, byte2, publisher_id & 0xFFFF,
                           counter & 0xFFFFFFFF, epoch_id & 0xFF)

    @staticmethod
    def decode(data: bytes) -> DataHeader:
        """
        Decode a 9-byte data header.

        Args:
            data: 9 bytes.

        Returns:
            Parsed DataHeader.

        Raises:
            ValueError: If data is not 9 bytes.
        """
        if len(data) < 9:
            raise ValueError(f"Header must be at least 9 bytes, got {len(data)}")

        byte1, byte2, publisher_id, counter, epoch_id = struct.unpack("!BBHIB", data[:9])

        max_level = (byte1 >> 4) & 0x0F
        min_level = byte1 & 0x0F
        int_conf_flag = bool((byte2 >> 7) & 0x01)
        hash_id = (byte2 >> 4) & 0x07
        cipher_id = byte2 & 0x0F

        return DataHeader(
            max_level=max_level,
            min_level=min_level,
            int_conf_flag=int_conf_flag,
            hash_id=hash_id,
            cipher_id=cipher_id,
            publisher_id=publisher_id,
            counter=counter,
            epoch_id=epoch_id,
        )

    @staticmethod
    def encode_for_level(level: int, publisher_id: int, counter: int,
                         epoch_id: int, min_level: int = None) -> bytes:
        """
        Convenience: encode header for a given security level with defaults.

        Args:
            level: Current security level (0-5).
            publisher_id: 16-bit publisher ID.
            counter: 32-bit message counter.
            epoch_id: 8-bit epoch ID.
            min_level: Minimum negotiated level (defaults to level).

        Returns:
            9-byte header.
        """
        if min_level is None:
            min_level = level
        has_conf = level >= 2
        hash_name = LEVEL_TO_HASH.get(level)
        cipher_name = LEVEL_TO_CIPHER.get(level)
        return HeaderCodec.encode(
            max_level=level, min_level=min_level,
            int_conf_flag=has_conf,
            hash_name=hash_name if hash_name else "SHA3-256",
            cipher_name=cipher_name,
            publisher_id=publisher_id,
            counter=counter, epoch_id=epoch_id,
        )


class SequenceNumberState:
    """
    Thread-safe sequence number state for control-plane messages.

    Manages monotonically increasing sequence numbers and ensures
    no (key, IV) pair reuse across a session.
    """

    def __init__(self, initial: int = 0):
        self._counter = initial
        self._lock = threading.Lock()

    def next(self) -> int:
        """Get and increment the sequence number. Thread-safe."""
        with self._lock:
            sn = self._counter
            self._counter += 1
            if self._counter > 0xFFFFFFFF:
                raise OverflowError(
                    "Sequence number overflow — must re-authenticate (new epoch)"
                )
            return sn

    @property
    def current(self) -> int:
        return self._counter

    def reset(self):
        """Reset on re-authentication."""
        with self._lock:
            self._counter = 0


class ReplayGuard:
    """
    Anti-replay protection per (ID_P, EpochID) pair.

    Rejects messages where Counter_wire ≤ Counter_max for the same
    publisher and epoch. Flushes state on epoch change or reboot.

    Uses a sliding window for out-of-order tolerance.
    """

    def __init__(self, window_size: int = 64):
        """
        Args:
            window_size: Size of the sliding window for out-of-order packets.
        """
        self.window_size = window_size
        # {(publisher_id, epoch_id): (max_counter, seen_bitmap)}
        self._state: dict[tuple[int, int], tuple[int, int]] = {}
        self._lock = threading.Lock()

    def check_and_accept(self, publisher_id: int, epoch_id: int,
                         counter: int) -> bool:
        """
        Check if a message is fresh (not replayed).

        Args:
            publisher_id: 16-bit publisher ID from header.
            epoch_id: 8-bit epoch ID from header.
            counter: 32-bit counter from header.

        Returns:
            True if the message is accepted (fresh), False if replayed.
        """
        key = (publisher_id, epoch_id)

        with self._lock:
            if key not in self._state:
                # First message from this (publisher, epoch)
                self._state[key] = (counter, 0)
                return True

            max_counter, bitmap = self._state[key]

            if counter > max_counter:
                # New high — shift window
                shift = counter - max_counter
                if shift < self.window_size:
                    bitmap = (bitmap << shift) | (1 << (shift - 1))
                else:
                    bitmap = 0
                self._state[key] = (counter, bitmap)
                return True

            elif counter == max_counter:
                # Exact replay
                return False

            else:
                # counter < max_counter — check window
                diff = max_counter - counter
                if diff >= self.window_size:
                    # Too old
                    return False
                bit = 1 << (diff - 1)
                if bitmap & bit:
                    # Already seen
                    return False
                # Accept and mark
                self._state[key] = (max_counter, bitmap | bit)
                return True

    def flush_epoch(self, publisher_id: int, epoch_id: int):
        """Flush state for a specific (publisher, epoch) — called on epoch rotation."""
        key = (publisher_id, epoch_id)
        with self._lock:
            self._state.pop(key, None)

    def flush_all(self):
        """Flush all state — called on subscriber reboot."""
        with self._lock:
            self._state.clear()

    def get_state_count(self) -> int:
        """Return number of tracked (publisher, epoch) pairs."""
        return len(self._state)
