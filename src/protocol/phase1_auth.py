"""
Phase I — Mutual Authentication.

Protocol flow:
  1. Client generates ephemeral ML-KEM keypair: (ek, dk) ← ML-KEM.KeyGen()
  2. Client → TTA: Auth_Req = {ek, nonce_cli, id_cli, sn}, signed with ML-DSA
  3. TTA verifies signature, checks CRL, then:
     TTA encapsulates: (K, c) ← ML-KEM.Encaps(ek)
  4. TTA → Client: Auth_Resp = {c, nonce_tta, sn}, signed with ML-DSA
     Transcript-bound: signature covers (Nonce_TTA ∥ Nonce_cli ∥ ID_cli ∥ sn ∥ c)
  5. Client decapsulates: K ← ML-KEM.Decaps(dk, c)
  6. Both derive channel keys:
     K_cli→TTA ∥ K_TTA→cli = SHAKE-256(K ∥ Nonce_cli ∥ Nonce_TTA)

The two directional keys prevent reflection attacks.
"""

import os
import struct
from dataclasses import dataclass

from ..pqcrypto.kem import KEMWrapper
from ..pqcrypto.sig import SigWrapper
from ..pqcrypto.kdf import derive_channel_keys


NONCE_SIZE = 32  # 256-bit nonces


@dataclass
class AuthRequest:
    """Phase I authentication request (Client → TTA)."""
    encapsulation_key: bytes   # ML-KEM public key
    nonce_client: bytes        # 32-byte random nonce
    client_id: bytes           # Client identifier
    sequence_number: int       # Monotonic sequence number
    signature: bytes           # ML-DSA signature over the above fields

    def serialize(self) -> bytes:
        """Serialize for transmission."""
        id_len = len(self.client_id)
        ek_len = len(self.encapsulation_key)
        sig_len = len(self.signature)
        header = struct.pack("!HHH I",
                             ek_len, id_len, sig_len,
                             self.sequence_number)
        return (header +
                self.encapsulation_key +
                self.nonce_client +
                self.client_id +
                self.signature)

    @classmethod
    def deserialize(cls, data: bytes) -> "AuthRequest":
        """Deserialize from received bytes."""
        ek_len, id_len, sig_len, sn = struct.unpack("!HHH I", data[:10])
        offset = 10
        ek = data[offset:offset + ek_len]; offset += ek_len
        nonce = data[offset:offset + NONCE_SIZE]; offset += NONCE_SIZE
        client_id = data[offset:offset + id_len]; offset += id_len
        sig = data[offset:offset + sig_len]; offset += sig_len
        return cls(
            encapsulation_key=ek,
            nonce_client=nonce,
            client_id=client_id,
            sequence_number=sn,
            signature=sig,
        )

    def signable_content(self) -> bytes:
        """Return the content that is signed."""
        return (self.encapsulation_key +
                self.nonce_client +
                self.client_id +
                struct.pack("!I", self.sequence_number))

    def byte_size(self) -> int:
        """Total serialized size for R2 byte counting."""
        return len(self.serialize())


@dataclass
class AuthResponse:
    """Phase I authentication response (TTA → Client)."""
    ciphertext: bytes          # ML-KEM ciphertext
    nonce_tta: bytes           # 32-byte random nonce
    sequence_number: int       # Monotonic sequence number
    signature: bytes           # ML-DSA signature over transcript

    def serialize(self) -> bytes:
        """Serialize for transmission."""
        ct_len = len(self.ciphertext)
        sig_len = len(self.signature)
        header = struct.pack("!HH I", ct_len, sig_len, self.sequence_number)
        return (header +
                self.ciphertext +
                self.nonce_tta +
                self.signature)

    @classmethod
    def deserialize(cls, data: bytes) -> "AuthResponse":
        """Deserialize from received bytes."""
        ct_len, sig_len, sn = struct.unpack("!HH I", data[:8])
        offset = 8
        ct = data[offset:offset + ct_len]; offset += ct_len
        nonce = data[offset:offset + NONCE_SIZE]; offset += NONCE_SIZE
        sig = data[offset:offset + sig_len]; offset += sig_len
        return cls(
            ciphertext=ct,
            nonce_tta=nonce,
            sequence_number=sn,
            signature=sig,
        )

    def byte_size(self) -> int:
        """Total serialized size for R2 byte counting."""
        return len(self.serialize())


def transcript(nonce_tta: bytes, nonce_client: bytes, client_id: bytes,
               sn: int, ciphertext: bytes) -> bytes:
    """
    Build the transcript for signature binding.

    Transcript = Nonce_TTA ∥ Nonce_cli ∥ ID_cli ∥ sn ∥ c

    This prevents UKS (Unknown Key Share) attacks by binding the
    TTA's response to the specific client request.
    """
    return nonce_tta + nonce_client + client_id + struct.pack("!I", sn) + ciphertext


class Phase1Client:
    """Client-side Phase I mutual authentication."""

    def __init__(self, client_id: bytes, security_level: int,
                 signing_key: bytes, verification_key: bytes):
        """
        Args:
            client_id: Unique client identifier.
            security_level: Protocol security level (1-5).
            signing_key: Client's ML-DSA signing key.
            verification_key: Client's ML-DSA verification key.
        """
        self.client_id = client_id
        self.level = security_level
        self.sk_sign = signing_key
        self.vk_sign = verification_key
        self.kem = KEMWrapper(security_level)
        self.sig = SigWrapper(security_level)

        # Ephemeral state
        self._ek: bytes | None = None
        self._dk: bytes | None = None
        self._nonce_client: bytes | None = None

    def create_auth_request(self, sequence_number: int) -> AuthRequest:
        """
        Step 1-2: Generate KEM keypair and create signed Auth_Req.

        Returns:
            AuthRequest ready for transmission.
        """
        # Generate ephemeral ML-KEM keypair
        self._ek, self._dk = self.kem.keygen()
        self._nonce_client = os.urandom(NONCE_SIZE)

        # Build request
        req = AuthRequest(
            encapsulation_key=self._ek,
            nonce_client=self._nonce_client,
            client_id=self.client_id,
            sequence_number=sequence_number,
            signature=b"",  # placeholder
        )

        # Sign
        req.signature = self.sig.sign(self.sk_sign, req.signable_content())
        return req

    def process_auth_response(self, resp: AuthResponse,
                              tta_vk: bytes) -> tuple[bytes, bytes]:
        """
        Step 5-6: Verify response, decapsulate, derive channel keys.

        Args:
            resp: AuthResponse from TTA.
            tta_vk: TTA's ML-DSA verification key.

        Returns:
            (k_client_to_tta, k_tta_to_client): Bidirectional channel keys.

        Raises:
            ValueError: If signature verification fails.
        """
        if self._dk is None or self._nonce_client is None:
            raise RuntimeError("Must call create_auth_request first")

        # Verify TTA's signature over transcript
        t = transcript(resp.nonce_tta, self._nonce_client,
                        self.client_id, resp.sequence_number,
                        resp.ciphertext)
        if not self.sig.verify(tta_vk, t, resp.signature):
            raise ValueError("TTA signature verification failed — possible MITM")

        # Decapsulate
        shared_secret = self.kem.decaps(self._dk, resp.ciphertext)

        # Derive bidirectional channel keys
        k_c2t, k_t2c = derive_channel_keys(
            shared_secret, self._nonce_client, resp.nonce_tta
        )

        # Clear ephemeral state
        self._dk = None

        return k_c2t, k_t2c


class Phase1TTA:
    """TTA-side Phase I mutual authentication."""

    def __init__(self, security_level: int,
                 signing_key: bytes, verification_key: bytes):
        """
        Args:
            security_level: Protocol security level (1-5).
            signing_key: TTA's ML-DSA signing key.
            verification_key: TTA's ML-DSA verification key.
        """
        self.level = security_level
        self.sk_sign = signing_key
        self.vk_sign = verification_key
        self.kem = KEMWrapper(security_level)
        self.sig = SigWrapper(security_level)

    def process_auth_request(self, req: AuthRequest, client_vk: bytes,
                             sequence_number: int) -> tuple[AuthResponse, bytes, bytes]:
        """
        Step 3-4: Verify request, encapsulate, sign transcript, derive keys.

        Args:
            req: AuthRequest from client.
            client_vk: Client's ML-DSA verification key (from certificate).
            sequence_number: TTA's sequence number for this response.

        Returns:
            (auth_response, k_client_to_tta, k_tta_to_client)

        Raises:
            ValueError: If client signature verification fails.
        """
        # Verify client's signature
        if not self.sig.verify(client_vk, req.signable_content(), req.signature):
            raise ValueError("Client signature verification failed")

        # Encapsulate
        shared_secret, ciphertext = self.kem.encaps(req.encapsulation_key)

        # Generate TTA nonce
        nonce_tta = os.urandom(NONCE_SIZE)

        # Build transcript and sign
        t = transcript(nonce_tta, req.nonce_client,
                        req.client_id, sequence_number, ciphertext)
        sig = self.sig.sign(self.sk_sign, t)

        resp = AuthResponse(
            ciphertext=ciphertext,
            nonce_tta=nonce_tta,
            sequence_number=sequence_number,
            signature=sig,
        )

        # Derive bidirectional channel keys
        k_c2t, k_t2c = derive_channel_keys(
            shared_secret, req.nonce_client, nonce_tta
        )

        return resp, k_c2t, k_t2c
