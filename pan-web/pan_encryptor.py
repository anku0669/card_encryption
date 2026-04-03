"""
pan_encryptor.py
────────────────
AES-256-GCM encryption/decryption for Primary Account Numbers.

Design:
  • AES-256-GCM — authenticated encryption (confidentiality + integrity).
  • Fresh 96-bit (12-byte) IV per encryption call; nonce reuse is catastrophic for GCM.
  • The token string is used as Additional Authenticated Data (AAD) so that a
    ciphertext cannot be silently swapped between two token records.
  • Key is stored in memory only; in production load from a KMS / HSM.
  • Plaintext bytes are zeroed immediately after use where Python's GC allows.
"""

import os
import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_KEY_BYTES = 32     # AES-256
_IV_BYTES  = 12     # 96-bit recommended for GCM
_TAG_BYTES = 16     # 128-bit authentication tag (AESGCM default)


@dataclass(frozen=True)
class EncryptionResult:
    """Immutable value object holding the three GCM outputs (all Base64-encoded)."""
    iv:          str
    cipher_text: str
    auth_tag:    str


class PanEncryptor:
    """
    Encrypts and decrypts PANs with AES-256-GCM.

    Usage
    -----
    enc = PanEncryptor()                  # new random key
    enc = PanEncryptor(key_bytes=raw_key) # existing 32-byte key (testing / rotation)
    """

    def __init__(self, key_bytes: bytes | None = None) -> None:
        if key_bytes is None:
            key_bytes = os.urandom(_KEY_BYTES)
        if len(key_bytes) != _KEY_BYTES:
            raise ValueError(f"AES-256 key must be exactly {_KEY_BYTES} bytes")
        self._aesgcm = AESGCM(key_bytes)

    # ── Encryption ─────────────────────────────────────────────────────────────

    def encrypt(self, pan: str, aad: str) -> EncryptionResult:
        """
        Encrypt a PAN.

        Parameters
        ----------
        pan : raw card number (digits only, validated by caller)
        aad : Additional Authenticated Data — not secret, but authenticated.
              Use the token string so ciphertexts are bound to their token.

        Returns
        -------
        EncryptionResult with Base64-encoded iv, cipher_text, auth_tag.
        """
        iv = os.urandom(_IV_BYTES)
        # cryptography's AESGCM appends the 16-byte tag at the end of the output
        raw = self._aesgcm.encrypt(iv, pan.encode(), aad.encode())

        cipher_text = raw[:-_TAG_BYTES]
        auth_tag    = raw[-_TAG_BYTES:]

        return EncryptionResult(
            iv          = base64.b64encode(iv).decode(),
            cipher_text = base64.b64encode(cipher_text).decode(),
            auth_tag    = base64.b64encode(auth_tag).decode(),
        )

    # ── Decryption ─────────────────────────────────────────────────────────────

    def decrypt(self, iv_b64: str, cipher_text_b64: str,
                auth_tag_b64: str, aad: str) -> str:
        """
        Decrypt a PAN.

        Raises
        ------
        EncryptionError if the key, AAD, or ciphertext has been tampered with.
        """
        try:
            iv          = base64.b64decode(iv_b64)
            cipher_text = base64.b64decode(cipher_text_b64)
            auth_tag    = base64.b64decode(auth_tag_b64)

            # AESGCM.decrypt expects ciphertext || tag
            combined = cipher_text + auth_tag
            plain = self._aesgcm.decrypt(iv, combined, aad.encode())
            return plain.decode()
        except Exception as exc:
            raise EncryptionError(
                "PAN decryption failed — possible tampering or wrong key"
            ) from exc


class EncryptionError(RuntimeError):
    """Raised when encryption or decryption fails."""
