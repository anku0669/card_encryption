"""
tokenization_service.py
───────────────────────
Core service: validate → mask → tokenize → encrypt → store.

The vault maps token → EncryptedPan and never holds a raw PAN.
In production, swap the in-memory dict for a database + KMS-backed key store.
"""

from __future__ import annotations

import uuid
from typing import Optional

from pan_encryptor import PanEncryptor
from pan_masker   import validate, mask, detect_scheme
from models       import DecryptedCard, EncryptedPan


class TokenizationService:
    """
    Public API
    ──────────
    tokenize(pan)          → EncryptedPan   (stores token, never raw PAN)
    detokenize(token)      → DecryptedCard  (use as context manager)
    find_by_token(token)   → EncryptedPan | None
    revoke_token(token)    → bool
    vault_size()           → int
    """

    def __init__(self, encryptor: PanEncryptor | None = None) -> None:
        self._vault: dict[str, EncryptedPan] = {}
        self._enc   = encryptor or PanEncryptor()

    # ── Tokenize ───────────────────────────────────────────────────────────────

    def tokenize(self, raw_pan: str) -> EncryptedPan:
        """
        Tokenize a PAN.

        1. Validate (Luhn + length) — raises ValueError on failure.
        2. Derive masked PAN and card scheme without persisting raw PAN.
        3. Generate a cryptographically random token (UUID v4).
        4. Encrypt with AES-256-GCM, using the token as AAD.
        5. Store only EncryptedPan — raw PAN is never written to the vault.

        Returns the EncryptedPan record (safe to return to the caller).
        """
        validate(raw_pan)                          # raises ValueError if invalid

        masked  = mask(raw_pan)
        scheme  = detect_scheme(raw_pan)
        token   = str(uuid.uuid4())

        result  = self._enc.encrypt(raw_pan, aad=token)

        record  = EncryptedPan(
            token       = token,
            cipher_text = result.cipher_text,
            iv          = result.iv,
            auth_tag    = result.auth_tag,
            masked_pan  = masked,
            card_scheme = scheme,
        )
        self._vault[token] = record
        return record

    # ── Detokenize ─────────────────────────────────────────────────────────────

    def detokenize(self, token: str) -> DecryptedCard:
        """
        Decrypt the PAN associated with *token*.

        Returns a DecryptedCard — ALWAYS use it as a context manager:

            with service.detokenize(token) as card:
                use(card.pan)

        Raises KeyError if the token is unknown.
        """
        record = self._vault.get(token)
        if record is None:
            raise KeyError(f"Unknown token: {token!r}")

        pan = self._enc.decrypt(
            iv_b64          = record.iv,
            cipher_text_b64 = record.cipher_text,
            auth_tag_b64    = record.auth_tag,
            aad             = token,     # must match the AAD used during encrypt
        )
        return DecryptedCard(
            pan         = pan,
            masked_pan  = record.masked_pan,
            card_scheme = record.card_scheme,
            token       = token,
        )

    # ── Token management ───────────────────────────────────────────────────────

    def find_by_token(self, token: str) -> Optional[EncryptedPan]:
        """Look up an encrypted record without decrypting — safe for display."""
        return self._vault.get(token)

    def revoke_token(self, token: str) -> bool:
        """
        Remove a token from the vault.
        After revocation the PAN is irrecoverable through this service.
        Returns True if the token existed and was removed.
        """
        return self._vault.pop(token, None) is not None

    def vault_size(self) -> int:
        return len(self._vault)

    def vault_snapshot(self) -> dict[str, EncryptedPan]:
        """Read-only view of the vault — for audit/testing only."""
        return dict(self._vault)
