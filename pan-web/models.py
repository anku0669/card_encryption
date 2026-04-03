"""
models.py
─────────
Data classes for the token vault.

EncryptedPan  — stored in the vault; NEVER contains raw PAN.
DecryptedCard — ephemeral; use as a context manager to ensure PAN is wiped.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class EncryptedPan:
    """
    Vault record.  All fields are safe to persist / log except cipher_text
    (which is opaque without the key, but should still be treated as sensitive).
    The raw PAN is NEVER present.
    """
    token:       str   # surrogate identifier (UUID v4)
    cipher_text: str   # Base64-encoded AES-GCM ciphertext
    iv:          str   # Base64-encoded 96-bit IV
    auth_tag:    str   # Base64-encoded 128-bit GCM tag
    masked_pan:  str   # e.g. ************1111
    card_scheme: str   # VISA / MASTERCARD / AMEX / DISCOVER / …

    def __repr__(self) -> str:
        return (
            f"EncryptedPan(token={self.token!r}, "
            f"masked_pan={self.masked_pan!r}, "
            f"card_scheme={self.card_scheme!r})"
        )


class DecryptedCard:
    """
    Ephemeral, mutable holder for a decrypted card.

    NEVER serialise, log, or persist this object.
    Always use it as a context manager so the PAN is wiped on exit:

        with service.detokenize(token) as card:
            process(card.pan)
        # PAN is now gone
    """

    def __init__(self, pan: str, masked_pan: str,
                 card_scheme: str, token: str) -> None:
        self._pan        = bytearray(pan.encode())   # mutable bytes for zeroing
        self.masked_pan  = masked_pan
        self.card_scheme = card_scheme
        self.token       = token

    # ── Context-manager support ────────────────────────────────────────────────

    def __enter__(self) -> "DecryptedCard":
        return self

    def __exit__(self, *_) -> None:
        self._wipe()

    # ── PAN access ─────────────────────────────────────────────────────────────

    @property
    def pan(self) -> str:
        """Return the PAN as a string.  Minimise its lifetime; avoid printing."""
        if not self._pan:
            return ""
        return self._pan.decode()

    def _wipe(self) -> None:
        """Zero out the PAN bytes."""
        for i in range(len(self._pan)):
            self._pan[i] = 0
        self._pan.clear()

    # ── Safety ─────────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        # Intentionally masks PAN to prevent log leaks.
        return (
            f"DecryptedCard(token={self.token!r}, "
            f"masked_pan={self.masked_pan!r}, "
            f"card_scheme={self.card_scheme!r})"
        )

    def __str__(self) -> str:
        return repr(self)
