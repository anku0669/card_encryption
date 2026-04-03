"""
pan_masker.py
─────────────
PAN masking, Luhn validation, and card-scheme detection.

PCI-DSS 4.0 §3.3.1 — only the last four digits may be displayed.
Raw PAN is never stored; only the masked string and scheme label are kept.
"""

import re


MASK_CHAR = "*"


def mask(pan: str) -> str:
    """
    Mask all digits except the last four.

    Example: "4111111111111111" → "************1111"
    """
    _validate(pan)
    visible = 4
    return MASK_CHAR * (len(pan) - visible) + pan[-visible:]


def detect_scheme(pan: str) -> str:
    """Detect the card network from the IIN without storing the PAN."""
    _validate(pan)
    if pan.startswith("4"):
        return "VISA"
    if re.match(r"^5[1-5]", pan) or re.match(r"^2[2-7]", pan):
        return "MASTERCARD"
    if re.match(r"^3[47]", pan):
        return "AMEX"
    if pan.startswith("6011") or pan.startswith("65") or re.match(r"^64[4-9]", pan) or re.match(r"^622", pan):
        return "DISCOVER"
    if re.match(r"^3(?:0[0-5]|[68])", pan):
        return "DINERS"
    if pan.startswith("35"):
        return "JCB"
    return "UNKNOWN"


def luhn_check(number: str) -> bool:
    """Standard Luhn algorithm."""
    total, alternate = 0, False
    for ch in reversed(number):
        n = int(ch)
        if alternate:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alternate = not alternate
    return total % 10 == 0


def validate(pan: str) -> None:
    """
    Validate PAN format and Luhn checksum.

    Raises ValueError on any failure — call this before any crypto work.
    """
    if not pan:
        raise ValueError("PAN must not be None or empty")
    if not re.fullmatch(r"\d{12,19}", pan):
        raise ValueError(
            f"PAN must be 12-19 digits; got {len(pan)} chars"
        )
    if not luhn_check(pan):
        raise ValueError("PAN failed Luhn check")


# ── private ────────────────────────────────────────────────────────────────────

def _validate(pan: str) -> None:
    validate(pan)
