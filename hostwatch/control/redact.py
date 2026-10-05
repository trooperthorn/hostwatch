"""Masking of secrets in the text a control action reports back to watchpost.

Masking runs on the whole text before it is clipped, so a secret that straddles the clip point can
never leave a readable half behind. It is a courtesy and not a guarantee: a secret in a shape this
module does not know passes through.
"""

from __future__ import annotations

import re

MAX_OUTPUT = 2000
MASK = "[redacted]"

_VALUE = r"""(?:"[^"\r\n]*"|'[^'\r\n]*'|\S+)"""
_B64 = r"[A-Za-z0-9+/_-]"

# Order matters: whole blocks and header lines first, then single tokens.
_PATTERNS = (
    # A PEM block, or an unterminated one (clipped output) through to the end of the text.
    re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?(?:-----END [A-Z0-9 ]+-----|\Z)", re.S),
    # An Authorization header or setting, the whole line, whatever the scheme.
    re.compile(r"(?i:authorization)[\"']?[ \t]*[=:][^\r\n]*"),
    re.compile(r"(?i:bearer)[ \t]+\S+"),
    # Hostwatch and watchpost key shapes.
    re.compile(r"\b(?:wpc|wpi|wpf|hw)_[A-Za-z0-9_-]{8,}"),
    # password=..., token: "...", api_key=... and the like, with a quoted or bare value.
    re.compile(r"(?i:(?:password|passwd|secret|token|api[_-]?key))[\"']?[ \t]*[=:][ \t]*" + _VALUE),
    # A long hex run (digests, raw keys).
    re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])"),
    # A long base64 or base64url run with a digit and mixed case, so ordinary long paths and words pass.
    re.compile(rf"(?<!{_B64})(?=\S*\d)(?=\S*[A-Z])(?=\S*[a-z]){_B64}{{40,}}={{0,2}}"),
)


def mask_secrets(text: str) -> str:
    for pattern in _PATTERNS:
        text = pattern.sub(MASK, text)
    return text


def clip(text: str) -> str:
    text = text.strip()
    return text if len(text) <= MAX_OUTPUT else text[:MAX_OUTPUT] + "...[truncated]"


def redact(text: str) -> str:
    """Mask first, then clip."""
    return clip(mask_secrets(text))
