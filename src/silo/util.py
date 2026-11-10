"""Small helpers shared across silo."""

from __future__ import annotations

import re

# C0/C1 controls (except tab and newline), DEL, line/paragraph separators and bidi controls.
_UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")


def _escape(match: re.Match) -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def safe_text(text: str) -> str:
    """Neutralise text that originates from a sandbox, a model file or a model directory.

    File names, GGUF metadata and runtime logs are attacker-controlled. Printed raw they can carry
    terminal escape sequences (retitle the window, rewrite earlier lines, write the clipboard via
    OSC 52), so everything untrusted goes through here before it reaches the operator's terminal.
    """
    return _UNSAFE.sub(_escape, text)
