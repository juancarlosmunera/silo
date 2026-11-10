"""Output tripwire.

Once kernel and network boundaries hold, the remaining channel out of the silo is the text itself.
A model with no network can still try to borrow somebody else's:

  * the operator's hands   - "run this command", pipe-to-shell, reverse shells, persistence;
  * the client's renderer  - a markdown image or HTML tag makes the chat UI fetch an attacker URL,
                             with data in the query string, without anyone clicking anything;
  * the operator's terminal - raw escape sequences (retitle, rewrite lines, OSC 52 clipboard writes);
  * a later reader          - instructions hidden in invisible Unicode (tag characters, bidi overrides).

These rules flag the common shapes of that. They are a tripwire, not a boundary: a capable model
can obfuscate past any regex. Their job is to make attempts visible in the audit log and, in enforce
mode, to stop the obvious ones. HIGH findings are blocked in enforce mode; MEDIUM are only recorded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

HIGH, MEDIUM = "high", "medium"


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    pattern: re.Pattern
    description: str


def _r(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule("pipe-to-shell", HIGH,
         _r(r"\b(curl|wget|fetch)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da|k|fi)?sh\b"),
         "download piped straight into a shell"),
    Rule("download-exec-powershell", HIGH,
         _r(r"(downloadstring|invoke-webrequest|\biwr\b|net\.webclient)[^\n]{0,200}(\|\s*)?\b(iex|invoke-expression)\b"),
         "PowerShell download-and-execute"),
    Rule("reverse-shell", HIGH,
         _r(r"/dev/(tcp|udp)/|\bnc(at)?\b[^\n]{0,80}\s-[a-z]*e\s|\bbash\s+-i\b[^\n]{0,40}>&|"
            r"\bsocat\b[^\n]{0,120}\bexec:|\bmkfifo\b[^\n]{0,120}\bnc\b"),
         "reverse-shell construction"),
    Rule("encoded-exec", HIGH,
         _r(r"base64\s+(-d|--decode)[^\n]{0,60}\|\s*(ba|z)?sh\b|"
            r"powershell(\.exe)?\s[^\n]{0,40}-e(nc(odedcommand)?)?\s+[a-z0-9+/=]{20,}"),
         "encoded payload executed"),
    Rule("sandbox-tamper", HIGH,
         _r(r"--privileged\b|seccomp[=:]\s*unconfined|label[=:]\s*disable|\bnsenter\b|"
            r"--(network|net|pid|ipc|userns)[= ]host\b|docker\.sock|podman\.sock|setenforce\s+0|"
            r"\bnft\s+flush\s+ruleset|\biptables\s+-F\b|kernel\.yama\.ptrace_scope\s*=\s*0"),
         "weakens container, LSM or firewall isolation"),
    Rule("remote-image", HIGH,
         _r(r"!\[[^\]\n]{0,300}\]\(\s*<?\s*(https?:)?//[^)\s]+|"
            r"<img\b[^>]{0,300}\bsrc\s*=\s*[\"']?\s*(https?:)?//"),
         "remote image: fetched automatically by markdown/HTML renderers (zero-click exfiltration)"),
    Rule("terminal-escape", HIGH,
         _r(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]"),
         "raw control character or terminal escape sequence"),
    Rule("active-content", MEDIUM,
         _r(r"<(script|iframe|object|embed)\b|<link\b[^>]{0,200}\bhref\s*=|"
            r"<meta\b[^>]{0,200}http-equiv\s*=\s*[\"']?refresh|\bjavascript:|\bdata:text/html"),
         "HTML that executes or fetches when rendered"),
    Rule("hidden-unicode", MEDIUM,
         _r("[\U000e0000-\U000e007f‪-‮⁦-⁩]"),
         "invisible Unicode (tag characters / bidi controls) used to smuggle text"),
    Rule("exfil-endpoint", MEDIUM,
         _r(r"https?://\d{1,3}(\.\d{1,3}){3}\b|webhook\.site|requestbin|pipedream\.net|\bngrok(-free)?\.(io|app)|"
            r"interact\.sh|\boast\.(pro|live|site|online|fun|me)\b|burpcollaborator|transfer\.sh|"
            r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot"),
         "known data-exfiltration or callback endpoint"),
    Rule("persistence", MEDIUM,
         _r(r"authorized_keys|\bcrontab\s+-|/etc/cron\.|>>\s*~?/?[\w/.]*\.(bashrc|zshrc|profile)\b|"
            r"systemctl\s+(--user\s+)?enable\b|\.config/autostart"),
         "installs persistence"),
    Rule("credential-access", MEDIUM,
         _r(r"\.ssh/id_[a-z0-9]+|\.aws/credentials|\.netrc\b|\.git-credentials|\.docker/config\.json|"
            r"\.config/gh/hosts\.yml|\.cache/huggingface/token|"
            r"\b(GITHUB|GH|OPENAI|ANTHROPIC|HF|AWS_SECRET)_[A-Z_]*(TOKEN|KEY)\b"),
         "reads credentials or tokens"),
)


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    match: str

    def as_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "match": self.match}


def scan(text: str) -> list[Finding]:
    out, seen = [], set()
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            key = (rule.id, m.group(0))
            if key not in seen:
                seen.add(key)
                out.append(Finding(rule.id, rule.severity, m.group(0)[:200]))
    return out


def blocking(findings: list[Finding]) -> bool:
    return any(f.severity == HIGH for f in findings)


class StreamScanner:
    """Incremental scanning of streamed deltas; patterns may straddle token boundaries."""

    WINDOW = 4096

    def __init__(self) -> None:
        self._tail = ""
        self._seen: set[tuple[str, str]] = set()
        self.findings: list[Finding] = []

    def feed(self, delta: str) -> list[Finding]:
        if not delta:
            return []
        self._tail = (self._tail + delta)[-self.WINDOW:]
        new = []
        for f in scan(self._tail):
            key = (f.rule, f.match)
            if key not in self._seen:
                self._seen.add(key)
                new.append(f)
        self.findings.extend(new)
        return new


def extract_text(payload: dict) -> str:
    """Pull every model-authored string out of an OpenAI-style response or stream chunk."""
    parts: list[str] = []
    for choice in payload.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        if isinstance(choice.get("text"), str):
            parts.append(choice["text"])
        for key in ("message", "delta"):
            msg = choice.get(key)
            if not isinstance(msg, dict):
                continue
            for field in ("content", "reasoning_content", "reasoning", "refusal"):
                value = msg.get(field)
                if isinstance(value, str):
                    parts.append(value)
                elif isinstance(value, list):
                    parts.extend(str(p.get("text") or "") for p in value if isinstance(p, dict))
            for call in msg.get("tool_calls") or []:
                fn = call.get("function") if isinstance(call, dict) else None
                if isinstance(fn, dict):
                    parts.append(str(fn.get("name") or ""))
                    parts.append(str(fn.get("arguments") or ""))
            legacy = msg.get("function_call")
            if isinstance(legacy, dict):
                parts.append(str(legacy.get("name") or ""))
                parts.append(str(legacy.get("arguments") or ""))
    return "".join(parts)


def has_tool_calls(payload: dict) -> bool:
    for choice in payload.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        for key in ("message", "delta"):
            msg = choice.get(key)
            if isinstance(msg, dict) and (msg.get("tool_calls") or msg.get("function_call")):
                return True
    return False


def tool_call_names(payload: dict) -> list[str]:
    names = []
    for choice in payload.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        for key in ("message", "delta"):
            msg = choice.get(key)
            if not isinstance(msg, dict):
                continue
            for call in msg.get("tool_calls") or []:
                fn = call.get("function") if isinstance(call, dict) else None
                if isinstance(fn, dict) and fn.get("name"):
                    names.append(str(fn["name"]))
            legacy = msg.get("function_call")
            if isinstance(legacy, dict) and legacy.get("name"):
                names.append(str(legacy["name"]))
    return names
