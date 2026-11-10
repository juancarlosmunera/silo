"""Model intake: format allowlist + SHA-256 manifest.

Model files are an attack vector before a single token is generated:
  * pickle-based checkpoints (.bin/.pt/.pth/.ckpt/...) execute arbitrary code on load;
  * Hugging Face repos with custom *.py run that code under trust_remote_code=True;
  * crafted GGUF/safetensors headers target parser bugs in the runtime.

Intake accepts an allowlist of data-only formats, checks magic bytes (extensions lie), rejects
symlinks and executables, and records size/mtime/sha256 per file. The manifest lives in silo's
state directory, outside the model directory, so whatever can tamper with weights cannot also
rewrite the record of what the weights should be.

Scope: this is a format gate plus an integrity record, not a deep validator. A well-formed GGUF can
still carry a malicious chat template or trigger a parser bug in the runtime; that is what the
sandbox is for.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

WEIGHT_FORMATS = {".gguf", ".safetensors"}
AUX_FORMATS = {".json", ".txt", ".md", ".model", ".tiktoken", ".jinja", ".vocab", ".tokenizer"}
PICKLE_EXT = {".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".joblib", ".npy", ".npz", ".h5", ".keras"}
CODE_EXT = {".py", ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".sh", ".bash", ".js", ".ipynb", ".bat",
            ".ps1"}

MAX_SAFETENSORS_HEADER = 100 << 20


@dataclass
class Verdict:
    path: str
    ok: bool
    kind: str
    reason: str


def _magic_problem(head: bytes) -> str | None:
    if head[:4] == b"\x7fELF":
        return "ELF executable"
    if head[:2] == b"#!":
        return "script with shebang"
    if head[:4] == b"PK\x03\x04":
        return "zip archive (PyTorch checkpoints are zipped pickles)"
    if len(head) >= 2 and head[0] == 0x80 and head[1] in (2, 3, 4, 5):
        return "raw pickle stream"
    if head[:6] == b"\x93NUMPY":
        return "numpy array (may embed pickles)"
    return None


def classify(root: Path, path: Path) -> Verdict:
    rel = str(path.relative_to(root))
    if path.is_symlink():
        return Verdict(rel, False, "symlink", "symlinks are not allowed in a model directory")
    if not path.is_file():
        return Verdict(rel, False, "special", "not a regular file")
    ext = path.suffix.lower()
    if ext in CODE_EXT:
        return Verdict(rel, False, "code", "executable code (would run under trust_remote_code or a loader)")
    if ext in PICKLE_EXT:
        return Verdict(rel, False, "pickle", "pickle-capable format: arbitrary code execution on load")
    with path.open("rb") as fh:
        head = fh.read(16)
        problem = _magic_problem(head)
        if problem:
            return Verdict(rel, False, "magic", f"content is a {problem}")
        if ext == ".gguf":
            if head[:4] != b"GGUF":
                return Verdict(rel, False, "gguf", "missing GGUF magic")
            version = struct.unpack("<I", head[4:8])[0]
            if version not in (2, 3):
                return Verdict(rel, False, "gguf", f"unsupported GGUF version {version}")
            return Verdict(rel, True, "gguf", f"GGUF v{version}")
        if ext == ".safetensors":
            if len(head) < 9:
                return Verdict(rel, False, "safetensors", "truncated header")
            size = path.stat().st_size
            hlen = struct.unpack("<Q", head[:8])[0]
            if hlen > MAX_SAFETENSORS_HEADER or 8 + hlen > size:
                return Verdict(rel, False, "safetensors", f"implausible header length {hlen}")
            fh.seek(8)
            try:
                header = json.loads(fh.read(hlen))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return Verdict(rel, False, "safetensors", "header is not valid JSON")
            if not isinstance(header, dict):
                return Verdict(rel, False, "safetensors", "header is not a JSON object")
            return Verdict(rel, True, "safetensors", f"{len(header) - ('__metadata__' in header)} tensors")
    if ext in AUX_FORMATS or path.name in ("LICENSE", "README", "NOTICE"):
        if ext == ".json":
            try:
                json.loads(path.read_bytes())
            except (UnicodeDecodeError, json.JSONDecodeError):
                return Verdict(rel, False, "json", "invalid JSON")
        return Verdict(rel, True, "aux", "data file")
    return Verdict(rel, False, "unknown", f"extension {ext or '(none)'} is not on the allowlist")


def walk(root: Path):
    """Yield every entry below root that is not a plain directory: files, symlinks, specials.

    Nothing is skipped. Hidden directories (.git, .cache) are mounted into the sandbox like
    everything else, so they are vetted like everything else.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        dirnames.sort()
        for d in list(dirnames):
            if (base / d).is_symlink():
                yield base / d
                dirnames.remove(d)
        for name in sorted(filenames):
            yield base / name


def sha256_file(path: Path, progress: bool = False) -> str:
    h = hashlib.sha256()
    size = path.stat().st_size
    done, last = 0, 0.0
    with path.open("rb") as fh:
        while chunk := fh.read(8 << 20):
            h.update(chunk)
            done += len(chunk)
            if progress and size > (1 << 30) and time.monotonic() - last > 1:
                last = time.monotonic()
                print(f"\r  hashing {path.name}: {done * 100 // size}%", end="", file=sys.stderr, flush=True)
    if progress and size > (1 << 30):
        print(f"\r  hashing {path.name}: 100%", file=sys.stderr)
    return h.hexdigest()


def scan(root: Path, allow_unknown: bool = False) -> list[Verdict]:
    verdicts = [classify(root, p) for p in walk(root)]
    if allow_unknown:
        for v in verdicts:
            if v.kind == "unknown":
                v.ok, v.reason = True, v.reason + " (allowed by --allow-unknown)"
    return verdicts


def build_manifest(root: Path, verdicts: list[Verdict], progress: bool = True) -> dict:
    files = {}
    for v in verdicts:
        path = root / v.path
        st = path.stat()
        files[v.path] = {
            "kind": v.kind,
            "size": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "sha256": sha256_file(path, progress=progress),
        }
    return {"version": 1, "root": str(root), "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "files": files}


def write_manifest(manifest: dict, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = out.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    tmp.replace(out)


def verify(root: Path, manifest_path: Path, full: bool = False) -> list[str]:
    """Return a list of problems; empty means the directory matches the manifest."""
    if not manifest_path.is_file():
        return [f"no manifest at {manifest_path}; run `silo intake` first"]
    manifest = json.loads(manifest_path.read_text())
    problems = []
    if manifest.get("root") != str(root):
        problems.append(f"manifest is for {manifest.get('root')}, not {root}")
    expected = manifest.get("files", {})
    present = {str(p.relative_to(root)): p for p in walk(root)}
    for rel in sorted(set(present) - set(expected)):
        problems.append(f"unmanifested file: {rel}")
    for rel in sorted(set(expected) - set(present)):
        problems.append(f"missing file: {rel}")
    for rel in sorted(set(expected) & set(present)):
        path, want = present[rel], expected[rel]
        if path.is_symlink() or not path.is_file():
            problems.append(f"{rel}: no longer a regular file")
            continue
        st = path.stat()
        if st.st_size != want["size"]:
            problems.append(f"{rel}: size changed ({want['size']} -> {st.st_size})")
            continue
        if full or st.st_mtime_ns != want["mtime_ns"]:
            if sha256_file(path, progress=True) != want["sha256"]:
                problems.append(f"{rel}: SHA-256 mismatch")
    return problems
