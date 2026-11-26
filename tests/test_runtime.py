import os
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from silo import runtime
from silo.config import Config, ConfigError


def cfg_with(extra=()):
    cfg = Config(name="t")
    cfg.model.dir = Path("/models-src")
    cfg.model.file = "kimi/Kimi-K2-Q2_K-00001-of-00008.gguf"
    cfg.model.extra_args = list(extra)
    return cfg


class ServerCommandTests(unittest.TestCase):
    def test_server_command(self):
        cmd = runtime.server_command(cfg_with(["--n-gpu-layers", "0", "--jinja", "--temp", "-1"]))
        self.assertEqual(cmd[:4], ["--model", "/models/kimi/Kimi-K2-Q2_K-00001-of-00008.gguf",
                                   "--host", "@" + runtime.ABSTRACT_SOCKET])
        for switch in runtime.SAFETY_SWITCHES:
            self.assertIn(switch, cmd)
        self.assertEqual(cmd[-5:], ["--n-gpu-layers", "0", "--jinja", "--temp", "-1"])

    def test_tuning_flags_are_accepted(self):
        for flag in ("--n-gpu-layers", "-ngl", "--batch-size", "--parallel", "--mlock", "--no-mmap", "--flash-attn",
                     "--chat-template", "--reasoning-format", "--mmproj", "--lora", "--cache-reuse", "--numa",
                     "--top-k", "--seed", "--threads-batch", "--device", "--main-gpu", "--tensor-split"):
            with self.subTest(flag=flag):
                runtime.check_extra_args([flag, "1"])

    def test_dangerous_server_flags_rejected(self):
        for flag in ("--tools=all", "--agent", "-ag", "--rpc", "-hf", "--hf-repo", "--model-url", "-mu", "--host",
                     "--port", "--reuse-port", "--webui-mcp-proxy", "--ui-mcp-proxy", "--mcp-servers-config",
                     "--props", "--slot-save-path", "-m", "--model", "--gpt-oss-20b-default", "--tools-runtime",
                     "--media-path", "--path", "--webui", "--ui", "--slots", "--metrics", "--api-key",
                     "--api-prefix", "--ssl-key-file", "--docker-repo", "-dr", "--mmproj-url", "--models-dir",
                     "--models-preset", "--log-prompts-dir", "--spec-draft-hf", "--hf-token",
                     # families, not just today's spellings: a future flag is refused without a silo release
                     "--web-search-url", "--tool-sandbox", "--remote-agent", "--mcp-anything", "--https-proxy"):
            with self.subTest(flag=flag), self.assertRaises(ConfigError):
                runtime.server_command(cfg_with([flag, "x"]))

    def test_only_exact_content_counts_as_pinned(self):
        digest = "a" * 64
        for ref in (f"ghcr.io/ggml-org/llama.cpp@sha256:{digest}", f"sha256:{digest}", digest):
            self.assertTrue(runtime.is_pinned(ref), ref)
        for ref in ("ghcr.io/ggml-org/llama.cpp:server", "python:3.13-slim", digest[:12], f"sha256:{digest[:12]}",
                    "localhost/llama:sha256", digest.upper()):
            self.assertFalse(runtime.is_pinned(ref), ref)

    def test_model_required(self):
        with self.assertRaises(ConfigError):
            runtime.server_command(Config())

    def test_probe_script_is_packaged(self):
        script = runtime.probe_script()
        self.assertIn("def main()", script)
        compile(script, "escape_probes.py", "exec")


class RunDirTests(unittest.TestCase):
    """The host-side directory for the connector's control socket, never shared with a sandbox."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Config(name="t")

    def mode(self, path):
        return oct(os.stat(path).st_mode & 0o777)

    def test_prepare(self):
        d = runtime.prepare_run_dir(self.cfg)
        self.assertEqual(d, Path(self.tmp.name) / "silo" / "t")
        self.assertEqual(self.mode(d.parent), "0o700")  # no other host user gets near it
        self.assertEqual(self.mode(d), "0o700")
        self.assertEqual(self.cfg.control_path.parent, d)

    def test_prepare_discards_whatever_was_there(self):
        d = runtime.prepare_run_dir(self.cfg)
        (d / "stale").write_text("x")
        os.symlink("/etc/passwd", d / "control.sock")
        d = runtime.prepare_run_dir(self.cfg)
        self.assertEqual(os.listdir(d), [])

    def test_remove_dir_only_touches_silo_runtime_dirs(self):
        victim = Path(self.tmp.name) / "victim"
        victim.mkdir()
        (victim / "keep").write_text("x")
        for path in (victim, Path(self.tmp.name), Path(self.tmp.name) / "silo" / "a" / "b"):
            with self.subTest(path=path), self.assertRaises(runtime.LaunchError):
                runtime._remove_dir(path)
        self.assertTrue((victim / "keep").exists())

    def test_health_of_a_missing_or_fake_control_socket_is_none(self):
        runtime.prepare_run_dir(self.cfg)
        self.assertIsNone(runtime.health(self.cfg))
        self.cfg.control_path.write_text("not a socket")
        self.assertIsNone(runtime.health(self.cfg))

    def test_connector_state(self):
        runtime.prepare_run_dir(self.cfg)
        self.assertIsNone(runtime.connector_pid(self.cfg))
        self.assertFalse(runtime.connector_serving(self.cfg))
        self.cfg.connector_pidfile.write_text(f"{os.getpid()}\n")
        self.assertEqual(runtime.connector_pid(self.cfg), os.getpid())
        self.assertFalse(runtime.connector_serving(self.cfg))  # no control socket yet
        for junk in ("", "abc", "1", "-5"):
            self.cfg.connector_pidfile.write_text(junk)
            self.assertIsNone(runtime.connector_pid(self.cfg))

    def test_connector_script_is_packaged_and_standalone(self):
        script = runtime.connector_script()
        compile(script, "connector.py", "exec")
        self.assertFalse(any(line.startswith(("from silo", "import silo")) for line in script.splitlines()))  # runs from source under `podman unshare`, outside the package


if __name__ == "__main__":
    unittest.main()
