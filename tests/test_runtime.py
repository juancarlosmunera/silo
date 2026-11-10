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
                                   "--host", runtime.SOCKET_IN_CONTAINER])
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

    def test_model_required(self):
        with self.assertRaises(ConfigError):
            runtime.server_command(Config())

    def test_probe_script_is_packaged(self):
        script = runtime.probe_script()
        self.assertIn("def main()", script)
        compile(script, "escape_probes.py", "exec")


class SocketDirTests(unittest.TestCase):
    """The one host directory shared with the sandbox."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Config(name="t")
        self.listener = None

    def bind(self):
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.cfg.socket_path))
        self.addCleanup(self.listener.close)

    def mode(self, path):
        return oct(os.stat(path).st_mode & 0o777)

    def test_prepare_then_lock(self):
        d = runtime.prepare_socket_dir(self.cfg)
        self.assertEqual(d, Path(self.tmp.name) / "silo" / "t")
        self.assertEqual(self.mode(d.parent), "0o700")  # no other host user gets near it
        self.assertEqual(self.mode(d), "0o777")         # the sandbox UID has to be able to bind
        self.assertFalse(runtime.socket_dir_locked(self.cfg))
        self.bind()
        runtime.lock_socket_dir(self.cfg)
        self.assertEqual(self.mode(d), "0o755")         # ...and nothing after that
        self.assertTrue(runtime.socket_dir_locked(self.cfg))

    def test_prepare_discards_whatever_was_there(self):
        d = runtime.prepare_socket_dir(self.cfg)
        (d / "leftover").write_text("x")
        (d / runtime.SOCKET_NAME).symlink_to("/run/user/0/bus")
        d = runtime.prepare_socket_dir(self.cfg)
        self.assertEqual(os.listdir(d), [])

    def test_lock_refuses_a_symlink_at_the_socket_path(self):
        d = runtime.prepare_socket_dir(self.cfg)
        other = Path(self.tmp.name) / "other.sock"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(other))
        self.addCleanup(s.close)
        (d / runtime.SOCKET_NAME).symlink_to(other)  # points at a real socket: only lstat tells them apart
        with self.assertRaises(runtime.LaunchError):
            runtime.lock_socket_dir(self.cfg)
        self.assertFalse(runtime.socket_dir_locked(self.cfg))

    def test_lock_refuses_extra_entries(self):
        d = runtime.prepare_socket_dir(self.cfg)
        self.bind()
        (d / "extra").write_text("x")
        with self.assertRaises(runtime.LaunchError):
            runtime.lock_socket_dir(self.cfg)

    def watch(self):
        watcher = runtime.SocketDirWatcher(self.cfg, time.monotonic() + 5)
        watcher.start()
        self.addCleanup(watcher.cancel)
        return watcher

    def test_watcher_locks_as_soon_as_the_socket_appears(self):
        d = runtime.prepare_socket_dir(self.cfg)
        watcher = self.watch()
        time.sleep(0.05)
        self.assertFalse(watcher.locked.is_set())  # nothing there yet, nothing locked
        self.assertEqual(self.mode(d), "0o777")
        self.bind()
        self.assertTrue(watcher.locked.wait(2))
        self.assertIsNone(watcher.error)
        self.assertEqual(self.mode(d), "0o755")
        bound, locked = os.lstat(self.cfg.socket_path).st_ctime_ns, os.lstat(d).st_ctime_ns
        self.assertLess((locked - bound) / 1e6, 250)  # generous for a loaded CI box; ~1 ms in practice

    def test_watcher_fails_the_launch_if_anything_else_shows_up(self):
        for plant in ("file", "symlink"):
            with self.subTest(plant=plant):
                d = runtime.prepare_socket_dir(self.cfg)
                watcher = self.watch()
                if plant == "file":
                    (d / "dropped").write_text("x")
                else:
                    (d / runtime.SOCKET_NAME).symlink_to("/run/user/0/bus")
                self.assertTrue(watcher.locked.wait(2))
                self.assertIsInstance(watcher.error, runtime.LaunchError)
                self.assertEqual(self.mode(d), "0o755")  # locked regardless, so nothing more can be added

    def test_watcher_can_be_cancelled(self):
        runtime.prepare_socket_dir(self.cfg)
        watcher = self.watch()
        watcher.cancel()
        watcher.join(2)
        self.assertFalse(watcher.is_alive())
        self.assertFalse(watcher.locked.is_set())

    def test_remove_dir_only_touches_silo_runtime_dirs(self):
        victim = Path(self.tmp.name) / "victim"
        victim.mkdir()
        (victim / "keep").write_text("x")
        for path in (victim, Path(self.tmp.name), Path(self.tmp.name) / "silo" / "a" / "b"):
            with self.subTest(path=path), self.assertRaises(runtime.LaunchError):
                runtime._remove_dir(path)
        self.assertTrue((victim / "keep").exists())

    def test_health_of_a_missing_or_fake_socket_is_none(self):
        runtime.prepare_socket_dir(self.cfg)
        self.assertIsNone(runtime.health(self.cfg.socket_path))
        self.cfg.socket_path.write_text("not a socket")
        self.assertIsNone(runtime.health(self.cfg.socket_path))


if __name__ == "__main__":
    unittest.main()
