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


def gvisor_cfg(**model):
    cfg = cfg_with()
    cfg.runtime.runsc = Path("/usr/local/bin/runsc")
    for key, value in model.items():
        setattr(cfg.model, key, value)
    return cfg


class GvisorCommandTests(unittest.TestCase):
    def test_runtime_listens_in_the_mounted_directory(self):
        with mock.patch.object(runtime, "physical_cores", return_value=None):
            cmd = runtime.server_command(gvisor_cfg())
        self.assertEqual(cmd[2:4], ["--host", "/run/silo/llama.sock"])
        self.assertNotIn("--threads", cmd)
        self.assertEqual(runtime.server_command(cfg_with())[2:4], ["--host", "@" + runtime.ABSTRACT_SOCKET])

    def test_threads_default_to_physical_cores_on_gvisor_only(self):
        with mock.patch.object(runtime, "physical_cores", return_value=6):
            cmd = runtime.server_command(gvisor_cfg())
            self.assertEqual(cmd[cmd.index("--threads") + 1], "6")
            cmd = runtime.server_command(gvisor_cfg(threads=2))  # an explicit setting wins
            self.assertEqual(cmd[cmd.index("--threads") + 1], "2")
            self.assertNotIn("--threads", runtime.server_command(cfg_with()))  # llama.cpp decides on the host kernel

    def test_physical_cores(self):
        with tempfile.TemporaryDirectory() as tmp:
            sysfs = Path(tmp)
            layout = {0: ("0", "0"), 1: ("0", "1"), 2: ("0", "0"), 3: ("0", "1"), 4: ("1", "0"), 5: ("1", "0")}
            for cpu, (package, core) in layout.items():
                topology = sysfs / f"cpu{cpu}" / "topology"
                topology.mkdir(parents=True)
                (topology / "physical_package_id").write_text(package + "\n")
                (topology / "core_id").write_text(core + "\n")
            with mock.patch.object(os, "sched_getaffinity", return_value={0, 1, 2, 3, 4, 5}):
                self.assertEqual(runtime.physical_cores(sysfs), 3)   # two hyperthreaded cores and one more package
            with mock.patch.object(os, "sched_getaffinity", return_value={0, 2}):
                self.assertEqual(runtime.physical_cores(sysfs), 1)   # only what this process may run on
            with mock.patch.object(os, "sched_getaffinity", return_value={0, 9}):
                self.assertIsNone(runtime.physical_cores(sysfs))     # topology not readable: do not guess

    def test_scope_carries_the_limits(self):
        cfg = gvisor_cfg()
        cfg.runtime.memory, cfg.runtime.pids_limit, cfg.runtime.cpus = "3g", 100, 1.5
        with mock.patch.object(runtime.shutil, "which", return_value="/usr/bin/systemd-run"):
            args = runtime.scoped(cfg, ["podman", "run"])
            self.assertEqual(args[:3], ["systemd-run", "--user", "--scope"])
            self.assertEqual(args[-2:], ["podman", "run"])
            for prop in (f"MemoryMax={3 << 30}", "MemorySwapMax=0", "TasksMax=712", "CPUQuota=150%"):
                self.assertIn(prop, args)
            self.assertIn(f"MemoryMax={512 << 20}", runtime.scoped(cfg, ["podman"], memory="512m"))
        self.assertEqual(runtime.scoped(cfg_with(), ["podman", "run"]), ["podman", "run"])  # host kernel: no scope

    def test_no_scope_means_no_launch(self):
        with mock.patch.object(runtime.shutil, "which", return_value=None), self.assertRaises(runtime.LaunchError):
            runtime.scoped(gvisor_cfg(), ["podman", "run"])


class GvisorSocketDirTests(unittest.TestCase):
    """On gVisor one directory is shared for the runtime's socket; it is locked once the socket exists."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.cfg = gvisor_cfg()
        runtime.prepare_run_dir(self.cfg)
        self.cfg.gvisor_socket_dir.mkdir(mode=0o700)
        os.chmod(self.cfg.gvisor_socket_dir, 0o777)

    def bind(self, name="llama.sock"):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.cfg.gvisor_socket_dir / name))
        self.addCleanup(listener.close)

    def lock(self):
        lock = runtime.GvisorSocketLock(self.cfg, time.monotonic() + 5)
        lock.start()
        return lock

    def test_locks_as_soon_as_the_socket_appears(self):
        lock = self.lock()
        time.sleep(0.05)
        self.assertFalse(lock.locked.is_set())
        self.assertFalse(runtime.runtime_reachable(self.cfg))  # an open directory is not a usable one
        self.bind()
        self.assertTrue(lock.locked.wait(2))
        self.assertIsNone(lock.error)
        self.assertEqual(oct(os.stat(self.cfg.gvisor_socket_dir).st_mode & 0o777), "0o755")
        self.assertTrue(runtime.runtime_reachable(self.cfg))

    def test_anything_but_the_socket_fails_the_launch(self):
        for plant in ("file", "symlink", "extra"):
            with self.subTest(plant=plant):
                directory = self.cfg.gvisor_socket_dir
                os.chmod(directory, 0o777)
                for entry in directory.iterdir():
                    entry.unlink()
                lock = self.lock()
                if plant == "file":
                    (directory / "llama.sock").write_text("not a socket")
                elif plant == "symlink":
                    os.symlink("/run/user/1000/bus", directory / "llama.sock")
                else:
                    (directory / "dropped").write_text("x")
                self.assertTrue(lock.locked.wait(2))
                self.assertIsInstance(lock.error, runtime.LaunchError)
                self.assertIn("unexpected content", str(lock.error))
                self.assertFalse(runtime.runtime_reachable(self.cfg))

    def test_gives_up_at_the_deadline(self):
        lock = runtime.GvisorSocketLock(self.cfg, time.monotonic() + 0.05)
        lock.start()
        lock.join(2)
        self.assertFalse(lock.is_alive())
        self.assertFalse(lock.locked.is_set())

    def test_health_goes_through_the_locked_socket_only(self):
        self.assertIsNone(runtime.health(self.cfg))            # nothing bound
        self.bind()
        self.assertIsNone(runtime.health(self.cfg, timeout=1))  # bound, but the directory is still open


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
        self.assertFalse(runtime.runtime_reachable(self.cfg))
        self.cfg.connector_pidfile.write_text(f"{os.getpid()}\n")
        self.assertEqual(runtime.connector_pid(self.cfg), os.getpid())
        self.assertFalse(runtime.runtime_reachable(self.cfg))  # no control socket yet
        for junk in ("", "abc", "1", "-5"):
            self.cfg.connector_pidfile.write_text(junk)
            self.assertIsNone(runtime.connector_pid(self.cfg))

    def test_connector_script_is_packaged_and_standalone(self):
        script = runtime.connector_script()
        compile(script, "connector.py", "exec")
        self.assertFalse(any(line.startswith(("from silo", "import silo")) for line in script.splitlines()))  # runs from source under `podman unshare`, outside the package


class EarlyExitTests(unittest.TestCase):
    def test_a_runtime_that_died_is_reported_with_its_reason(self):
        cfg = Config(name="t")
        with mock.patch.object(runtime, "container_running", return_value=False), \
                mock.patch.object(runtime, "_exit_hint", return_value="exit code 1"), \
                mock.patch.object(runtime, "_tail_logs", return_value="error: invalid argument: --x"):
            with self.assertRaises(runtime.LaunchError) as cm:
                runtime._raise_if_exited(cfg)
        self.assertIn("exited during startup (exit code 1)", str(cm.exception))
        self.assertIn("invalid argument: --x", str(cm.exception))
        with mock.patch.object(runtime, "container_running", return_value=True):
            runtime._raise_if_exited(cfg)  # still running: nothing to report


if __name__ == "__main__":
    unittest.main()
