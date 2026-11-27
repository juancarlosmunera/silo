import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from silo import config


def write(text: str) -> Path:
    fd, path = tempfile.mkstemp(suffix=".toml")
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    return Path(path)


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = config.validate(config.Config())
        self.assertEqual(cfg.container_name, "silo-default")
        self.assertEqual(cfg.gateway.listen, "127.0.0.1")
        self.assertEqual(cfg.runtime.gpu, "none")

    def test_load(self):
        cfg = config.load(write('[silo]\nname = "kimi"\n[model]\ndir = "/srv/m"\nfile = "k.gguf"\n'
                                '[runtime]\nmemory = "64g"\n'))
        self.assertEqual(cfg.name, "kimi")
        self.assertEqual(cfg.model.dir, Path("/srv/m"))
        self.assertEqual(cfg.runtime.memory, "64g")

    def test_unknown_keys_rejected(self):
        for text in ('[runtime]\nnetwork = "host"\n', '[sandbox]\nx = 1\n', '[silo]\nname = "a"\nfoo = 1\n'):
            with self.subTest(text=text), self.assertRaises(config.ConfigError):
                config.load(write(text))

    def test_validation(self):
        bad = [
            '[silo]\nname = "../etc"\n',
            '[runtime]\ngpu = "tpu"\n',
            '[runtime]\nseccomp_action = "allow"\n',
            '[gateway]\nscanner = "loud"\n',
            '[gateway]\nlisten = "0.0.0.0"\n',
            '[model]\ndir = "/m"\nfile = "../../etc/passwd"\n',
            '[model]\ndir = "/m"\nfile = "/etc/passwd"\n',
            # wrong types never coerce
            '[gateway]\nport = "8088"\n',
            '[gateway]\nport = true\n',
            '[gateway]\nallow_tools = 1\n',
            '[gateway]\nallow_tools = "false"\n',
            # a tool list only means something with tool calling on, and holds API-valid names
            '[gateway]\ntools = ["read_file"]\n',
            '[gateway]\nallow_tools = true\ntools = "read_file"\n',
            '[gateway]\nallow_tools = true\ntools = ["read file"]\n',
            '[gateway]\nallow_tools = true\ntools = ["a", "a"]\n',
            '[gateway]\nallow_tools = true\ntools = [""]\n',
            '[gateway]\nmax_tool_arguments_bytes = 0\n',
            # origins exactly as browsers send them, never patterns
            '[gateway]\nallowed_origins = ["*"]\n',
            '[gateway]\nallowed_origins = ["null"]\n',
            '[gateway]\nallowed_origins = ["http://localhost:3000/"]\n',
            '[gateway]\nallowed_origins = ["https://chat.example:443"]\n',
            '[gateway]\nallowed_origins = ["https://Chat.example"]\n',
            '[gateway]\nallowed_origins = ["https://*.example.com"]\n',
            '[gateway]\nallowed_origins = ["file:///tmp"]\n',
            '[gateway]\nallowed_origins = "http://localhost:3000"\n',
            '[runtime]\npids_limit = 64.5\n',
            '[runtime]\nexec_lock = "yes"\n',
            '[runtime]\nexec_lock = 0\n',
            '[model]\nextra_args = "--jinja"\n',
            '[model]\nextra_args = ["--threads", 4]\n',
            '[gateway]\nport = 0\n',
            '[gateway]\napi_key_env = "KEY; rm -rf"\nlisten = "0.0.0.0"\n',
            'runtime = "x"\n',
            '[silo\nname = "broken toml"\n',
            # an image reference can never be mistaken for a podman option
            '[runtime]\nimage = "--privileged"\n',
            '[runtime]\nprobe_image = "-v=/:/host"\n',
            '[runtime]\nimage = "img --network=host"\n',
            # model directories that must never be bind-mounted and relabelled
            '[model]\ndir = "/"\nfile = "m.gguf"\n',
            '[model]\ndir = "~"\nfile = "m.gguf"\n',
            '[model]\ndir = "/home"\nfile = "m.gguf"\n',
            '[model]\ndir = "/etc"\nfile = "m.gguf"\n',
            '[model]\ndir = "/srv"\nfile = "m.gguf"\n',
            f'[model]\ndir = "{Path.home().resolve().parent}"\nfile = "m.gguf"\n',
            '[model]\ndir = "/srv/a:/srv/b"\nfile = "m.gguf"\n',
        ]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(config.ConfigError):
                config.load(write(text))

    def runsc(self, mode=0o755, dir_mode=0o755):
        """A stand-in runsc in a directory other users can traverse (as /usr/local/bin is)."""
        tmp = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = Path(tmp) / "runsc"
        path.write_text("#!/bin/sh\n")
        path.chmod(mode)
        os.chmod(tmp, dir_mode)
        return path

    def nested_runsc(self):
        """runsc in a sound directory, one level below a directory that anyone can write to (and is not sticky)."""
        open_dir = tempfile.mkdtemp(dir="/var/tmp")
        self.addCleanup(shutil.rmtree, open_dir, ignore_errors=True)
        inner = Path(open_dir) / "gvisor"
        inner.mkdir(mode=0o755)
        path = inner / "runsc"
        path.write_text("#!/bin/sh\n")
        path.chmod(0o755)
        os.chmod(open_dir, 0o777)
        return path

    def test_gvisor(self):
        path = self.runsc()
        cfg = config.load(write(f'[runtime]\nrunsc = "{path}"\n'))
        self.assertEqual((cfg.runtime.runsc, cfg.runtime.gvisor_platform), (path, "systrap"))
        self.assertEqual(cfg.gvisor_socket_path, cfg.socket_dir / "sock" / "llama.sock")
        cfg = config.load(write(f'[runtime]\nrunsc = "{path}"\ngvisor_platform = "kvm"\n'))
        self.assertEqual(cfg.runtime.gvisor_platform, "kvm")
        self.assertIsNone(config.Config().runtime.runsc)  # off unless asked for

    def test_gvisor_refused(self):
        good = self.runsc()
        bad = {
            "missing": '[runtime]\nrunsc = "/nonexistent/runsc"\n',
            "not executable": f'[runtime]\nrunsc = "{self.runsc(mode=0o644)}"\n',
            "replaceable by others": f'[runtime]\nrunsc = "{self.runsc(mode=0o777)}"\n',
            "in a directory others can write to": f'[runtime]\nrunsc = "{self.runsc(dir_mode=0o777)}"\n',
            "below a directory others can write to": f'[runtime]\nrunsc = "{self.nested_runsc()}"\n',
            "not reachable by the sandbox UID (file)": f'[runtime]\nrunsc = "{self.runsc(mode=0o750)}"\n',
            "not reachable by the sandbox UID (directory)": f'[runtime]\nrunsc = "{self.runsc(dir_mode=0o700)}"\n',
            "with a GPU": f'[runtime]\nrunsc = "{good}"\ngpu = "dri"\n',
            "unknown platform": f'[runtime]\nrunsc = "{good}"\ngvisor_platform = "ptrace"\n',
            "platform without runsc": '[runtime]\ngvisor_platform = "kvm"\n',
            "wrong type": '[runtime]\nrunsc = true\n',
        }
        for label, text in bad.items():
            with self.subTest(label), self.assertRaises(config.ConfigError):
                config.load(write(text))

    def test_runsc_owned_by_another_user_is_refused(self):
        # As seen by a different user, the stand-in runsc and its directory belong to somebody else:
        # the situation after a /var/tmp cleanup when another user re-creates the configured path.
        text = f'[runtime]\nrunsc = "{self.runsc()}"\n'
        with mock.patch("os.getuid", return_value=os.getuid() + 4242):
            with self.assertRaises(config.ConfigError) as cm:
                config.load(write(text))
        self.assertIn("belongs to UID", str(cm.exception))

    def test_runsc_through_a_symlink_is_checked_where_it_points(self):
        good = self.runsc()
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o777)  # anyone could replace the link: Podman must be given the target
            link = Path(tmp) / "runsc"
            link.symlink_to(good)
            cfg = config.load(write(f'[runtime]\nrunsc = "{link}"\n'))
            self.assertEqual(cfg.runtime.runsc, good.resolve())

    def test_private_home_install_is_explained(self):
        with tempfile.TemporaryDirectory() as private:  # 0700, like ~/.local
            path = Path(private) / "runsc"
            path.write_text("#!/bin/sh\n")
            path.chmod(0o755)
            with self.assertRaises(config.ConfigError) as cm:
                config.load(write(f'[runtime]\nrunsc = "{path}"\n'))
        self.assertIn("unprivileged UID", str(cm.exception))
        self.assertIn("/usr/local/bin", str(cm.exception))

    def test_memory_bytes(self):
        for text, expected in (("8g", 8 << 30), ("512m", 512 << 20), ("100k", 100 << 10), ("4096", 4096),
                               ("4096b", 4096), ("2G", 2 << 30)):
            self.assertEqual(config.memory_bytes(text), expected)
        with self.assertRaises(config.ConfigError):
            config.memory_bytes("lots")

    def test_safe_defaults(self):
        cfg = config.Config()
        self.assertFalse(cfg.gateway.allow_tools)
        self.assertFalse(cfg.gateway.log_content)
        self.assertEqual(cfg.gateway.scanner, "monitor")
        self.assertEqual(cfg.runtime.gpu, "none")
        self.assertTrue(cfg.runtime.exec_lock)
        self.assertFalse(config.load(write('[runtime]\nexec_lock = false\n')).runtime.exec_lock)

    def test_types_are_coerced_only_where_safe(self):
        cfg = config.load(write('[runtime]\ncpus = 4\nimage = "ghcr.io/x/y@sha256:' + "a" * 64 + '"\n'
                                '[gateway]\ntimeout = 30\nallow_tools = true\n'))
        self.assertEqual((cfg.runtime.cpus, cfg.gateway.timeout, cfg.gateway.allow_tools), (4.0, 30.0, True))

    def test_config_is_never_taken_from_the_current_directory(self):
        with tempfile.TemporaryDirectory() as untrusted, tempfile.TemporaryDirectory() as empty_xdg:
            Path(untrusted, "silo.toml").write_text('[silo]\nname = "planted"\n[gateway]\nallow_tools = true\n')
            old = os.getcwd()
            os.chdir(untrusted)
            try:
                with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": empty_xdg}):
                    os.environ.pop("SILO_CONFIG", None)
                    cfg = config.load()
                    self.assertEqual((cfg.name, cfg.source, cfg.gateway.allow_tools), ("default", None, False))
                    # the same file is honoured once it is named explicitly
                    self.assertEqual(config.load(Path("silo.toml")).name, "planted")
                    with mock.patch.dict(os.environ, {"SILO_CONFIG": str(Path(untrusted, "silo.toml"))}):
                        self.assertEqual(config.load().name, "planted")
                    with mock.patch.dict(os.environ, {"SILO_CONFIG": "/nonexistent/silo.toml"}):
                        with self.assertRaises(config.ConfigError):
                            config.load()
            finally:
                os.chdir(old)

    def test_user_config_directory_is_the_default(self):
        with tempfile.TemporaryDirectory() as xdg:
            Path(xdg, "silo").mkdir()
            Path(xdg, "silo", "silo.toml").write_text('[silo]\nname = "mine"\n')
            with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": xdg}):
                os.environ.pop("SILO_CONFIG", None)
                cfg = config.load()
            self.assertEqual((cfg.name, cfg.source), ("mine", Path(xdg, "silo", "silo.toml").resolve()))

    def test_remote_listen_requires_api_key(self):
        cfg = config.load(write('[gateway]\nlisten = "0.0.0.0"\napi_key_env = "SILO_KEY"\n'))
        self.assertEqual(cfg.gateway.listen, "0.0.0.0")


if __name__ == "__main__":
    unittest.main()
