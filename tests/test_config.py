import os
import tempfile
import unittest
from pathlib import Path

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
            '[runtime]\npids_limit = 64.5\n',
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

    def test_safe_defaults(self):
        cfg = config.Config()
        self.assertFalse(cfg.gateway.allow_tools)
        self.assertFalse(cfg.gateway.log_content)
        self.assertEqual(cfg.gateway.scanner, "monitor")
        self.assertEqual(cfg.runtime.gpu, "none")

    def test_types_are_coerced_only_where_safe(self):
        cfg = config.load(write('[runtime]\ncpus = 4\nimage = "ghcr.io/x/y@sha256:' + "a" * 64 + '"\n'
                                '[gateway]\ntimeout = 30\nallow_tools = true\n'))
        self.assertEqual((cfg.runtime.cpus, cfg.gateway.timeout, cfg.gateway.allow_tools), (4.0, 30.0, True))

    def test_remote_listen_requires_api_key(self):
        cfg = config.load(write('[gateway]\nlisten = "0.0.0.0"\napi_key_env = "SILO_KEY"\n'))
        self.assertEqual(cfg.gateway.listen, "0.0.0.0")


if __name__ == "__main__":
    unittest.main()
