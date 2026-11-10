"""silo is run from directories it does not trust. Nothing in the current directory may reach it."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LAUNCHER = REPO / "bin" / "silo"
PLANTED = 'import sys\nprint("PLANTED CODE RAN", file=sys.stderr)\nraise SystemExit(99)\n'
STDLIB_SHADOWS = ("json.py", "tomllib.py", "argparse.py", "subprocess.py", "pathlib.py", "socket.py")


class UntrustedDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        (self.dir / "model.gguf").write_bytes(b"GGUF")

    def plant(self, *names):
        for name in names:
            (self.dir / name).write_text(PLANTED)

    def run_in_dir(self, argv, **env):
        clean = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        return subprocess.run(argv, cwd=self.dir, env={**clean, **env}, capture_output=True, text=True, timeout=60)

    def assert_clean(self, result):
        self.assertNotIn("PLANTED", result.stdout + result.stderr)
        self.assertEqual((result.returncode, result.stdout.strip()[:5]), (0, "silo "), result.stderr)

    def test_launcher_ignores_modules_planted_in_the_current_directory(self):
        self.plant(*STDLIB_SHADOWS, "silo.py", "runpy.py", "sitecustomize.py")
        (self.dir / "silo").mkdir()
        (self.dir / "silo" / "__init__.py").write_text(PLANTED)
        self.assert_clean(self.run_in_dir([str(LAUNCHER), "--version"]))

    def test_launcher_ignores_pythonpath_and_startup_hooks(self):
        self.plant(*STDLIB_SHADOWS, "silo.py", "startup.py")
        result = self.run_in_dir([str(LAUNCHER), "--version"], PYTHONPATH=str(self.dir),
                                 PYTHONSTARTUP=str(self.dir / "startup.py"), PYTHONHOME="")
        self.assert_clean(result)

    def test_launcher_is_isolated_even_when_run_through_an_interpreter(self):
        # `python3 bin/silo` loses the -I from the shebang; the script directory, not the current
        # directory, is then first on the path, and bin/ holds nothing importable.
        self.plant(*STDLIB_SHADOWS, "silo.py")
        self.assert_clean(self.run_in_dir([sys.executable, str(LAUNCHER), "--version"]))

    def test_module_run_drops_the_current_directory(self):
        # Partial by nature: -m cannot be protected against a planted silo.py or runpy.py, which is
        # why the documentation says not to use it. Shadowed standard-library modules are stopped.
        self.plant(*STDLIB_SHADOWS)
        self.assert_clean(self.run_in_dir([sys.executable, "-m", "silo", "--version"], PYTHONPATH=str(REPO / "src")))

    def test_launcher_is_executable_and_isolated(self):
        self.assertTrue(os.access(LAUNCHER, os.X_OK))
        self.assertEqual(LAUNCHER.read_text().splitlines()[0], "#!/usr/bin/env -S python3 -I")


if __name__ == "__main__":
    unittest.main()
