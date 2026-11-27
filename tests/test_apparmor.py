import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from silo import apparmor

# A stand-in for crun: records how it was called and exits.
FAKE_RUNTIME = """#!/bin/sh
printf '%s\\n' "$@" > "$(dirname "$0")/called-with"
"""


class WrapperTests(unittest.TestCase):
    """The OCI runtime wrapper, run for real against a stand-in runtime."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.runtime = self.dir / "fake-crun"
        self.runtime.write_text(FAKE_RUNTIME)
        self.runtime.chmod(0o755)
        self.wrapper = apparmor.install_wrapper(self.dir / "oci", str(self.runtime))
        self.bundle = self.dir / "bundle"
        self.bundle.mkdir()
        self.spec = {"ociVersion": "1.2.0", "process": {"args": ["/app/llama-server"], "noNewPrivileges": True,
                                                         "user": {"uid": 65534, "gid": 65534}},
                     "linux": {"seccomp": {"listenerPath": "/run/user/1000/silo/default/exec.sock"}},
                     "big": 18446744073709551615}
        (self.bundle / "config.json").write_text(json.dumps(self.spec))

    def run_wrapper(self, *args):
        (self.dir / "called-with").unlink(missing_ok=True)
        res = subprocess.run([str(self.wrapper), *args], capture_output=True, text=True, timeout=30)
        called = self.dir / "called-with"
        return res, (called.read_text().splitlines() if called.exists() else None)

    def config(self):
        return json.loads((self.bundle / "config.json").read_text())

    def test_create_sets_the_profile_and_changes_nothing_else(self):
        args = ["--root", "/run/user/1000/crun", "create", "--bundle", str(self.bundle), "--pid-file", "/x/pid", "abc123"]
        res, called = self.run_wrapper(*args)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(called, args)                        # the real runtime gets exactly what Podman passed
        after = self.config()
        self.assertEqual(after["process"].pop("apparmorProfile"), "silo-runtime")
        self.assertEqual(after, self.spec)                    # seccomp listener, user, big numbers: untouched
        self.assertEqual(os.listdir(self.bundle), ["config.json"])  # no temporary file left behind

    def test_both_spellings_of_the_bundle_option(self):
        for args in (["create", f"--bundle={self.bundle}", "id"], ["create", "-b", str(self.bundle), "id"],
                     ["run", "--bundle", str(self.bundle), "id"]):
            with self.subTest(args=args[:2]):
                (self.bundle / "config.json").write_text(json.dumps(self.spec))
                res, called = self.run_wrapper(*args)
                self.assertEqual((res.returncode, called), (0, args))
                self.assertEqual(self.config()["process"]["apparmorProfile"], "silo-runtime")

    def test_exec_confines_the_added_process_too(self):
        process = self.dir / "process.json"
        process.write_text(json.dumps({"args": ["/bin/sh"], "cwd": "/"}))
        res, called = self.run_wrapper("exec", "--process", str(process), "abc123")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(json.loads(process.read_text()), {"args": ["/bin/sh"], "cwd": "/", "apparmorProfile": "silo-runtime"})
        self.assertEqual(called[0], "exec")

    def test_other_commands_pass_straight_through(self):
        before = (self.bundle / "config.json").read_text()
        for args in (["start", "abc123"], ["state", "abc123"], ["kill", "abc123", "TERM"], ["delete", "--force", "abc123"],
                     ["--version"]):
            with self.subTest(args=args):
                res, called = self.run_wrapper(*args)
                self.assertEqual((res.returncode, called), (0, args))
        self.assertEqual((self.bundle / "config.json").read_text(), before)

    def test_restore_starts_a_container_too(self):
        res, called = self.run_wrapper("restore", "--bundle", str(self.bundle), "--image-path", "/x", "abc123")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(self.config()["process"]["apparmorProfile"], "silo-runtime")
        res, called = self.run_wrapper("restore", "--image-path", "/x", "abc123")
        self.assertNotEqual(res.returncode, 0)
        self.assertIsNone(called)

    def test_the_subcommand_is_not_confused_with_option_values(self):
        process = self.dir / "process.json"
        process.write_text(json.dumps({"args": ["/bin/sh"]}))
        # an exec whose pid file is called "create": the process, not the bundle, gets the profile
        res, called = self.run_wrapper("exec", "--pid-file", "create", "--process", str(process), "abc123")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(json.loads(process.read_text())["apparmorProfile"], "silo-runtime")
        # global option values that look like subcommands
        for args in (["--root", "run", "kill", "abc123", "TERM"], ["--log", "create", "state", "abc123"],
                     ["--root", "exec", "delete", "abc123"], ["kill", "exec"]):
            with self.subTest(args=args):
                res, called = self.run_wrapper(*args)
                self.assertEqual((res.returncode, called), (0, args), res.stderr)
        # a command the wrapper does not know could start something: refused
        res, called = self.run_wrapper("--debug", "frobnicate", "abc123")
        self.assertNotEqual(res.returncode, 0)
        self.assertIsNone(called)

    def test_fails_closed_when_it_cannot_set_the_profile(self):
        res, called = self.run_wrapper("create", "abc123")            # no bundle named
        self.assertNotEqual(res.returncode, 0)
        self.assertIsNone(called)                                     # the real runtime was never started
        self.assertIn("unconfined", res.stderr)
        res, called = self.run_wrapper("create", "--bundle", str(self.dir / "missing"), "abc123")
        self.assertNotEqual(res.returncode, 0)
        self.assertIsNone(called)
        (self.bundle / "config.json").write_text("not json")
        res, called = self.run_wrapper("create", "--bundle", str(self.bundle), "abc123")
        self.assertNotEqual(res.returncode, 0)
        self.assertIsNone(called)
        res, called = self.run_wrapper("exec", "abc123", "/bin/sh")   # exec without a process file
        self.assertNotEqual(res.returncode, 0)
        self.assertIsNone(called)

    def test_installation(self):
        self.assertEqual(self.wrapper.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.wrapper.parent.stat().st_mode & 0o777, 0o700)
        source = self.wrapper.read_text()
        self.assertTrue(source.startswith(f"#!{sys.executable} -I\n"))
        self.assertFalse(any(line.startswith(("from silo", "import silo")) for line in source.splitlines()))
        first = self.wrapper.stat().st_mtime_ns
        self.assertEqual(apparmor.install_wrapper(self.dir / "oci", str(self.runtime)), self.wrapper)
        self.assertEqual(self.wrapper.stat().st_mtime_ns, first)      # unchanged: not rewritten
        apparmor.install_wrapper(self.dir / "oci", "/usr/bin/runc")
        self.assertIn("'/usr/bin/runc'", self.wrapper.read_text())    # a different runtime: rewritten


class DetectionTests(unittest.TestCase):
    def test_not_loaded_where_apparmor_is_off(self):
        with mock.patch.object(apparmor, "ENABLED", Path("/nonexistent/enabled")):
            self.assertFalse(apparmor.enabled())
            self.assertFalse(apparmor.profile_loaded())

    def test_enabled_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            flag = Path(tmp) / "enabled"
            for content, expected in (("Y\n", True), ("N\n", False), ("", False)):
                flag.write_text(content)
                with mock.patch.object(apparmor, "ENABLED", flag):
                    self.assertIs(apparmor.enabled(), expected)

    def test_a_profile_that_cannot_exist_is_not_loaded(self):
        # Wherever this runs: either AppArmor is off, or the kernel says there is no such profile.
        self.assertFalse(apparmor.profile_loaded("silo-no-such-profile-7f3a"))


if __name__ == "__main__":
    unittest.main()
