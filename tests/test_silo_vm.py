"""bin/silo-vm: the properties that make the VM a boundary must not erode."""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "bin" / "silo-vm"


def run(*args, **env):
    clean = {k: v for k, v in os.environ.items() if not k.startswith("SILO_VM_")}
    return subprocess.run([str(SCRIPT), *args], capture_output=True, text=True, timeout=60, env={**clean, **env})


class SiloVmTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        self.text = SCRIPT.read_text()
        start = self.text.index("\nboot() {")
        self.boot = self.text[start:self.text.index("\n}\n", start)]

    def test_script_is_valid_posix_sh_and_executable(self):
        self.assertTrue(os.access(SCRIPT, os.X_OK))
        self.assertEqual(self.text.splitlines()[0], "#!/bin/sh")
        self.assertEqual(subprocess.run(["sh", "-n", str(SCRIPT)]).returncode, 0)

    def test_every_boot_is_hardened(self):
        for option in ("-nodefaults", "-no-user-config", "-display none", "accel=kvm",
                       "-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
                       "-device vhost-vsock-pci,guest-cid="):
            self.assertIn(option, self.boot)
        self.assertIn("readonly=on", self.boot)  # the cloud-init seed

    def test_no_network_device_unless_updating(self):
        self.assertNotIn("netdev", self.boot)
        self.assertNotIn("virtio-net", self.boot)
        branches = dict(re.findall(r"\n([a-z-]+)\)\n(.*?)\n    ;;", self.text, re.S))
        self.assertEqual(set(branches), {"create", "update", "start", "stop", "status", "ssh-config"})
        self.assertIn("-netdev user,id=n0 -device virtio-net-pci,netdev=n0", branches["update"])
        for name in ("start", "stop", "status", "create", "ssh-config"):
            self.assertNotIn("netdev", branches[name], name)
        self.assertRegex(branches["start"], r"\n    boot\n")  # normal operation adds nothing to the base options

    def test_nothing_on_the_host_listens_for_the_guest(self):
        # No forwarded ports, no monitor or QMP socket, no VNC/SPICE, no TAP or bridge.
        for word in ("hostfwd", "guestfwd", "-monitor", "-qmp", "-vnc", "-spice", "tap,", "bridge"):
            self.assertNotIn(word, self.text, word)

    def test_ssh_configuration(self):
        result = run("ssh-config", SILO_VM_DIR=self.dir, SILO_VM_CID="77")
        self.assertEqual(result.returncode, 0, result.stderr)
        config = result.stdout
        self.assertIn("ProxyCommand /usr/lib/systemd/systemd-ssh-proxy vsock/77 22", config)
        for line in ("ProxyUseFdpass yes", "ForwardAgent no", "IdentityAgent none", "IdentitiesOnly yes",
                     f"IdentityFile {self.dir}/key", f"UserKnownHostsFile {self.dir}/known_hosts"):
            self.assertIn(line, config)
        self.assertRegex(config, r"Host silo-vm\n    User silo\n")
        self.assertRegex(config, r"Host silo-vm-admin\n    User admin\n")
        self.assertIn("vsock/42", run("ssh-config", SILO_VM_DIR=self.dir).stdout)

    def test_guest_accounts_in_the_first_boot_recipe(self):
        seed = self.text[self.text.index("#cloud-config"):self.text.index("\nSEED\n")]
        admin, silo = seed.split("  - name: silo")
        self.assertIn("sudo:", admin)
        self.assertNotIn("sudo", silo.split("ssh_pwauth")[0])  # the account that runs the model has none
        self.assertNotIn("groups", silo.split("ssh_pwauth")[0])
        for line in ("ssh_pwauth: false", "package_upgrade: true", "[loginctl, enable-linger, silo]", "mode: poweroff"):
            self.assertIn(line, seed)
        self.assertEqual(seed.count("lock_passwd: true"), 2)

    def test_usage_and_errors(self):
        self.assertEqual(run().returncode, 2)
        self.assertIn("silo-vm create IMAGE.qcow2", run().stdout)
        for command in ("start", "update", "status"):
            result = run(command, SILO_VM_DIR=self.dir)
            self.assertEqual(result.returncode, 1, command)
            self.assertIn("no VM in", result.stderr)
        result = run("create", "/nonexistent/image.qcow2", SILO_VM_DIR=self.dir)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no such image", result.stderr)
        self.assertEqual(os.listdir(self.dir), [])  # nothing created on failure


if __name__ == "__main__":
    unittest.main()
