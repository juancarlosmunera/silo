import unittest
from pathlib import Path

from silo import sandbox
from silo.config import Config


def build(**kw):
    defaults = dict(name="silo-t", image="img:1", command=["--x"], seccomp_profile=Path("/tmp/p.json"))
    defaults.update(kw)
    return sandbox.podman_run_args(Config(), **defaults)


class SandboxArgsTests(unittest.TestCase):
    def test_required_flags_present(self):
        args = build()
        for flag in sandbox.REQUIRED_FLAGS:
            self.assertIn(flag, args)
        self.assertIn("--security-opt=seccomp=/tmp/p.json", args)
        self.assertEqual(args[-2:], ["img:1", "--x"])
        mask = next(a for a in args if a.startswith("--security-opt=mask="))
        for path in ("/dev/pts", "/proc/kallsyms", "/sys/kernel"):
            self.assertIn(path, mask.split("=", 2)[2].split(":"))
        self.assertIn("--log-driver=k8s-file", args)
        self.assertIn("--memory-swap=8g", args)  # same as --memory: no swap for the sandbox

    def test_no_devices_without_gpu(self):
        self.assertFalse(any(a.startswith("--device") for a in build()))

    def test_gpu_devices(self):
        self.assertIn("--device=nvidia.com/gpu=all", build(gpu="nvidia"))
        self.assertIn("--device=/dev/dri", build(gpu="dri"))

    def test_mounts(self):
        args = build(mounts=[sandbox.Mount(Path("/m"), "/models", shared_label=True),
                             sandbox.Mount(Path("/s"), "/run/silo", writable=True)])
        self.assertIn("--volume=/m:/models:ro,z,nosuid,nodev,noexec", args)
        self.assertIn("--volume=/s:/run/silo:rw,Z,nosuid,nodev,noexec", args)

    def test_writable_shared_mount_rejected(self):
        with self.assertRaises(sandbox.HardeningError):
            sandbox.Mount(Path("/s"), "/x", writable=True, shared_label=True).flag()

    def test_assert_hardened_catches_tampering(self):
        good = build()
        image_at = good.index("img:1")
        for bad in ("--privileged", "--network=host", "--net=host", "--cap-add=SYS_ADMIN", "--pid=host",
                    "--security-opt=seccomp=unconfined", "--security-opt=label=disable", "-p", "--publish=80:80",
                    "--network=pasta", "--device=/dev/kvm", "--userns=host", "--env-host"):
            tampered = good[:image_at] + [bad] + good[image_at:]
            with self.subTest(bad=bad), self.assertRaises(sandbox.HardeningError):
                sandbox.assert_hardened(tampered)
        for flag in ("--network=none", "--cap-drop=all", "--read-only", "--unsetenv-all", "--pull=never",
                     "--security-opt=no-new-privileges", "--user=65534:65534"):
            stripped = [a for a in good if a != flag]
            with self.subTest(missing=flag), self.assertRaises(sandbox.HardeningError):
                sandbox.assert_hardened(stripped)
        for prefix in ("--security-opt=mask=", "--security-opt=seccomp="):
            stripped = [a for a in good if not a.startswith(prefix)]
            with self.subTest(missing=prefix), self.assertRaises(sandbox.HardeningError):
                sandbox.assert_hardened(stripped)
        weakened = [a.replace(":/dev/pts", "") for a in good]
        with self.assertRaises(sandbox.HardeningError):
            sandbox.assert_hardened(weakened)

    def test_separated_option_values_fail_closed(self):
        # "--network host" (two argv entries) makes "host" look like the image; everything after it
        # is then missing from the option list and the check must refuse rather than guess.
        good = build()
        image_at = good.index("img:1")
        with self.assertRaises(sandbox.HardeningError):
            sandbox.assert_hardened(good[:3] + ["--network", "host"] + good[3:image_at] + good[image_at:])

    def test_command_args_after_image_are_not_checked_as_podman_flags(self):
        # llama-server's own "--host" etc. live after the image and must not trip the podman checks
        args = build(command=["--host", "/run/silo/llama.sock", "-p", "x"])
        self.assertEqual(args[-4:], ["--host", "/run/silo/llama.sock", "-p", "x"])


if __name__ == "__main__":
    unittest.main()
