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

    def gvisor_cfg(self, platform="systrap"):
        cfg = Config()
        cfg.runtime.runsc = Path("/usr/local/bin/runsc")
        cfg.runtime.gvisor_platform = platform
        return cfg

    def gvisor_args(self, platform="systrap"):
        return sandbox.podman_run_args(self.gvisor_cfg(platform), name="silo-t", image="img:1", command=["--x"],
                                       seccomp_profile=Path("/tmp/p.json"))

    def test_gvisor_sandbox(self):
        args = self.gvisor_args()
        run = args.index("run")
        self.assertEqual(args[1:run], ["--runtime=/usr/local/bin/runsc", "--runtime-flag=ignore-cgroups",
                                       "--runtime-flag=network=none", "--runtime-flag=directfs=false",
                                       "--runtime-flag=host-uds=create", "--cgroup-manager=cgroupfs",
                                       "--runtime-flag=platform=systrap"])
        self.assertIn("--runtime-flag=platform=kvm", self.gvisor_args("kvm"))
        for flag in sandbox.REQUIRED_FLAGS:  # everything silo asks of a sandbox still applies on gVisor
            self.assertIn(flag, args[run:])
        self.assertIn("--security-opt=label=disable", args)
        self.assertIn("--security-opt=seccomp=/tmp/p.json", args)
        self.assertEqual(args[-2:], ["img:1", "--x"])
        self.assertEqual(build()[:2], ["podman", "run"])  # and without runsc nothing changes

    def test_gvisor_exceptions_only_apply_to_gvisor(self):
        gvisor = sandbox.gvisor_globals(self.gvisor_cfg().runtime)
        args = self.gvisor_args()
        sandbox.assert_hardened(args, gvisor=gvisor)
        plain = build()
        with self.assertRaises(sandbox.HardeningError):  # label=disable is refused on the host kernel
            sandbox.assert_hardened(plain[:2] + ["--security-opt=label=disable"] + plain[2:])
        with self.assertRaises(sandbox.HardeningError):  # a gVisor command line is not accepted as a plain one
            sandbox.assert_hardened(args)
        for extra in ("--runtime-flag=network=host", "--runtime-flag=host-uds=all", "--runtime-flag=directfs=true",
                      "--root=/tmp/elsewhere"):
            with self.subTest(extra=extra), self.assertRaises(sandbox.HardeningError):
                sandbox.assert_hardened(["podman", extra, *args[1:]], gvisor=gvisor)
        with self.assertRaises(sandbox.HardeningError):  # the globals must be exactly the expected ones
            sandbox.assert_hardened([a for a in args if a != "--runtime-flag=directfs=false"], gvisor=gvisor)
        for bad in ("--privileged", "--network=host", "--cap-add=SYS_ADMIN"):
            with self.subTest(bad=bad), self.assertRaises(sandbox.HardeningError):
                sandbox.assert_hardened(args[:args.index("run") + 1] + [bad] + args[args.index("run") + 1:],
                                        gvisor=gvisor)

    def test_gvisor_scope(self):
        scope = sandbox.gvisor_scope(2 << 30, 1024)
        self.assertEqual(scope[:3], ["systemd-run", "--user", "--scope"])
        for prop in ("MemoryMax=2147483648", "MemorySwapMax=0", "TasksMax=1024"):
            self.assertIn(prop, scope)
        self.assertFalse(any(p.startswith("CPUQuota") for p in scope))
        self.assertIn("CPUQuota=250%", sandbox.gvisor_scope(1 << 30, 64, cpus=2.5))

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
