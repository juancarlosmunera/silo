"""The parts of the escape probes that can be checked without a sandbox."""

import unittest

from silo.probes import escape_probes as probes

# /proc/self/mountinfo of a silo sandbox (rootless Podman 5.8, crun), trimmed to one line per kind.
SILO_MOUNTS = """\
1157 925 0:39 /home/u/models/m /models ro,nosuid,nodev,noexec,relatime - btrfs /dev/nvme0n1p3 ro
1163 1158 0:71 / /dev/shm ro,nosuid,nodev,noexec,relatime - tmpfs shm rw
1164 925 0:60 /containers/overlay-containers/55/userdata/.containerenv /run/.containerenv ro,nosuid,nodev - tmpfs tmpfs rw
1166 925 0:60 /containers/overlay-containers/55/userdata/hostname /etc/hostname ro,nosuid,nodev - tmpfs tmpfs rw
925 924 0:68 / / ro,relatime - overlay overlay rw
1158 925 0:72 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw
1159 925 0:73 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1160 925 0:74 / /dev ro,nosuid - tmpfs tmpfs rw
1162 1160 0:76 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw
1167 1160 0:70 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
1168 1161 0:28 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime,nosymfollow - cgroup2 cgroup2 rw
1169 1160 0:6 /null /dev/null rw,nosuid,noexec - devtmpfs devtmpfs rw
1170 1160 0:6 /urandom /dev/urandom rw,nosuid,noexec - devtmpfs devtmpfs rw
1171 1159 0:60 /crun/.empty-directory /proc/acpi ro,nosuid,nodev,relatime - tmpfs tmpfs rw
1172 1161 0:60 /crun/.empty-directory /sys/kernel ro,nosuid,nodev,relatime - tmpfs tmpfs rw
"""
# What must never be there: a writable host directory. One lives on tmpfs (as silo's old socket
# directory in $XDG_RUNTIME_DIR did), one on disk.
SHARED_TMPFS = "1161 925 0:60 /silo/default /run/silo rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw\n"
SHARED_DISK = "1173 925 0:39 /home/u/work /data rw,nosuid,nodev,noexec,relatime - btrfs /dev/nvme0n1p3 rw\n"
PRIVATE_TMPFS = "1174 925 0:80 / /var/tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw\n"
GPU_NODE = "1175 1160 0:6 /dri/renderD128 /dev/dri/renderD128 rw,nosuid,noexec - devtmpfs devtmpfs rw\n"

DIRS = {"/models", "/tmp", "/proc", "/dev", "/dev/shm", "/dev/pts", "/dev/mqueue", "/sys/fs/cgroup", "/", "/run/silo",
        "/data", "/var/tmp", "/proc/acpi", "/sys/kernel"}


def shared(table: str) -> list[str]:
    return probes.shared_writable_dirs(table.splitlines(), isdir=DIRS.__contains__)


class SharedDirectoryTests(unittest.TestCase):
    def test_a_silo_sandbox_shares_nothing_writable(self):
        self.assertEqual(shared(SILO_MOUNTS), [])

    def test_a_writable_host_directory_is_found_on_any_filesystem(self):
        self.assertEqual(shared(SILO_MOUNTS + SHARED_TMPFS), ["/run/silo"])  # tmpfs: the case a type filter misses
        self.assertEqual(shared(SILO_MOUNTS + SHARED_DISK), ["/data"])
        self.assertEqual(shared(SHARED_TMPFS + SILO_MOUNTS + SHARED_DISK), ["/run/silo", "/data"])

    def test_an_unexpected_scratch_mount_fails_closed(self):
        # indistinguishable from a bind of a whole host tmpfs, so it is reported
        self.assertEqual(shared(SILO_MOUNTS + PRIVATE_TMPFS), ["/var/tmp"])

    def test_read_only_mounts_and_device_nodes_do_not_count(self):
        read_only = SHARED_DISK.replace(" rw,nosuid", " ro,nosuid")
        self.assertEqual(shared(SILO_MOUNTS + read_only + GPU_NODE), [])

    def test_superblock_options_are_not_mount_options(self):
        # the trailing field says the filesystem is writable; the mount itself is read-only
        line = "1157 925 0:39 /home/u/models/m /models ro,nosuid - btrfs /dev/nvme0n1p3 rw,ssd\n"
        self.assertEqual(shared(line), [])


class MountOptionTests(unittest.TestCase):
    def options(self, path, extra=""):
        return probes.mount_options(path, (SILO_MOUNTS + extra).splitlines())

    def test_the_mount_that_holds_the_path(self):
        self.assertIn("noexec", self.options("/tmp"))
        self.assertIn("noexec", self.options("/tmp/some/dropped/file"))
        self.assertNotIn("noexec", self.options("/usr/local/bin"))   # the root filesystem
        self.assertEqual(self.options("/tmpfoo"), self.options("/"))  # a name that merely starts like a mount point

    def test_the_last_mount_on_a_path_wins(self):
        remounted = "1180 925 0:90 / /tmp rw,nosuid,nodev,relatime - tmpfs tmpfs rw\n"
        self.assertNotIn("noexec", self.options("/tmp", remounted))

    def test_unreadable_table_means_no_flags(self):
        self.assertEqual(probes.mount_options("/tmp", ["garbage"]), set())


class LsmVerdictTests(unittest.TestCase):
    """What the probes make of the label in /proc/self/attr/current."""

    def verdict(self, label, canary=None):
        return probes.lsm_verdict(label, lambda: canary)[0]

    def denied(self):
        return PermissionError(13, "Permission denied")

    def test_selinux(self):
        self.assertEqual(self.verdict("system_u:system_r:container_t:s0:c12,c34"), "PASS")
        self.assertEqual(self.verdict("unconfined_u:unconfined_r:container_runtime_t:s0"), "WARN")
        self.assertEqual(self.verdict("unconfined_u:unconfined_r:unconfined_t:s0"), "WARN")

    def test_no_confinement(self):
        for label in ("", "unconfined", "crun (unconfined)", "something-odd"):
            with self.subTest(label=label):
                self.assertEqual(self.verdict(label), "WARN")

    def test_silos_apparmor_profile_must_be_enforced_not_just_attached(self):
        for label in ("silo-runtime (enforce)", "crun//&silo-runtime (mixed)", "silo-runtime//&crun (mixed)"):
            with self.subTest(label=label):
                self.assertEqual(self.verdict(label, self.denied()), "PASS")   # the profile refused the canary
                self.assertEqual(self.verdict(label, None), "WARN")            # complain mode: it went through
                self.assertEqual(self.verdict(label, OSError(30, "Read-only file system")), "WARN")

    def test_a_stack_without_silos_profile_is_not_confinement(self):
        refused = self.denied()
        self.assertEqual(self.verdict("crun//&docker-default (mixed)", refused), "WARN")
        self.assertEqual(self.verdict("not-silo-runtime (complain)", refused), "WARN")
        self.assertEqual(self.verdict("docker-default (enforce)"), "PASS")  # some other enforcing profile

    def test_the_profile_file_agrees_with_the_probe(self):
        from pathlib import Path
        profile = Path(__file__).resolve().parents[1] / "host" / "apparmor" / "silo-runtime"
        text = profile.read_text()
        self.assertIn(f"profile {probes.SILO_APPARMOR} ", text)
        self.assertIn(f"deny {probes.APPARMOR_CANARY} w,", text)
        rules = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
        self.assertIn("network unix,", rules)
        for forbidden in ("capability", "mount", "ptrace", "network inet", "network,", "userns", "change_profile"):
            self.assertFalse(any(r == forbidden + "," or r.startswith(forbidden + " ") for r in rules), forbidden)


if __name__ == "__main__":
    unittest.main()
