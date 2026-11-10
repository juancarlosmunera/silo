import json
import unittest
from pathlib import Path

from silo import seccomp

SYSTEM_BASE = Path("/usr/share/containers/seccomp.json")

# Minimal profile shaped like containers-common's: unconditional allows plus cap-gated rules.
FIXTURE = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "defaultErrnoRet": 38,
    "archMap": [{"architecture": "SCMP_ARCH_X86_64", "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]},
                {"architecture": "SCMP_ARCH_AARCH64", "subArchitectures": ["SCMP_ARCH_ARM"]}],
    "syscalls": [
        {"names": ["read", "write", "clone", "clone3", "unshare", "socket", "socketpair", "socketcall", "ptrace",
                   "mount", "keyctl", "memfd_create", "io_uring_setup", "msgget", "msgsnd", "splice", "vmsplice",
                   "io_setup", "mq_open", "futex", "mmap"], "action": "SCMP_ACT_ALLOW",
         "args": [], "includes": {}, "excludes": {}},
        {"names": ["bpf"], "action": "SCMP_ACT_ALLOW", "args": [], "includes": {"caps": ["CAP_SYS_ADMIN"]}},
        {"names": ["socket"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 0, "value": 16, "op": "SCMP_CMP_NE"}],
         "excludes": {"caps": ["CAP_AUDIT_WRITE"]}},
    ],
}


def rules_for(profile, name):
    return [r for r in profile["syscalls"] if name in r["names"]]


class HardenTests(unittest.TestCase):
    def harden(self, **kw):
        return seccomp.harden(FIXTURE, machine="x86_64", **kw)

    def test_native_arch_only(self):
        p = self.harden()
        self.assertEqual(p["archMap"], [{"architecture": "SCMP_ARCH_X86_64", "subArchitectures": []}])
        p = seccomp.harden(FIXTURE, machine="aarch64")
        self.assertEqual(p["archMap"][0]["architecture"], "SCMP_ARCH_AARCH64")
        self.assertEqual(p["archMap"][0]["subArchitectures"], [])

    def test_unsupported_arch_rejected(self):
        with self.assertRaises(ValueError):
            seccomp.harden(FIXTURE, machine="mips64")

    def test_denied_syscalls_never_allowed(self):
        p = self.harden()
        for rule in p["syscalls"]:
            if rule["action"] == "SCMP_ACT_ALLOW":
                for name in rule["names"]:
                    self.assertNotIn(name, seccomp.DENY, f"{name} still allowed")
                    self.assertNotIn(name, seccomp.FORCE_ENOSYS)
                    self.assertNotEqual(name, "memfd_create")

    def test_socket_af_unix_only(self):
        profile = self.harden()
        self.assertEqual(rules_for(profile, "socket"), rules_for(profile, "socketpair"))
        rules = rules_for(profile, "socket")
        self.assertEqual(len(rules), 2)
        allow = [r for r in rules if r["action"] == "SCMP_ACT_ALLOW"][0]
        deny = [r for r in rules if r["action"] != "SCMP_ACT_ALLOW"][0]
        self.assertEqual(allow["args"], [{"index": 0, "value": 1, "valueTwo": 0, "op": "SCMP_CMP_EQ"}])
        self.assertEqual(deny["args"][0]["op"], "SCMP_CMP_NE")
        self.assertEqual(deny["errnoRet"], seccomp.EAFNOSUPPORT)

    def test_clone_namespace_flags_denied(self):
        rules = rules_for(self.harden(), "clone")
        allow = [r for r in rules if r["action"] == "SCMP_ACT_ALLOW"]
        self.assertEqual(len(allow), 1)
        self.assertEqual(allow[0]["args"][0]["op"], "SCMP_CMP_MASKED_EQ")
        self.assertEqual(allow[0]["args"][0]["value"], seccomp.CLONE_NS_MASK)
        self.assertEqual(allow[0]["args"][0]["valueTwo"], 0)
        denied_bits = {r["args"][0]["value"] for r in rules if r["action"] != "SCMP_ACT_ALLOW"}
        self.assertEqual(denied_bits, set(seccomp.CLONE_NS_FLAGS.values()))

    def test_clone3_is_enosys_even_in_kill_mode(self):
        for action in ("errno", "kill"):
            rule = rules_for(self.harden(action=action), "clone3")
            self.assertEqual(len(rule), 1)
            self.assertEqual(rule[0]["action"], "SCMP_ACT_ERRNO")
            self.assertEqual(rule[0]["errnoRet"], seccomp.ENOSYS)

    def test_kill_mode(self):
        p = self.harden(action="kill")
        deny = [r for r in p["syscalls"] if "ptrace" in r["names"]][0]
        self.assertEqual(deny["action"], "SCMP_ACT_KILL_PROCESS")

    def test_argument_filtered_syscalls_have_no_unconditional_rule(self):
        # libseccomp lets an unconditional rule silently override argument-filtered ones, so the
        # filtered syscalls must not survive anywhere else in the profile.
        for profile in (self.harden(), self.harden(action="kill")):
            for name in seccomp.REPLACED:
                for rule in rules_for(profile, name):
                    self.assertTrue(rule.get("args"), f"{name} has a rule without argument conditions")
                    self.assertTrue(rule.get("comment", "").startswith("silo:"), f"{name}: base rule survived")

    def test_exploit_primitives_denied(self):
        allowed = seccomp.allowed_unconditionally(self.harden())
        for name in ("msgget", "msgsnd", "splice", "vmsplice", "io_setup", "mq_open"):
            self.assertNotIn(name, allowed)

    def test_gpu_mode_keeps_memfd(self):
        p = self.harden(cpu_only=False)
        self.assertIn("memfd_create", seccomp.allowed_unconditionally(p))
        self.assertNotIn("memfd_create", seccomp.allowed_unconditionally(self.harden()))

    def test_base_profile_not_mutated(self):
        before = json.dumps(FIXTURE, sort_keys=True)
        self.harden()
        self.assertEqual(before, json.dumps(FIXTURE, sort_keys=True))

    def test_harmless_syscalls_survive(self):
        allowed = seccomp.allowed_unconditionally(self.harden())
        self.assertTrue({"read", "write", "futex", "mmap"} <= allowed)

    @unittest.skipUnless(SYSTEM_BASE.is_file(), "containers-common seccomp profile not installed")
    def test_system_profile(self):
        base = json.loads(SYSTEM_BASE.read_text())
        p = seccomp.harden(base, machine="x86_64")
        allowed = seccomp.allowed_unconditionally(p)
        for name in ("unshare", "setns", "mount", "ptrace", "io_uring_setup", "socketcall", "clone3", "keyctl",
                     "bpf", "userfaultfd", "memfd_create", "socket", "socketpair", "clone", "msgget", "splice",
                     "io_setup", "mq_open", "pidfd_getfd", "process_vm_readv", "open_by_handle_at"):
            self.assertNotIn(name, allowed)
        for name in ("execve", "read", "mmap", "futex", "connect", "bind", "accept4", "epoll_wait"):
            self.assertIn(name, allowed)  # what an inference server actually needs still works
        for name in seccomp.REPLACED:
            for rule in rules_for(p, name):
                self.assertTrue(rule.get("args"))


if __name__ == "__main__":
    unittest.main()
