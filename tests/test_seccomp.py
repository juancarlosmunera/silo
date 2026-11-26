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
                   "io_setup", "mq_open", "futex", "mmap", "execve", "execveat"], "action": "SCMP_ACT_ALLOW",
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

    def test_exec_lock(self):
        listener = Path("/run/user/1000/silo/default/exec.sock")
        for action in ("errno", "kill"):
            p = self.harden(action=action, exec_listener=listener)
            self.assertEqual(p["listenerPath"], str(listener))
            for name in seccomp.EXEC_SYSCALLS:
                rules = rules_for(p, name)
                self.assertEqual([r["action"] for r in rules], ["SCMP_ACT_NOTIFY"], name)
                self.assertNotIn(name, seccomp.allowed_unconditionally(p))
        # the supervisor decides, in kill mode too: the entrypoint's own exec must not be killed by the filter
        self.assertFalse(any(r["action"] == "SCMP_ACT_KILL_PROCESS" and set(r["names"]) & set(seccomp.EXEC_SYSCALLS)
                             for r in self.harden(action="kill", exec_listener=listener)["syscalls"]))

    def test_without_the_exec_lock_nothing_is_notified(self):
        p = self.harden()
        self.assertNotIn("listenerPath", p)
        self.assertFalse(any(r["action"] == "SCMP_ACT_NOTIFY" for r in p["syscalls"]))

    def test_a_listener_in_the_base_profile_is_not_inherited(self):
        base = {**FIXTURE, "listenerPath": "/somewhere/else.sock", "listenerMetadata": "x"}
        p = seccomp.harden(base, machine="x86_64")
        self.assertNotIn("listenerPath", p)
        self.assertNotIn("listenerMetadata", p)
        p = seccomp.harden(base, machine="x86_64", exec_listener=Path("/run/silo-exec.sock"))
        self.assertEqual(p["listenerPath"], "/run/silo-exec.sock")

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



MAX64 = (1 << 64) - 1
OPS = {
    "SCMP_CMP_EQ": lambda x, a: x == a["value"],
    "SCMP_CMP_NE": lambda x, a: x != a["value"],
    "SCMP_CMP_LT": lambda x, a: x < a["value"],
    "SCMP_CMP_LE": lambda x, a: x <= a["value"],
    "SCMP_CMP_GT": lambda x, a: x > a["value"],
    "SCMP_CMP_GE": lambda x, a: x >= a["value"],
    "SCMP_CMP_MASKED_EQ": lambda x, a: x & a["value"] == a["valueTwo"],
}


def matching(rules, args):
    """The rules whose every condition holds for the given argument values (libseccomp semantics)."""
    return [r for r in rules if all(OPS[c["op"]](args[c["index"]], c) for c in r["args"])]


def samples(values):
    """Allowed values, their neighbours, the extremes, and the same with stray upper bits."""
    out = {0, 1, 0xFFFF, seccomp.U32, seccomp.U32 + 1, MAX64, 0x80000000}
    for v in values:
        out |= {v, max(v - 1, 0), min(v + 1, MAX64), v | 1 << 32, v | 1 << 63, v ^ 1, v ^ 0x80000000}
    return sorted(out)


class ArgumentAllowlistTests(unittest.TestCase):
    def profile(self, **kw):
        return seccomp.harden(FIXTURE, machine="x86_64", **kw)

    def assert_partition(self, rules, allowed, args_for):
        """Every probed call matches exactly one rule, and it allows exactly the allowlisted values."""
        for value in samples(allowed):
            with self.subTest(value=hex(value)):
                hits = matching(rules, args_for(value))
                self.assertEqual(len(hits), 1, f"{len(hits)} rules match")
                self.assertEqual(hits[0]["action"] == "SCMP_ACT_ALLOW", value in allowed)

    def test_ioctl_and_prctl(self):
        p = self.profile()
        self.assert_partition(rules_for(p, "ioctl"), set(seccomp.IOCTL_ALLOW), lambda v: {0: 3, 1: v, 2: 0})
        self.assert_partition(rules_for(p, "prctl"), set(seccomp.PRCTL_ALLOW), lambda v: {0: v, 1: 0})

    def test_setsockopt(self):
        rules = rules_for(self.profile(), "setsockopt")
        levels = set(seccomp.SETSOCKOPT_ALLOW)
        self.assert_partition([r for r in rules if all(c["index"] == 1 for c in r["args"])] + [
            {"action": "SCMP_ACT_ALLOW", "args": [{"index": 1, "value": lvl, "op": "SCMP_CMP_EQ"}]} for lvl in levels],
            levels, lambda v: {1: v, 2: 0})
        for level, names in seccomp.SETSOCKOPT_ALLOW.items():
            with self.subTest(level=level):
                self.assert_partition(rules, set(names), lambda v: {0: 3, 1: level, 2: v})
        # a level outside the list is denied whatever the option
        for optname in (2, 26, 1 << 40):
            hits = matching(rules, {1: 0, 2: optname})
            self.assertEqual([h["action"] for h in hits], ["SCMP_ACT_ERRNO"])

    def test_known_dangerous_values_denied(self):
        p = self.profile(action="kill")
        cases = (("ioctl", {1: 0x5412}),            # TIOCSTI
                 ("ioctl", {1: 0xC0306401}),        # a DRM ioctl
                 ("prctl", {0: 35}),                # PR_SET_MM
                 ("prctl", {0: 0x53564D41}),        # PR_SET_VMA
                 ("prctl", {0: 59}),                # PR_SET_SYSCALL_USER_DISPATCH
                 ("setsockopt", {1: 1, 2: 26}),     # SO_ATTACH_FILTER
                 ("setsockopt", {1: 1, 2: 50}),     # SO_ATTACH_BPF
                 ("setsockopt", {1: 1, 2: 42}))     # SO_PEEK_OFF
        for name, args in cases:
            with self.subTest(name=name, args=args):
                hits = matching(rules_for(p, name), {0: 0, 1: 0, 2: 0, **args})
                self.assertEqual([h["action"] for h in hits], ["SCMP_ACT_KILL_PROCESS"])

    def test_measured_runtime_calls_allowed(self):
        p = self.profile()
        for name, args in (("ioctl", {1: 0x802C542A}), ("setsockopt", {1: 1, 2: 2}), ("setsockopt", {1: 1, 2: 20}),
                           ("setsockopt", {1: 1, 2: 21}), ("setsockopt", {1: 6, 2: 1}),
                           ("prctl", {0: 24}), ("prctl", {0: 8}),
                           ("prctl", {0: 51})):  # PR_SVE_GET_VL: what llama-server asks on aarch64
            with self.subTest(name=name, args=args):
                hits = matching(rules_for(p, name), {0: 0, 1: 0, 2: 0, **args})
                self.assertEqual([h["action"] for h in hits], ["SCMP_ACT_ALLOW"])

    def test_gpu_sandboxes_keep_the_base_rules(self):
        p = self.profile(cpu_only=False)
        for name in seccomp.ARG_FILTERED:
            self.assertFalse(any("allowlist" in r.get("comment", "") for r in rules_for(p, name)))

    def test_filtered_syscalls_have_no_unconditional_rule(self):
        for profile in (self.profile(), self.profile(action="kill")):
            for name in seccomp.ARG_FILTERED:
                rules = rules_for(profile, name)
                self.assertTrue(rules)
                for rule in rules:
                    self.assertTrue(rule.get("args"), f"{name} has a rule without argument conditions")

    def test_complement_rejects_wide_values(self):
        with self.assertRaises(ValueError):
            seccomp._complement(2, [1, 1 << 33])

    def test_no_rule_compares_an_argument_twice(self):
        # libseccomp evaluates both comparisons of a rule like `> a AND < b`. gVisor keeps one per
        # argument and silently drops the other, which widens a deny rule until it kills allowlisted
        # calls. A profile that never does it means the same thing to both.
        profiles = [self.profile(), self.profile(action="kill"), self.profile(cpu_only=False)]
        if SYSTEM_BASE.is_file():
            profiles.append(seccomp.harden(json.loads(SYSTEM_BASE.read_text()), machine="x86_64"))
        for profile in profiles:
            for rule in profile["syscalls"]:
                indexes = [arg["index"] for arg in rule.get("args") or []]
                self.assertEqual(len(indexes), len(set(indexes)), f"{rule['names']}: {rule.get('args')}")

    def test_same_verdict_if_an_engine_takes_the_first_matching_rule(self):
        # Disjoint rules make evaluation order irrelevant; this pins it for the calls that matter.
        p = self.profile(action="kill")
        cases = ((("setsockopt", {1: 1, 2: 2}), "SCMP_ACT_ALLOW"),       # SO_REUSEADDR: what llama-server does first
                 (("setsockopt", {1: 1, 2: 20}), "SCMP_ACT_ALLOW"),
                 (("setsockopt", {1: 6, 2: 1}), "SCMP_ACT_ALLOW"),
                 (("setsockopt", {1: 1, 2: 26}), "SCMP_ACT_KILL_PROCESS"),
                 (("setsockopt", {1: 3, 2: 2}), "SCMP_ACT_KILL_PROCESS"),
                 (("ioctl", {1: 0x541B}), "SCMP_ACT_ALLOW"),
                 (("ioctl", {1: 0x5412}), "SCMP_ACT_KILL_PROCESS"),
                 (("prctl", {0: 15}), "SCMP_ACT_ALLOW"),
                 (("prctl", {0: 35}), "SCMP_ACT_KILL_PROCESS"))
        for (name, args), verdict in cases:
            with self.subTest(name=name, args=args):
                first = next(r for r in rules_for(p, name)
                             if all(OPS[c["op"]](({0: 0, 1: 0, 2: 0} | args)[c["index"]], c) for c in r["args"]))
                self.assertEqual(first["action"], verdict)


if __name__ == "__main__":
    unittest.main()
