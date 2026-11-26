"""Seccomp profile generation.

Starts from the distro's container default (/usr/share/containers/seccomp.json, maintained upstream
as new syscalls appear) and tightens it for a hostile workload. The stock profile assumes a cooperative
workload and leans on user namespaces + dropped capabilities; it unconditionally allows unshare, clone3,
mount, ptrace, keyctl, socketcall and every socket family. For an LLM runtime we assume the process is
compromised, so:

  * sockets: AF_UNIX only, for socket() and socketpair(). No IP, netlink, packet, vsock, AF_ALG.
  * no network-filter bypasses: io_uring (does socket/connect itself), socketcall, and every
    non-native ABI (32-bit/x32 syscalls would dodge the per-arch rules).
  * no namespace creation: unshare/setns denied, clone(2) namespace flags denied, clone3 forced to
    ENOSYS (its flags live in a struct seccomp cannot read; libc then falls back to clone).
  * no cross-process access and none of the kernel interfaces that dominate container-escape CVEs:
    bpf, perf_event_open, userfaultfd, keyrings, mount API, ptrace, process_vm_*, pidfd_getfd ...
  * none of the standard kernel-exploitation primitives an inference server has no use for:
    SysV/POSIX message queues (msg_msg spraying), splice/vmsplice/tee, legacy AIO, remap_file_pages.
  * on CPU-only sandboxes, ioctl, prctl and setsockopt are limited to argument values an inference
    server uses (measured on llama-server, see ARG_ALLOWLISTS): no driver ioctls, no socket filters.

libseccomp detail this module depends on: an unconditional rule for a syscall silently wins over any
argument-filtered rule for the same syscall, whatever the action or order. So a syscall that needs
argument filtering must first be removed from the base profile entirely (REPLACED) and re-added with
conditions that are disjoint and exhaustive.

Portability rule this module keeps: no rule compares the same argument twice. gVisor, which also
enforces this profile when it is the sandbox's kernel, keeps one comparison per argument and drops
the rest without an error (see _complement).
"""

from __future__ import annotations

import copy
import json
import os
import platform
from pathlib import Path

AF_UNIX = 1
EPERM = 1
ENOSYS = 38
EAFNOSUPPORT = 97

NATIVE_ARCH = {"x86_64": "SCMP_ARCH_X86_64", "aarch64": "SCMP_ARCH_AARCH64"}

# clone(2) flags that create namespaces (flags are arg0 on x86_64 and aarch64).
CLONE_NS_FLAGS = {
    "CLONE_NEWTIME": 0x00000080,
    "CLONE_NEWNS": 0x00020000,
    "CLONE_NEWCGROUP": 0x02000000,
    "CLONE_NEWUTS": 0x04000000,
    "CLONE_NEWIPC": 0x08000000,
    "CLONE_NEWUSER": 0x10000000,
    "CLONE_NEWPID": 0x20000000,
    "CLONE_NEWNET": 0x40000000,
}
CLONE_NS_MASK = sum(CLONE_NS_FLAGS.values())

DENY: dict[str, str] = {
    # network-filter bypasses
    "socketcall": "32-bit socket multiplexer; args sit behind a pointer the AF_UNIX rule cannot read",
    "io_uring_setup": "io_uring performs socket/connect/openat without the filtered syscalls",
    "io_uring_enter": "io_uring (see io_uring_setup)",
    "io_uring_register": "io_uring (see io_uring_setup)",
    # namespaces and mounts: a nested user namespace re-grants a full capability set
    "unshare": "creates namespaces (nested userns => capabilities => netfilter/fs attack surface)",
    "setns": "joins namespaces",
    "mount": "mount API",
    "umount": "mount API",
    "umount2": "mount API",
    "pivot_root": "mount API",
    "chroot": "mount API",
    "move_mount": "new mount API",
    "open_tree": "new mount API",
    "fsopen": "new mount API",
    "fsconfig": "new mount API",
    "fsmount": "new mount API",
    "fspick": "new mount API",
    "mount_setattr": "new mount API",
    # cross-process access
    "ptrace": "process inspection/injection",
    "process_vm_readv": "reads another process's memory",
    "process_vm_writev": "writes another process's memory",
    "process_madvise": "acts on another process's memory",
    "pidfd_getfd": "steals file descriptors from another process",
    "kcmp": "cross-process kernel object comparison (KASLR/info leak primitive)",
    # kernel interfaces that dominate escape/LPE history
    "bpf": "eBPF verifier is a recurring LPE source",
    "perf_event_open": "perf subsystem LPEs and side channels",
    "userfaultfd": "classic race-widening primitive for kernel exploits",
    "keyctl": "kernel keyring",
    "add_key": "kernel keyring",
    "request_key": "kernel keyring",
    "fanotify_init": "filesystem-wide monitoring",
    "name_to_handle_at": "file handles (shocker-style escapes)",
    "open_by_handle_at": "file handles (shocker-style escapes)",
    "lookup_dcookie": "kernel profiling interface",
    "modify_ldt": "x86 LDT manipulation, historical LPE source",
    "uselib": "legacy loader",
    "vm86": "legacy",
    "vm86old": "legacy",
    "iopl": "raw I/O port access",
    "ioperm": "raw I/O port access",
    # host administration
    "kexec_load": "host administration",
    "kexec_file_load": "host administration",
    "init_module": "kernel modules",
    "finit_module": "kernel modules",
    "delete_module": "kernel modules",
    "reboot": "host administration",
    "swapon": "host administration",
    "swapoff": "host administration",
    "acct": "host administration",
    "quotactl": "host administration",
    "quotactl_fd": "host administration",
    "syslog": "kernel log (KASLR leaks)",
    "vhangup": "terminal control",
    "settimeofday": "host clock",
    "clock_settime": "host clock",
    # kernel-exploitation primitives with no role in inference
    "msgget": "SysV message queues: msg_msg is the standard kernel heap-spray / OOB-read object",
    "msgsnd": "SysV message queues (see msgget)",
    "msgrcv": "SysV message queues (see msgget)",
    "msgctl": "SysV message queues (see msgget)",
    "mq_open": "POSIX message queues",
    "mq_unlink": "POSIX message queues",
    "mq_timedsend": "POSIX message queues",
    "mq_timedreceive": "POSIX message queues",
    "mq_notify": "POSIX message queues (netlink-backed notification path)",
    "mq_getsetattr": "POSIX message queues",
    "mq_timedsend_time64": "POSIX message queues (32-bit time64 variant)",
    "mq_timedreceive_time64": "POSIX message queues (32-bit time64 variant)",
    "ipc": "32-bit SysV IPC multiplexer (reaches msgget & co behind one number)",
    "vmsplice": "maps user pages into pipes; recurring LPE primitive",
    "splice": "page-cache/pipe splicing (Dirty Pipe class)",
    "tee": "pipe buffer duplication (Dirty Pipe class)",
    "remap_file_pages": "deprecated nonlinear mappings",
    "io_setup": "legacy AIO: unneeded, recurring use-after-free source",
    "io_destroy": "legacy AIO",
    "io_submit": "legacy AIO",
    "io_cancel": "legacy AIO",
    "io_getevents": "legacy AIO",
    "io_pgetevents": "legacy AIO",
}

# Denied with ENOSYS even in "kill" mode, because libc probes them and falls back on ENOSYS.
FORCE_ENOSYS: dict[str, str] = {
    "clone3": "flags live in a struct seccomp cannot inspect; ENOSYS makes libc fall back to clone(2)",
}

# Denied only for CPU-only sandboxes: GPU userspace drivers may rely on it, llama.cpp on CPU does not.
# memfd_create + execveat is the standard fileless-execution path (run a dropped exploit binary
# without any writable+executable filesystem).
CPU_ONLY_DENY: dict[str, str] = {
    "memfd_create": "fileless execution of dropped binaries",
}

# Argument allowlists, applied on CPU-only sandboxes (GPU userspace drivers issue device ioctls that
# cannot be enumerated here). Each maps an argument index to the values allowed; everything else is
# denied. The values are what llama-server and the probe runner (CPython) were measured using under
# strace, plus a few read-only or self-directed operations that runtimes commonly issue.
# Numbers are the asm-generic ones, identical on x86_64 and aarch64.
IOCTL_ALLOW: dict[int, str] = {
    0x5401: "TCGETS: isatty() and terminal checks (ENOTTY on anything that is not a tty)",
    0x802C542A: "TCGETS2: isatty() in newer glibc",
    0x5413: "TIOCGWINSZ: terminal size queries",
    0x541B: "FIONREAD: bytes waiting on a socket or pipe",
    0x5421: "FIONBIO: non-blocking mode, handled generically in fs/ioctl.c",
    0x5450: "FIONCLEX: close-on-exec off, generic",
    0x5451: "FIOCLEX: close-on-exec on, generic (CPython's set_inheritable)",
}
PRCTL_ALLOW: dict[int, str] = {
    # crun runs these after loading the filter, while it drops capabilities before exec. Both only
    # shed privilege: the bounding set can only shrink, and KEEPCAPS matters for setuid transitions,
    # which no_new_privs and the empty capability set already rule out.
    24: "PR_CAPBSET_DROP (crun)", 8: "PR_SET_KEEPCAPS (crun)",
    1: "PR_SET_PDEATHSIG", 2: "PR_GET_PDEATHSIG", 3: "PR_GET_DUMPABLE",
    15: "PR_SET_NAME: thread names", 16: "PR_GET_NAME",
    21: "PR_GET_SECCOMP", 23: "PR_CAPBSET_READ", 30: "PR_GET_TIMERSLACK", 37: "PR_GET_CHILD_SUBREAPER",
    38: "PR_SET_NO_NEW_PRIVS (can only tighten)", 39: "PR_GET_NO_NEW_PRIVS", 42: "PR_GET_THP_DISABLE",
    52: "PR_GET_SPECULATION_CTRL",
}
SOL_SOCKET, IPPROTO_TCP = 1, 6
SETSOCKOPT_ALLOW: dict[int, dict[int, str]] = {
    SOL_SOCKET: {
        2: "SO_REUSEADDR (llama-server's listener)", 7: "SO_SNDBUF", 8: "SO_RCVBUF", 9: "SO_KEEPALIVE",
        13: "SO_LINGER", 20: "SO_RCVTIMEO_OLD (llama-server)", 21: "SO_SNDTIMEO_OLD (llama-server)",
        66: "SO_RCVTIMEO_NEW", 67: "SO_SNDTIMEO_NEW",
    },
    IPPROTO_TCP: {1: "TCP_NODELAY (llama-server sets it; on AF_UNIX the kernel answers EOPNOTSUPP)"},
}
ARG_FILTERED = {"ioctl", "prctl", "setsockopt"}

# Removed from the base profile and re-added below with silo's own argument conditions.
REPLACED = {"socket", "socketpair", "clone"}


def _deny(action: str, errno: int) -> dict:
    if action == "kill":
        return {"action": "SCMP_ACT_KILL_PROCESS"}
    return {"action": "SCMP_ACT_ERRNO", "errnoRet": errno}


def _arg(index: int, value: int, op: str, value_two: int = 0) -> dict:
    return {"index": index, "value": value, "valueTwo": value_two, "op": op}


U32 = 0xFFFFFFFF


def _complement(index: int, values) -> list[list[dict]]:
    """Conditions that together match every 64-bit value of one argument except `values`.

    Each is a single comparison, so that a rule never compares the same argument twice. That matters
    beyond style: libseccomp evaluates both comparisons of a range like `> a AND < b`, but gVisor's
    conversion of an OCI profile keeps one comparison per argument and silently drops the other,
    which turns such a deny rule into `< b` and kills calls that are on the allowlist. libseccomp 2.6
    also refuses (EEXIST) several range rules behind a shared condition on another argument.

    So the complement is written as aligned bit-prefix blocks of the low 32 bits (masked equality,
    like the CIDR blocks that cover every address but a few), plus one rule for any value with upper
    bits set. Together with the equality rules for `values` they are disjoint and exhaustive.
    """
    vals = sorted(set(values))
    if any(v > U32 for v in vals):
        raise ValueError("allowlists cover 32-bit values")
    if len(vals) == 1:
        return [[_arg(index, vals[0], "SCMP_CMP_NE")]]
    out = [[_arg(index, U32, "SCMP_CMP_GT")]]

    def walk(depth: int, prefix: int, members: list[int]) -> None:
        if not members:
            mask = (((1 << depth) - 1) << (32 - depth)) | (U32 << 32)
            out.append([_arg(index, mask, "SCMP_CMP_MASKED_EQ", prefix)])
            return
        if depth == 32:
            return
        bit = 31 - depth
        walk(depth + 1, prefix, [v for v in members if not v >> bit & 1])
        walk(depth + 1, prefix | 1 << bit, [v for v in members if v >> bit & 1])

    walk(0, 0, vals)
    return out


def _allowlist_rules(name: str, index: int, values, deny: dict, prefix: tuple = (), label: str = "") -> list[dict]:
    """Allow rules for `values` of one argument, then deny rules for everything else."""
    allow = [{"names": [name], "action": "SCMP_ACT_ALLOW", "args": [*prefix, _arg(index, v, "SCMP_CMP_EQ")],
              "comment": f"silo: {name}{label} allowlist"} for v in sorted(values)]
    denied = [{"names": [name], **deny, "args": [*prefix, *condition],
               "comment": f"silo: {name}{label} not allowlisted"} for condition in _complement(index, values)]
    return allow + denied


def argument_rules(action: str) -> list[dict]:
    """The ioctl / prctl / setsockopt rules for a CPU-only sandbox."""
    deny = _deny(action, EPERM)
    rules = _allowlist_rules("ioctl", 1, IOCTL_ALLOW, deny)
    rules += _allowlist_rules("prctl", 0, PRCTL_ALLOW, deny)
    # Allow rules come before deny rules for each syscall. With disjoint rules the order means nothing,
    # but an engine that evaluated them first-match would then at worst allow what is allowlisted.
    for level, names in SETSOCKOPT_ALLOW.items():
        rules += _allowlist_rules("setsockopt", 2, names, deny, prefix=(_arg(1, level, "SCMP_CMP_EQ"),),
                                  label=f" level {level}")
    rules += [{"names": ["setsockopt"], **deny, "args": condition, "comment": "silo: setsockopt level not allowlisted"}
              for condition in _complement(1, SETSOCKOPT_ALLOW)]
    return rules


def harden(base: dict, machine: str | None = None, action: str = "errno", cpu_only: bool = True) -> dict:
    """Return a hardened copy of an OCI/containers seccomp profile."""
    if action not in ("errno", "kill"):
        raise ValueError("action must be 'errno' or 'kill'")
    machine = machine or platform.machine()
    try:
        arch = NATIVE_ARCH[machine]
    except KeyError:
        raise ValueError(f"unsupported architecture {machine!r} (supported: {', '.join(NATIVE_ARCH)})")

    profile = copy.deepcopy(base)
    profile.pop("architectures", None)
    # Native ABI only: any foreign-ABI syscall hits libseccomp's bad-arch action (kill).
    profile["archMap"] = [{"architecture": arch, "subArchitectures": []}]
    profile["defaultAction"] = "SCMP_ACT_ERRNO"
    profile["defaultErrnoRet"] = ENOSYS

    deny = dict(DENY, **(CPU_ONLY_DENY if cpu_only else {}))
    strip = set(deny) | set(FORCE_ENOSYS) | REPLACED | (ARG_FILTERED if cpu_only else set())
    rules = []
    for rule in profile.get("syscalls", []):
        names = [n for n in rule.get("names", []) if n not in strip]
        if names:
            rules.append({**rule, "names": names})

    # Allow-on-equal is safe against the 64-bit/32-bit argument mismatch: the kernel truncates the
    # family to an int, but a 64-bit value that equals 1 also has low 32 bits equal to 1.
    rules.append({
        "names": ["socket", "socketpair"],
        "action": "SCMP_ACT_ALLOW",
        "args": [_arg(0, AF_UNIX, "SCMP_CMP_EQ")],
        "comment": "silo: AF_UNIX is the only socket family",
    })
    rules.append({
        "names": ["socket", "socketpair"],
        **_deny(action, EAFNOSUPPORT),
        "args": [_arg(0, AF_UNIX, "SCMP_CMP_NE")],
        "comment": "silo: no IP/netlink/packet/vsock/alg/tipc sockets (also stops family module autoload)",
    })
    rules.append({
        "names": ["clone"],
        "action": "SCMP_ACT_ALLOW",
        # (flags & mask) == 0  -> threads and plain forks only
        "args": [_arg(0, CLONE_NS_MASK, "SCMP_CMP_MASKED_EQ", 0)],
        "comment": "silo: clone without namespace flags",
    })
    for flag_name, bit in CLONE_NS_FLAGS.items():
        rules.append({
            "names": ["clone"],
            **_deny(action, EPERM),
            "args": [_arg(0, bit, "SCMP_CMP_MASKED_EQ", bit)],
            "comment": f"silo: clone with {flag_name}",
        })
    if cpu_only:
        rules.extend(argument_rules(action))
    rules.append({
        "names": sorted(deny),
        **_deny(action, EPERM),
        "comment": "silo: denied syscalls (see silo/seccomp.py for rationale)",
    })
    rules.append({
        "names": sorted(FORCE_ENOSYS),
        "action": "SCMP_ACT_ERRNO",
        "errnoRet": ENOSYS,
        "comment": "silo: force libc fallback to filterable syscalls",
    })
    profile["syscalls"] = rules
    return profile


def allowed_unconditionally(profile: dict) -> set[str]:
    """Syscall names the profile allows with no argument or capability conditions."""
    out: set[str] = set()
    for rule in profile.get("syscalls", []):
        if rule.get("action") != "SCMP_ACT_ALLOW" or rule.get("args"):
            continue
        if rule.get("includes") or rule.get("excludes"):
            continue
        out.update(rule.get("names", []))
    return out


def write_profile(base_path: Path, out_path: Path, action: str = "errno", cpu_only: bool = True) -> Path:
    base = json.loads(base_path.read_text())
    profile = harden(base, action=action, cpu_only=cpu_only)
    out_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = out_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(profile, indent=2) + "\n")
    os.chmod(tmp, 0o644)
    tmp.replace(out_path)
    return out_path
