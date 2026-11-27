#!/usr/bin/env python3
"""silo escape probes.

Runs INSIDE a sandbox (stdlib only, fed to `python3 -I -` on stdin) and attempts the things a
compromised model runtime would try: reach the network, open exotic socket families, create
namespaces, touch kernel attack surface, write persistence, find host sockets and secrets.

Every probe reports one of (INFO lines are context, not results):
  PASS  the attempt was contained
  FAIL  a boundary is missing: egress worked, or a dangerous kernel interface is reachable
  WARN  not an escape by itself, but weaker than silo's intended posture
  SKIP  not applicable on this architecture / image

Syscall probes run in a forked child with an alarm, so a SECCOMP_RET_KILL (seccomp_action="kill")
or a hang is recorded instead of taking the whole run down.
"""

import ctypes
import errno
import glob
import json
import mmap
import os
import platform
import signal
import socket
import subprocess
import sys

MACHINE = platform.machine()
RESULTS = []
# The launcher passes --gvisor for sandboxes on gVisor (runtime.runsc). There, cgroups, /dev and the TTY
# layer are gVisor's own emulation and host LSMs do not apply; the probes report that instead of
# treating it as the host's. The flag is only honoured if the kernel really is gVisor (kernel.gvisor).
GVISOR_REQUESTED = "--gvisor" in sys.argv[1:]
GVISOR = GVISOR_REQUESTED and "gvisor" in platform.release().lower()
GVISOR_DEV = {"fuse", "net", "char"}  # emulated inside gVisor's kernel, not host devices
# The launcher passes --no-exec-lock when execve is not decided by silo's supervisor: switched off in
# silo.toml, or a gVisor sandbox, where the kernel feature behind it does not exist.
EXEC_LOCK = "--no-exec-lock" not in sys.argv[1:]
# The launcher passes --gpu when the sandbox has GPU passthrough: the argument allowlists for ioctl,
# prctl and setsockopt are then not applied (GPU drivers need device ioctls), which is reported as WARN.
GPU = "--gpu" in sys.argv[1:]

SYSNR = {
    "x86_64": {
        "socket": 41, "ptrace": 101, "mount": 165, "keyctl": 250, "add_key": 248, "unshare": 272,
        "perf_event_open": 298, "open_by_handle_at": 304, "setns": 308, "process_vm_readv": 310,
        "bpf": 321, "userfaultfd": 323, "socketpair": 53, "msgget": 68, "io_setup": 206,
        "remap_file_pages": 216, "mq_open": 240, "splice": 275, "vmsplice": 278,
        "ioctl": 16, "prctl": 157, "setsockopt": 54, "clone": 56, "sendfile": 40, "seccomp": 317,
    },
    "aarch64": {
        "socket": 198, "ptrace": 117, "mount": 40, "keyctl": 219, "add_key": 217, "unshare": 97,
        "perf_event_open": 241, "open_by_handle_at": 265, "setns": 268, "process_vm_readv": 270,
        "bpf": 280, "userfaultfd": 282, "socketpair": 199, "msgget": 186, "io_setup": 0,
        "remap_file_pages": 234, "mq_open": 180, "splice": 76, "vmsplice": 75,
        "ioctl": 29, "prctl": 167, "setsockopt": 208, "clone": 220, "sendfile": 71, "seccomp": 277,
    },
}
# Unified numbering for syscalls added after 5.1 (same on every architecture).
COMMON_NR = {"io_uring_setup": 425, "open_tree": 428, "fsopen": 430, "clone3": 435, "pidfd_getfd": 438}

# Errnos that mean "refused before reaching the interesting kernel code".
REFUSED = {errno.EPERM, errno.EACCES, errno.ENOSYS, errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT}

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def record(probe, status, detail):
    entry = {"probe": probe, "status": status, "detail": detail}
    RESULTS.append(entry)
    print(json.dumps(entry), flush=True)


def in_child(fn, timeout=8):
    """Run fn() in a forked child. Returns ("ok", value) | ("signal", signum) | ("error", text)."""
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        os.close(rfd)
        signal.alarm(timeout)
        try:
            payload = ["ok", fn()]
        except BaseException as exc:  # noqa: BLE001 - report anything
            payload = ["error", f"{type(exc).__name__}: {exc}"]
        os.write(wfd, json.dumps(payload).encode())
        os._exit(0)
    os.close(wfd)
    chunks = []
    while True:
        chunk = os.read(rfd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(rfd)
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return ("signal", os.WTERMSIG(status))
    data = b"".join(chunks)
    return tuple(json.loads(data)) if data else ("error", "child produced no output")


def raw_syscall(nr, *args):
    ctypes.set_errno(0)
    ret = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) for a in args])
    return [ret, ctypes.get_errno()]


def describe(kind, value):
    """Human-readable form of an in_child() outcome that did not succeed."""
    if kind == "signal":
        if value == signal.SIGSYS:
            return "process killed by seccomp (SIGSYS)"
        if value == signal.SIGALRM:
            return "timed out"
        return f"child died with signal {value}"
    return str(value)


def judge_syscall(probe, outcome, what, fail_as="FAIL", note=""):
    kind, value = outcome
    if kind == "signal":
        sig = signal.Signals(value).name if value in signal.Signals._value2member_map_ else value
        if value == signal.SIGSYS:
            return record(probe, "PASS", f"{what}: process killed by seccomp (SIGSYS)")
        if value == signal.SIGALRM:
            return record(probe, "WARN", f"{what}: timed out")
        return record(probe, "WARN", f"{what}: child died with {sig}")
    if kind == "error":
        return record(probe, "WARN", f"{what}: probe error {value}")
    ret, err = value
    if ret >= 0:
        return record(probe, fail_as, f"{what}: succeeded (ret={ret}){note}")
    if err in REFUSED:
        return record(probe, "PASS", f"{what}: refused ({errno.errorcode.get(err, err)})")
    return record(probe, fail_as, f"{what}: reached the kernel (errno {errno.errorcode.get(err, err)}){note}")


def nr(name):
    if name in COMMON_NR:
        return COMMON_NR[name]
    return SYSNR.get(MACHINE, {}).get(name)


# --------------------------------------------------------------------------------------------- net

def probe_interfaces():
    try:
        ifaces = sorted(os.listdir("/sys/class/net"))
    except OSError as exc:
        return record("net.interfaces", "PASS", f"/sys/class/net unreadable ({exc.strerror})")
    extra = [i for i in ifaces if i != "lo"]
    if extra:
        return record("net.interfaces", "FAIL", f"network interfaces present: {extra}")
    record("net.interfaces", "PASS", f"interfaces: {ifaces}")


def probe_routes():
    try:
        with open("/proc/net/route") as fh:
            rows = fh.read().splitlines()[1:]
    except OSError as exc:
        return record("net.routes", "PASS", f"/proc/net/route unreadable ({exc.strerror})")
    defaults = [r for r in rows if r.split()[1:2] == ["00000000"]]
    if defaults:
        return record("net.routes", "FAIL", f"default route present: {defaults[0].split()[0]}")
    record("net.routes", "PASS", f"{len(rows)} IPv4 routes, no default route")


SOCKET_FAMILIES = [
    ("AF_INET", 2, socket.SOCK_STREAM, 0),
    ("AF_INET6", 10, socket.SOCK_STREAM, 0),
    ("AF_INET/raw", 2, socket.SOCK_RAW, 1),
    ("AF_NETLINK", 16, socket.SOCK_RAW, 0),
    ("AF_PACKET", 17, socket.SOCK_RAW, 0),
    ("AF_VSOCK", 40, socket.SOCK_STREAM, 0),
    ("AF_ALG", 38, socket.SOCK_SEQPACKET, 0),
    ("AF_XDP", 44, socket.SOCK_RAW, 0),
    ("AF_BLUETOOTH", 31, socket.SOCK_STREAM, 0),
    ("AF_CAN", 29, socket.SOCK_RAW, 1),
    ("AF_TIPC", 30, socket.SOCK_RDM, 0),
    ("AF_RDS", 21, socket.SOCK_SEQPACKET, 0),
]


def probe_socket_families():
    socket_nr = nr("socket")
    for label, fam, typ, proto in SOCKET_FAMILIES:
        if socket_nr is None:
            record(f"net.socket.{label}", "SKIP", f"no syscall table for {MACHINE}")
            continue
        outcome = in_child(lambda: raw_syscall(socket_nr, fam, typ, proto))
        if outcome[0] == "ok" and outcome[1][0] < 0 and outcome[1][1] in (errno.EINVAL, errno.ESOCKTNOSUPPORT):
            # family exists in kernel but rejected this socket type: still reachable code
            record(f"net.socket.{label}", "FAIL", f"socket({label}) reached the kernel (errno {outcome[1][1]})")
            continue
        judge_syscall(f"net.socket.{label}", outcome, f"socket({label})")


def probe_socketpair():
    # socketpair() is a second way to instantiate a socket family (and to trigger its module autoload).
    number = nr("socketpair")
    if number is None:
        return record("net.socketpair", "SKIP", f"no syscall table for {MACHINE}")
    pair = (ctypes.c_int * 2)()
    for label, fam, typ in (("AF_INET", 2, socket.SOCK_STREAM), ("AF_TIPC", 30, socket.SOCK_DGRAM)):
        outcome = in_child(lambda: raw_syscall(number, fam, typ, 0, ctypes.addressof(pair)))
        judge_syscall(f"net.socketpair.{label}", outcome, f"socketpair({label})")
    try:
        a, b = socket.socketpair()
        a.close()
        b.close()
        record("net.socketpair.AF_UNIX", "PASS", "AF_UNIX socketpair works (the one family the sandbox needs)")
    except OSError as exc:
        record("net.socketpair.AF_UNIX", "WARN", f"AF_UNIX socketpair unavailable ({exc.strerror})")


def probe_dns():
    def resolve():
        return [ai[4][0] for ai in socket.getaddrinfo("example.com", 443, proto=socket.IPPROTO_TCP)]
    kind, value = in_child(resolve, timeout=10)
    if kind == "ok":
        return record("net.dns", "FAIL", f"resolved example.com -> {value[:3]}")
    record("net.dns", "PASS", f"resolution failed ({describe(kind, value)})")


def probe_tcp_egress():
    def connect():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect(("1.1.1.1", 443))
        return s.getsockname()[0]
    kind, value = in_child(connect, timeout=8)
    if kind == "ok":
        return record("net.tcp_egress", "FAIL", f"connected to 1.1.1.1:443 from {value}")
    record("net.tcp_egress", "PASS", f"no route out ({describe(kind, value)})")


def probe_abstract_unix():
    # Abstract sockets are scoped to the network namespace; host ones (X11, dbus, systemd) must be invisible.
    targets = ["\0/tmp/.X11-unix/X0", "\0/tmp/.X11-unix/X1", "\0/org/freedesktop/systemd1/notify"]
    reached = []
    for target in targets:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect(target)
            reached.append(target.replace("\0", "@"))
        except OSError:
            pass
        finally:
            s.close()
    if reached:
        return record("net.abstract_unix", "FAIL", f"host abstract sockets reachable: {reached}")
    record("net.abstract_unix", "PASS", "no host abstract sockets reachable")


# ---------------------------------------------------------------------------- seccomp / kernel ABI

def probe_syscalls():
    cases = [
        ("io_uring_setup", (0, 0), "io_uring (bypasses socket filtering)"),
        ("unshare", (0x10000000,), "unshare(CLONE_NEWUSER)"),
        ("setns", (-1, 0), "setns"),
        ("clone3", (0, 0), "clone3 (uninspectable flags)"),
        ("mount", (0, 0, 0, 0, 0), "mount"),
        ("fsopen", (0, 0), "fsopen (new mount API)"),
        ("open_tree", (-1, 0, 0), "open_tree (new mount API)"),
        ("ptrace", (0, 0, 0, 0), "ptrace(PTRACE_TRACEME)"),
        ("process_vm_readv", (1, 0, 0, 0, 0, 0), "process_vm_readv"),
        ("pidfd_getfd", (-1, 0, 0), "pidfd_getfd"),
        ("bpf", (0, 0, 0), "bpf"),
        ("perf_event_open", (0, 0, -1, -1, 0), "perf_event_open"),
        ("userfaultfd", (1,), "userfaultfd(UFFD_USER_MODE_ONLY), which needs no privilege"),
        ("keyctl", (0, -3, 0), "keyctl(GET_KEYRING_ID)"),
        ("add_key", (0, 0, 0, 0, 0), "add_key"),
        ("open_by_handle_at", (-1, 0, 0), "open_by_handle_at"),
        ("msgget", (0, 0o600), "msgget (msg_msg heap-spray primitive)"),
        ("mq_open", (0, 0, 0, 0), "mq_open"),
        ("splice", (-1, 0, -1, 0, 0, 0), "splice"),
        ("vmsplice", (-1, 0, 0, 0), "vmsplice"),
        ("io_setup", (1, 0), "io_setup (legacy AIO)"),
        ("remap_file_pages", (0, 0, 0, 0, 0), "remap_file_pages"),
        # loading a classic BPF program into the kernel; flags 0 with no program: EFAULT if reached
        ("seccomp", (1, 0, 0), "seccomp(SECCOMP_SET_MODE_FILTER)"),
        ("sendfile", (-1, -1, 0, 1), "sendfile (zero-copy into pipes, like splice)"),
    ]
    for name, args, what in cases:
        number = nr(name)
        if number is None:
            record(f"sys.{name}", "SKIP", f"no syscall number for {MACHINE}")
            continue
        judge_syscall(f"sys.{name}", in_child(lambda: raw_syscall(number, *args)), what)


def probe_clone_newuser():
    # The clone(2) flag filter itself: no other probe issues clone with a namespace flag.
    def clone_newuser():
        ret, err = raw_syscall(nr("clone"), 0x10000000 | signal.SIGCHLD, 0, 0, 0, 0)  # CLONE_NEWUSER
        if ret == 0:
            os._exit(0)  # the child, in a new user namespace: proof enough, leave at once
        if ret > 0:
            os.waitpid(ret, 0)
        return [ret, err]
    judge_syscall("sys.clone_newuser", in_child(clone_newuser), "clone(CLONE_NEWUSER)")

    # Python's os.fork uses clone without namespace flags; exercise the flag filter directly via libc.
    if not hasattr(os, "unshare"):
        def via_libc():
            ctypes.set_errno(0)
            return [libc.unshare(0x10000000), ctypes.get_errno()]
    else:
        def via_libc():
            try:
                os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)
                return [0, 0]
            except OSError as exc:
                return [-1, exc.errno]
    judge_syscall("sys.userns_via_libc", in_child(via_libc), "unshare(CLONE_NEWUSER|CLONE_NEWNET) via libc")


def probe_compat_abi():
    if MACHINE != "x86_64":
        return record("abi.compat", "SKIP", f"compat-ABI probes are x86_64-only (on {MACHINE})")

    # x32 ABI: syscall number with bit 30 set. Must be killed or refused, never executed.
    x32 = in_child(lambda: raw_syscall(0x40000000 | 41, 2, 1, 0))
    judge_syscall("abi.x32_socket", x32, "x32 socket(AF_INET)")

    # i386 ABI via int 0x80 from a 64-bit process: socket(AF_INET, SOCK_STREAM, 0) = i386 nr 359.
    # A classic seccomp bypass when a profile only covers the native table.
    code = bytes([
        0x53,                          # push rbx
        0xB8, 0x67, 0x01, 0x00, 0x00,  # mov eax, 359
        0xBB, 0x02, 0x00, 0x00, 0x00,  # mov ebx, 2   (AF_INET)
        0xB9, 0x01, 0x00, 0x00, 0x00,  # mov ecx, 1   (SOCK_STREAM)
        0x31, 0xD2,                    # xor edx, edx
        0xCD, 0x80,                    # int 0x80
        0x5B,                          # pop rbx
        0xC3,                          # ret
    ])

    def int80():
        buf = mmap.mmap(-1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        buf.write(code)
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        ret = ctypes.CFUNCTYPE(ctypes.c_int)(addr)()
        return [ret, -ret if ret < 0 else 0]

    kind, value = in_child(int80)
    if kind == "error" and ("PermissionError" in value or "mmap" in value):
        return record("abi.i386_int80_socket", "PASS", f"cannot map executable memory ({value})")
    if kind == "signal" and value == signal.SIGSEGV:
        # The only instruction in that stub that can fault is `int 0x80` itself: there is no gate for
        # the vector. That is a kernel without 32-bit emulation, or gVisor on its KVM platform. Either
        # way the i386 syscall table cannot be reached at all.
        return record("abi.i386_int80_socket", "PASS",
                      "int 0x80 faults (SIGSEGV): this kernel has no i386 syscall entry point")
    judge_syscall("abi.i386_int80_socket", (kind, value), "i386 int 0x80 socket(AF_INET)")


# -------------------------------------------------------------------------------------- filesystem

def try_write(path):
    try:
        with open(path, "w") as fh:
            fh.write("silo-probe")
        os.unlink(path)
        return None
    except OSError as exc:
        return exc


def probe_readonly():
    for probe, path in (("fs.rootfs_readonly", "/etc/silo-probe"),
                        ("fs.usr_readonly", "/usr/local/bin/silo-probe"),
                        ("fs.models_readonly", "/models/silo-probe")):
        if probe == "fs.models_readonly" and not os.path.isdir("/models"):
            record(probe, "SKIP", "/models not mounted")
            continue
        err = try_write(path)
        if err is None:
            record(probe, "FAIL", f"wrote {path}")
        else:
            record(probe, "PASS", f"write to {path} refused ({err.strerror})")


# Kernel-provided filesystems that cannot be a host directory.
PSEUDO_FILESYSTEMS = ("proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue")
# gVisor sandboxes only: where the one shared directory, for the runtime's socket, is mounted.
SOCKET_DIR = "/run/silo"


def shared_writable_dirs(mountinfo, isdir=os.path.isdir):
    """Mount points of writable directory mounts outside the sandbox's own scratch set.

    Whatever the filesystem: a host directory under /run/user is tmpfs too, so the type says nothing
    about where a mount comes from. Device nodes and single files are not directories; they are
    judged by dev.nodes and fs.unexpected_rw_mounts.
    """
    found = []
    for line in mountinfo:
        fields = line.split()
        target, opts = fields[4], fields[5].split(",")
        fstype = fields[fields.index("-") + 1] if "-" in fields else ""
        if "rw" in opts and target not in EXPECTED_RW_MOUNTS and fstype not in PSEUDO_FILESYSTEMS and isdir(target):
            found.append(target)
    return found


def probe_socket_dir():
    # The runtime answers on an abstract UNIX socket inside its own network namespace; the gateway
    # reaches it through silo's connector. No host directory is mounted into the sandbox writable.
    #
    # gVisor sandboxes are the exception: abstract sockets stay inside gVisor's kernel, so one
    # directory is shared for the runtime's socket. silo locks it once the socket is bound, and the
    # probes get it in that locked state.
    try:
        with open("/proc/self/mountinfo") as fh:
            host_mounts = shared_writable_dirs(fh)
    except (OSError, IndexError, ValueError) as exc:
        return record("fs.no_shared_dir", "WARN", f"cannot read the mount table ({exc})")
    socket_dir = GVISOR and SOCKET_DIR in host_mounts
    if socket_dir:
        host_mounts.remove(SOCKET_DIR)
    if host_mounts:
        record("fs.no_shared_dir", "FAIL", f"host directories mounted writable: {host_mounts}")
    elif socket_dir:
        record("fs.no_shared_dir", "PASS", "the socket directory is the only host directory mounted writable")
    else:
        record("fs.no_shared_dir", "PASS", "no host directory is mounted writable (the runtime socket is abstract)")
    if not GVISOR:
        return
    if not socket_dir:
        return record("fs.socket_dir_locked", "SKIP", f"{SOCKET_DIR} is not mounted")
    err = try_write(f"{SOCKET_DIR}/silo-probe")
    if err is None:
        return record("fs.socket_dir_locked", "FAIL", "sandbox can create files in the shared socket directory")
    try:
        os.symlink(f"{SOCKET_DIR}/elsewhere", f"{SOCKET_DIR}/llama.sock")
        os.unlink(f"{SOCKET_DIR}/llama.sock")
        return record("fs.socket_dir_locked", "FAIL", "sandbox can plant a symlink at the socket path")
    except OSError:
        pass
    record("fs.socket_dir_locked", "PASS", f"shared socket directory is not writable ({err.strerror})")


def writable_dirs():
    """Every directory on a distinct mount (plus the usual scratch paths) the sandbox user can write to."""
    candidates = {"/tmp", "/var/tmp", "/dev/shm", "/dev/mqueue", "/run", "/run/silo", "/models", "/"}
    try:
        with open("/proc/self/mountinfo") as fh:
            candidates.update(line.split()[4] for line in fh)
    except OSError:
        pass
    found = []
    for path in sorted(candidates):
        if os.path.isdir(path) and try_write(os.path.join(path, ".silo-probe-w")) is None:
            found.append(path)
    return found


def mount_options(path, mountinfo=None):
    """Options of the mount that holds `path`: the longest matching mount point, the last one mounted there."""
    best, options = "", set()
    try:
        lines = mountinfo if mountinfo is not None else open("/proc/self/mountinfo").read().splitlines()
        for line in lines:
            fields = line.split()
            target = fields[4]
            if (path == target or path.startswith(target.rstrip("/") + "/")) and len(target) >= len(best):
                best, options = target, set(fields[5].split(","))
    except (OSError, IndexError):
        pass
    return options


def probe_tmp_noexec():
    # Dropping a binary and running it needs a place that is both writable and executable.
    dirs = writable_dirs()
    if not dirs:
        return record("fs.writable_noexec", "PASS", "no writable directory at all")
    executable = []
    for directory in dirs:
        path = os.path.join(directory, "silo-probe.sh")
        try:
            with open(path, "w") as fh:
                fh.write("#!/bin/sh\nexit 42\n")
            os.chmod(path, 0o755)
            # Only its own exit status proves that it ran: a child killed on the way (seccomp or the
            # exec lock in kill mode) returns a signal number, and a refused execve raises.
            if subprocess.run([path], capture_output=True, timeout=5).returncode == 42:
                executable.append(directory)
        except (OSError, subprocess.SubprocessError):
            pass
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
    if executable:
        return record("fs.writable_noexec", "FAIL", f"writable and executable: {executable}")
    # Running the file can also have been refused by the exec lock, which refuses everything. The
    # mount flag is the layer under it, so it is checked by itself.
    unflagged = [d for d in dirs if "noexec" not in mount_options(d)]
    if unflagged:
        return record("fs.writable_noexec", "WARN", f"writable locations without noexec: {unflagged} "
                                                    "(a file dropped there did not run, but not because of the mount)")
    record("fs.writable_noexec", "PASS", f"writable locations {dirs} are all noexec")


def probe_memfd_exec():
    # Fileless execution: copy a binary into an anonymous memfd and exec it.
    source = next((p for p in ("/bin/true", "/usr/bin/true") if os.path.exists(p)), None)
    if not source or not hasattr(os, "memfd_create"):
        return record("fs.memfd_exec", "SKIP", "no /bin/true or memfd_create")

    def attempt():
        try:
            fd = os.memfd_create("silo-probe", 0)
        except OSError as exc:
            return ["memfd_refused", errno.errorcode.get(exc.errno, exc.errno)]
        with open(source, "rb") as fh:
            os.write(fd, fh.read())
        try:
            rc = subprocess.run([f"/proc/self/fd/{fd}"], pass_fds=(fd,), timeout=5).returncode
        except OSError as exc:
            return ["exec_refused", errno.errorcode.get(exc.errno, exc.errno)]
        if rc < 0:  # killed on its way into execve (the exec lock in kill mode): the copy never ran
            return ["exec_killed", signal.Signals(-rc).name]
        return ["executed", rc]

    kind, value = in_child(attempt)
    if kind == "signal" and value == signal.SIGSYS:
        return record("fs.memfd_exec", "PASS", "memfd_create: process killed by seccomp (SIGSYS)")
    if kind != "ok":
        return record("fs.memfd_exec", "WARN", f"probe error: {value}")
    outcome, info = value
    if outcome == "executed":
        return record("fs.memfd_exec", "WARN",
                      f"fileless exec via memfd works (rc={info}); host sysctl vm.memfd_noexec=1 restricts it")
    record("fs.memfd_exec", "PASS", f"{outcome.replace('_', ' ')} ({info})")


EXPECTED_RW_MOUNTS = {"/tmp", "/dev", "/dev/shm", "/dev/pts", "/dev/mqueue", "/proc",
                      "/sys/fs/cgroup", "/run/.containerenv", "/etc/hostname", "/etc/resolv.conf",
                      # rootless podman cannot mknod, so these are bind mounts of the host's nodes
                      "/dev/null", "/dev/zero", "/dev/full", "/dev/tty", "/dev/random", "/dev/urandom",
                      "/dev/console"}


def _gvisor_expected(mountpoint):
    """On gVisor: its emulated cgroup controllers under /sys/fs/cgroup, and the socket directory."""
    return GVISOR and (mountpoint.startswith("/sys/fs/cgroup/") or mountpoint == SOCKET_DIR)


def probe_mounts():
    rw = []
    with open("/proc/self/mountinfo") as fh:
        for line in fh:
            parts = line.split()
            mountpoint, opts = parts[4], parts[5].split(",")
            if "rw" in opts and mountpoint not in EXPECTED_RW_MOUNTS and not _gvisor_expected(mountpoint):
                rw.append(mountpoint)
    if rw:
        return record("fs.unexpected_rw_mounts", "WARN", f"writable mounts: {rw}")
    record("fs.unexpected_rw_mounts", "PASS", "only expected scratch mounts are writable")


HOST_SOCKETS = [
    "/run/podman/podman.sock", "/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
    "/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket", "/run/systemd/private",
    "/run/systemd/journal/socket", "/dev/log", "/run/user/*/bus", "/run/user/*/podman/podman.sock",
    "/run/user/*/wayland-*", "/run/user/*/pipewire-*", "/tmp/.X11-unix/*", "/run/user/*/keyring/*",
    "/run/user/*/gnupg/*", "/tmp/ssh-*/agent.*",
]
HOST_SECRETS = ["/home/*/.ssh", "/root/.ssh", "/home/*/.aws", "/home/*/.config/gh", "/home/*/.gnupg",
                "/home/*/.docker/config.json", "/home/*/.cache/huggingface/token", "/home/*/.kube"]


def probe_host_artifacts():
    found = [p for pattern in HOST_SOCKETS for p in glob.glob(pattern)]
    if found:
        record("host.sockets", "FAIL", f"host IPC sockets visible: {found}")
    else:
        record("host.sockets", "PASS", "no container-engine, dbus, display, audio or agent sockets visible")
    secrets = [p for pattern in HOST_SECRETS for p in glob.glob(pattern)]
    if secrets:
        record("host.secrets", "FAIL", f"host credential paths visible: {secrets}")
    else:
        record("host.secrets", "PASS", "no host home directories or credential stores visible")


# ----------------------------------------------------------------------------- process credentials

def status_fields():
    out = {}
    with open("/proc/self/status") as fh:
        for line in fh:
            key, _, value = line.partition(":")
            out[key] = value.strip()
    return out


def probe_credentials():
    st = status_fields()
    if os.getuid() == 0:
        record("proc.uid", "WARN", "running as uid 0 inside the container")
    else:
        record("proc.uid", "PASS", f"uid={os.getuid()} gid={os.getgid()}")
    eff, bnd = int(st.get("CapEff", "0"), 16), int(st.get("CapBnd", "0"), 16)
    if eff:
        record("proc.capabilities", "FAIL", f"effective capabilities present: {eff:#x}")
    elif bnd:
        record("proc.capabilities", "WARN", f"no effective caps, but bounding set is {bnd:#x}")
    else:
        record("proc.capabilities", "PASS", "effective and bounding capability sets are empty")
    record("proc.no_new_privs", "PASS" if st.get("NoNewPrivs") == "1" else "FAIL",
           f"NoNewPrivs={st.get('NoNewPrivs')}")
    record("proc.seccomp", "PASS" if st.get("Seccomp") == "2" else "FAIL",
           f"Seccomp={st.get('Seccomp')} filters={st.get('Seccomp_filters')}")


def probe_pid_namespace():
    pids = [p for p in os.listdir("/proc") if p.isdigit()]
    if len(pids) > 64:
        return record("proc.pid_namespace", "FAIL", f"{len(pids)} processes visible (host PID namespace?)")
    record("proc.pid_namespace", "PASS", f"{len(pids)} processes visible")


def probe_gvisor():
    if not GVISOR_REQUESTED:
        return
    if GVISOR:
        return record("kernel.gvisor", "PASS", f"running on gVisor's user-space kernel ({platform.release()})")
    record("kernel.gvisor", "FAIL", f"the launcher asked for gVisor but the kernel is {platform.release()}")


def probe_exec_lock():
    """After the sandbox's first program has started, can another one be executed?"""
    target = next((p for p in ("/bin/true", "/usr/bin/true", "/bin/sh") if os.path.exists(p)), None)
    if target is None:
        return record("proc.exec_locked", "SKIP", "no program to try in this image")

    def attempt():
        try:
            os.execv(target, [target])
        except OSError as exc:
            return errno.errorcode.get(exc.errno, str(exc.errno))

    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:  # child: either becomes `target` and exits 0, or reports why it could not
        os.close(rfd)
        signal.alarm(8)
        os.write(wfd, (attempt() or "").encode())
        os._exit(3)
    os.close(wfd)
    refused = os.read(rfd, 64).decode()
    os.close(rfd)
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        outcome = f"the process was killed ({signal.Signals(os.WTERMSIG(status)).name})"
        contained = os.WTERMSIG(status) in (signal.SIGKILL, signal.SIGSYS)
    elif refused:
        outcome, contained = f"refused ({refused})", True
    else:
        outcome, contained = "it ran", False
    if contained:
        return record("proc.exec_locked", "PASS", f"execve of {target}: {outcome}")
    if GVISOR:
        return record("proc.exec_locked", "INFO", f"execve of {target}: {outcome}. silo's exec lock needs seccomp "
                                                  "user notification, which gVisor does not have")
    if not EXEC_LOCK:
        return record("proc.exec_locked", "WARN", f"execve of {target}: {outcome}. The exec lock is off "
                                                  "(runtime.exec_lock = false): programs in the image can be run")
    record("proc.exec_locked", "FAIL", f"execve of {target}: {outcome}. Nothing stops a program in the image from being started")


def lsm_verdict(label, canary):
    """(status, detail) for an LSM label. `canary()` tries the write only silo's AppArmor profile forbids."""
    if not label or label == "unconfined":
        return "WARN", "not confined by SELinux or AppArmor"
    if label.endswith(")") and " (" in label:  # AppArmor: "<profile> (<mode>)", or a stack "<a>//&<b> (<mode>)"
        profile, _, mode = label[:-1].rpartition(" (")
        if SILO_APPARMOR in profile.split("//&"):
            # With no_new_privs AppArmor stacks silo's profile on the label the container runtime had,
            # and a stack's mode does not say whether silo's part is enforced or only attached. So try
            # the one thing nothing but that profile forbids.
            err = canary()
            if err is not None and err.errno == errno.EACCES:
                return "PASS", f"confined by AppArmor as {profile}: the profile refused the write that only it forbids"
            if err is None:
                return "WARN", (f"AppArmor profile {SILO_APPARMOR} is attached ({label}) but not enforced: a write "
                                "it denies went through")
            return "WARN", f"AppArmor label {label}; could not tell whether it is enforced ({err.strerror})"
        if mode == "enforce":
            return "PASS", f"confined by AppArmor profile {profile}"
        return "WARN", f"not confined: AppArmor profile '{profile}' is in {mode} mode"
    fields = label.split(":")
    if len(fields) >= 3:  # SELinux: user:role:type[:level[:categories]]
        if fields[2].startswith("container_") and fields[2] != "container_runtime_t":
            return "PASS", f"confined by SELinux as {label}"
        return "WARN", f"not confined as a container: SELinux type {fields[2]} ({label})"
    return "WARN", f"unrecognised LSM label {label}"


def probe_lsm():
    """Is the process confined by a mandatory access control policy (SELinux or AppArmor)?"""
    if GVISOR:
        return record("proc.lsm", "INFO", "not applicable: the sandbox runs on gVisor's kernel, which host "
                                          "SELinux/AppArmor policies do not reach (see kernel.gvisor)")
    try:
        with open("/proc/self/attr/current") as fh:
            label = fh.read().strip("\0\n ")
    except OSError:
        return record("proc.lsm", "WARN", "no LSM label readable: not confined by SELinux or AppArmor")
    record("proc.lsm", *lsm_verdict(label, lambda: try_write(APPARMOR_CANARY)))


# silo's AppArmor profile (host/apparmor/silo-runtime) and the one write nothing but it forbids.
SILO_APPARMOR = "silo-runtime"
APPARMOR_CANARY = "/tmp/.silo-apparmor-canary"

SENSITIVE_ENV = ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "PROXY", "SSH_AUTH_SOCK", "DBUS", "DISPLAY",
                 "WAYLAND", "XDG_RUNTIME_DIR", "AWS_", "HF_", "LLAMA_ARG_")


def probe_environment():
    leaked = sorted(k for k in os.environ if any(s in k.upper() for s in SENSITIVE_ENV))
    if leaked:
        return record("proc.environment", "FAIL", f"sensitive variables present: {leaked}")
    record("proc.environment", "PASS", f"environment: {sorted(os.environ)}")


def probe_cgroup_limits():
    if GVISOR:
        return record("proc.cgroup_limits", "INFO", "enforced on the host by silo's systemd scope around the "
                                                    "gVisor sandbox (not visible inside it)")
    limits = {}
    for name in ("memory.max", "pids.max"):
        try:
            with open(f"/sys/fs/cgroup/{name}") as fh:
                limits[name] = fh.read().strip()
        except OSError:
            limits[name] = "unreadable"
    unlimited = [k for k, v in limits.items() if v in ("max", "unreadable")]
    if unlimited:
        return record("proc.cgroup_limits", "WARN", f"no limit enforced for {unlimited}: {limits}")
    record("proc.cgroup_limits", "PASS", f"{limits}")


# ------------------------------------------------------------------------------- devices / kernel

STANDARD_DEV = {"null", "zero", "full", "random", "urandom", "tty", "console", "ptmx", "pts", "shm",
                "mqueue", "fd", "stdin", "stdout", "stderr", "core"}
CRITICAL_DEV = {"kvm", "fuse", "net", "mem", "kmem", "port", "kmsg", "vhost-net", "vhost-vsock", "vsock"}


def probe_devices():
    try:
        entries = set(os.listdir("/dev"))
    except OSError as exc:
        return record("dev.nodes", "WARN", f"/dev unreadable ({exc.strerror})")
    extra = sorted(entries - STANDARD_DEV - (GVISOR_DEV if GVISOR else set()))
    critical = sorted(e for e in extra if e in CRITICAL_DEV)
    if critical:
        return record("dev.nodes", "FAIL", f"host-facing devices present: {critical}")
    if extra:
        return record("dev.nodes", "WARN", f"non-standard devices present (GPU passthrough?): {extra}")
    record("dev.nodes", "PASS", "only standard pseudo-devices present")


def probe_pty():
    # No pty means no TTY layer: no line-discipline autoload (n_gsm & co), no TIOCSTI.
    if GVISOR:
        return record("dev.pty", "PASS", "pseudo-terminals, if any, are gVisor's own; the host TTY layer is not reachable")
    for path in ("/dev/ptmx", "/dev/pts/ptmx"):
        try:
            fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
        except OSError:
            continue
        os.close(fd)
        return record("dev.pty", "WARN", f"pseudo-terminals can be allocated via {path} (TTY layer reachable)")
    record("dev.pty", "PASS", "no pseudo-terminal can be allocated")


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(SockFilter))]


def probe_argument_filters():
    """ioctl, prctl and setsockopt with values outside silo's allowlists. Each succeeds in a stock container."""
    numbers = {name: nr(name) for name in ("ioctl", "prctl", "setsockopt")}
    if None in numbers.values():
        return record("args.allowlists", "SKIP", f"no syscall numbers for {MACHINE}")

    def ioctl(cmd):
        def run():
            fd = os.open("/etc/passwd", os.O_RDONLY)
            out = ctypes.c_int(0)
            return raw_syscall(numbers["ioctl"], fd, cmd, ctypes.addressof(out))
        return run

    def setsockopt(level, name, value_ptr, size):
        a, _b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        return raw_syscall(numbers["setsockopt"], a.fileno(), level, name, value_ptr, size)

    def passcred():
        one = ctypes.c_int(1)
        return setsockopt(1, 16, ctypes.addressof(one), 4)  # SOL_SOCKET, SO_PASSCRED

    def attach_filter():
        accept_all = (SockFilter * 1)(SockFilter(0x06, 0, 0, 0xFFFFFFFF))  # BPF_RET|BPF_K
        prog = SockFprog(1, accept_all)
        return setsockopt(1, 26, ctypes.addressof(prog), ctypes.sizeof(prog))  # SO_ATTACH_FILTER

    cases = [
        ("args.ioctl_unlisted", ioctl(2), "ioctl(FIGETBSZ) on a regular file"),
        ("args.ioctl_upper_bits", ioctl(0x5401 | 1 << 32), "ioctl(TCGETS with stray upper bits)"),
        ("args.prctl_unlisted", lambda: raw_syscall(numbers["prctl"], 36, 1, 0, 0, 0),
         "prctl(PR_SET_CHILD_SUBREAPER)"),
        ("args.setsockopt_unlisted", passcred, "setsockopt(SO_PASSCRED) on a UNIX socket"),
        ("args.socket_filter", attach_filter, "setsockopt(SO_ATTACH_FILTER): classic BPF without bpf()"),
    ]
    fail_as, note = ("WARN", " (argument allowlists are off with GPU passthrough)") if GPU else ("FAIL", "")
    for probe, fn, what in cases:
        judge_syscall(probe, in_child(fn), what, fail_as, note)
    # and what the runtime needs still works
    def allowed():
        a, _b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        waiting = ctypes.c_int(-1)
        return raw_syscall(numbers["ioctl"], a.fileno(), 0x541B, ctypes.addressof(waiting))  # FIONREAD
    kind, value = in_child(allowed)
    if kind == "ok" and value[0] == 0:
        record("args.allowlisted", "PASS", "allowlisted calls still work (ioctl FIONREAD)")
    else:
        record("args.allowlisted", "WARN", f"an allowlisted call was refused: {describe(kind, value)}")


def probe_kernel_leaks():
    try:
        with open("/proc/kallsyms") as fh:
            first = fh.readline().split()
    except OSError:
        return record("kernel.kallsyms", "PASS", "/proc/kallsyms unreadable")
    if not first:
        record("kernel.kallsyms", "PASS", "/proc/kallsyms masked (empty)")
    elif int(first[0], 16) != 0:
        record("kernel.kallsyms", "FAIL", "kernel symbol addresses readable (KASLR bypass)")
    else:
        record("kernel.kallsyms", "WARN", "kallsyms readable (addresses zeroed, symbol names disclosed)")

    exposed = []
    for path in ("/proc/modules", "/proc/cmdline"):
        try:
            with open(path) as fh:
                if fh.read(1):
                    exposed.append(path)
        except OSError:
            pass
    for path in ("/sys/module", "/sys/kernel"):
        try:
            if os.listdir(path):
                exposed.append(path)
        except OSError:
            pass
    if exposed:
        return record("kernel.masked_paths", "WARN", f"host kernel details readable: {exposed}")
    record("kernel.masked_paths", "PASS", "module list, boot command line, /sys/module and /sys/kernel masked")


def main():
    record("meta.host", "INFO", f"arch={MACHINE} kernel={platform.release()} python={platform.python_version()}")
    for fn in (probe_gvisor, probe_interfaces, probe_routes, probe_socket_families, probe_socketpair, probe_dns,
               probe_tcp_egress, probe_abstract_unix, probe_syscalls, probe_clone_newuser, probe_compat_abi,
               probe_readonly, probe_socket_dir, probe_tmp_noexec, probe_memfd_exec, probe_mounts,
               probe_host_artifacts, probe_credentials, probe_pid_namespace, probe_exec_lock, probe_lsm,
               probe_environment, probe_cgroup_limits, probe_devices, probe_pty, probe_argument_filters,
               probe_kernel_leaks):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - a crashing probe must not hide the others
            record(f"error.{fn.__name__}", "WARN", f"{type(exc).__name__}: {exc}")
    counts = {s: sum(r["status"] == s for r in RESULTS) for s in ("PASS", "FAIL", "WARN", "SKIP")}
    print(json.dumps({"summary": counts}), flush=True)
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
