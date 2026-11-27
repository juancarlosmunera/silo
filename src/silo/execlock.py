"""Exec lock: after the runtime has started, nothing else can be executed in the sandbox.

A seccomp filter is fixed before the container's entrypoint is executed, so it cannot allow that
one execve and deny the rest: it would have to count. This module is the part that counts.

silo's seccomp profile answers execve and execveat with SECCOMP_RET_USER_NOTIF: the calling thread
is suspended and the kernel asks a supervisor, over a file descriptor, what to do. The container
runtime (crun, runc) hands that descriptor to whoever listens on the profile's `listenerPath`, with
a short JSON description that names the container's first process. The supervisor then:

  * lets exactly one execve continue: the first one, and only if it comes from that first process.
    That is the runtime executing the image's entrypoint, before any code from the image has run;
  * refuses every later one with EPERM, or, with seccomp_action = "kill", kills the process that
    made the call, as a seccomp kill would;
  * records each refusal in silo's audit log (a sample of them once there are more than a hundred).

The decision never looks at the arguments of the call, only at which call it is, so the usual
objection to continuing a notified syscall (the target can change its arguments after they were
inspected) does not arise. If the supervisor dies, the kernel answers every execve with ENOSYS:
the lock fails closed. A shell, an interpreter or a download tool that ships in the image, and a
binary an attacker managed to bring along, are all equally unusable after start.

The supervisor is started before the container, under `podman unshare`, from source text fed to
`python3 -I -`; it therefore imports nothing from silo. Once it holds the descriptor it drops to an
unprivileged UID of the user namespace with no capabilities. In kill mode it keeps exactly one,
CAP_KILL, which is what signalling a process of the sandbox's UID takes.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import json
import os
import select
import signal
import socket
import struct
import sys
import time

SUPERVISOR_UID = 65532  # container UID the supervisor drops to: neither the sandbox's nor the connector's
ACCEPT_TIMEOUT = 900.0  # seconds to wait for the runtime's descriptor; the launcher stops us sooner on failure

# struct seccomp_notif      { __u64 id; __u32 pid; __u32 flags; struct seccomp_data data; }   80 bytes
# struct seccomp_data       { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; } 64 bytes
# struct seccomp_notif_resp { __u64 id; __s64 val; __s32 error; __u32 flags; }                24 bytes
NOTIF_SIZE, RESP_SIZE = 80, 24
NOTIF_HEAD = struct.Struct("<QIIiI")
RESP = struct.Struct("<QqiI")
FLAG_CONTINUE = 1


def _ioc(direction: int, number: int, size: int) -> int:
    return (direction << 30) | (size << 16) | (ord("!") << 8) | number


# asm-generic ioctl encoding, the same on x86_64 and aarch64.
NOTIF_RECV = _ioc(3, 0, NOTIF_SIZE)   # _IOWR('!', 0, struct seccomp_notif)
NOTIF_SEND = _ioc(3, 1, RESP_SIZE)    # _IOWR('!', 1, struct seccomp_notif_resp)
NOTIF_ID_VALID = _ioc(1, 2, 8)        # _IOW('!', 2, __u64)


def parse_state(message: bytes) -> int:
    """The PID of the container's first process, from the runtime's container process state."""
    try:
        state = json.loads(message)
        pid = state["pid"]
    except (ValueError, KeyError, TypeError):
        raise ValueError("the runtime did not send a container process state") from None
    if type(pid) is not int or pid <= 1:
        raise ValueError(f"implausible container PID {pid!r}")
    return pid


class Decider:
    """Which execve this is. Kept apart from the ioctl plumbing so that it can be tested."""

    def __init__(self, init_pid: int):
        self.init_pid = init_pid
        self.seen = 0

    def allow(self, pid: int) -> bool:
        self.seen += 1
        return self.seen == 1 and pid == self.init_pid


def _tgid(tid: int) -> int | None:
    """The thread group of `tid`, from /proc.

    The first line of that file is the thread's name, which the sandboxed process chooses: it can
    hold a carriage return, invalid UTF-8 or text that looks like another field. So the file is read
    as bytes and split on newlines only, which the kernel escapes in the name, and the field is
    looked for at the start of a line after the name.
    """
    try:
        with open(f"/proc/{tid}/status", "rb") as fh:
            lines = fh.read(1 << 16).split(b"\n")
    except OSError:
        return None
    for line in lines[1:]:
        if line.startswith(b"Tgid:\t"):
            value = line[6:].strip()
            return int(value) if value.isdigit() else None
    return None


def _kill_caller(fd: int, notif_id: int, tid: int) -> str:
    """Kill the process that made the call, if it is still the one suspended in this notification."""
    tgid = _tgid(tid)
    if tgid is None:
        return "gone before it could be killed"
    try:
        pidfd = os.pidfd_open(tgid)
    except OSError as exc:
        return f"not killed ({errno.errorcode.get(exc.errno, exc.errno)})"
    try:
        # Still suspended in this very call? Then the descriptor opened above is that process, not a
        # later one that reused its number.
        fcntl.ioctl(fd, NOTIF_ID_VALID, struct.pack("<Q", notif_id))
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        return "killed"
    except OSError as exc:
        return f"not killed ({errno.errorcode.get(exc.errno, exc.errno)})"
    finally:
        os.close(pidfd)


def supervise(fd: int, decider: Decider, kill: bool, report) -> None:
    """Answer execve notifications on `fd` until no process is left that could send one."""
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    while True:
        events = poller.poll()
        if any(event & select.POLLIN for _, event in events):
            request = bytearray(NOTIF_SIZE)
            try:
                fcntl.ioctl(fd, NOTIF_RECV, request)
            except OSError as exc:
                if exc.errno == errno.ENOENT:  # the caller was killed before we read its request
                    continue
                return
            notif_id, tid, _flags, syscall, _arch = NOTIF_HEAD.unpack_from(request)
            if decider.allow(tid):
                response = RESP.pack(notif_id, 0, 0, FLAG_CONTINUE)
            else:
                response = RESP.pack(notif_id, 0, -errno.EPERM, 0)
                outcome = _kill_caller(fd, notif_id, tid) if kill else "refused (EPERM)"
                report(tid, syscall, decider.seen, outcome)
            try:
                fcntl.ioctl(fd, NOTIF_SEND, bytearray(response))
            except OSError:
                pass  # the caller is gone (killed, by us or otherwise): nothing to answer
        elif events:  # POLLHUP: every process that had the filter has exited
            return


PR_SET_KEEPCAPS, PR_SET_NO_NEW_PRIVS = 8, 38
CAP_KILL = 5
LINUX_CAPABILITY_VERSION_3 = 0x20080522


def _capabilities() -> tuple[int, int]:
    """(effective, permitted) capability sets of this process."""
    values = {}
    with open("/proc/self/status") as fh:
        for line in fh:
            key, _, value = line.partition(":")
            if key in ("CapEff", "CapPrm"):
                values[key] = int(value.strip(), 16)
    return values["CapEff"], values["CapPrm"]


def _drop_privileges(uid: int, keep_kill: bool) -> None:
    """Become an unprivileged UID with no capabilities, or with CAP_KILL alone."""
    libc = ctypes.CDLL(None, use_errno=True)

    def check(result: int, what: str) -> None:
        if result != 0:
            err = ctypes.get_errno()
            raise OSError(err, f"{what}: {os.strerror(err)}")

    if keep_kill:  # permitted capabilities survive the change of UID; effective ones are set again below
        check(libc.prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0), "prctl(PR_SET_KEEPCAPS)")
    os.setgroups([])
    os.setresgid(uid, uid, uid)
    os.setresuid(uid, uid, uid)
    wanted = 1 << CAP_KILL if keep_kill else 0
    header = struct.pack("<Ii", LINUX_CAPABILITY_VERSION_3, 0)
    data = struct.pack("<6I", wanted, wanted, 0, 0, 0, 0)  # effective, permitted, inheritable: low, then high words
    check(libc.capset(ctypes.c_char_p(header), ctypes.c_char_p(data)), "capset")
    check(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "prctl(PR_SET_NO_NEW_PRIVS)")
    if _capabilities() != (wanted, wanted):
        raise RuntimeError(f"unexpected capabilities after dropping privileges: {_capabilities()}")


REPORT_FIRST = 100       # refusals recorded one by one; after that one line per REPORT_EVERY
REPORT_EVERY = 10_000    # so that a sandbox looping on execve cannot fill the disk through the logs


def _reporter(audit_fd: int | None, name: str):
    def report(pid: int, syscall: int, count: int, outcome: str) -> None:
        # count includes the one allowed execve, so refusals are count - 1
        refused = count - 1
        if refused > REPORT_FIRST and refused % REPORT_EVERY:
            return
        if refused > REPORT_FIRST:
            outcome = f"{outcome}; {refused} refused so far, only every {REPORT_EVERY}th is recorded"
        print(f"execlock: execve #{count} by pid {pid} (syscall {syscall}): {outcome}", file=sys.stderr, flush=True)
        if audit_fd is None:
            return
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "silo": name, "event": "exec_refused",
                 "pid": pid, "syscall": syscall, "refused": refused, "outcome": outcome}
        try:
            os.write(audit_fd, (json.dumps(entry, separators=(",", ":")) + "\n").encode())
        except OSError:
            pass
    return report


def serve(listen: str, pidfile: str, kill: bool, audit: str | None, name: str, uid: int) -> int:
    os.umask(0o177)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(listen)
    listener.listen(1)
    with open(pidfile, "w") as fh:
        fh.write(f"{os.getpid()}\n")
    audit_fd = os.open(audit, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600) if audit else None
    print(f"execlock: ready, pid {os.getpid()}", file=sys.stderr, flush=True)

    listener.settimeout(ACCEPT_TIMEOUT)
    conn, _ = listener.accept()
    with conn:
        conn.settimeout(10)
        message, fds, _flags, _addr = socket.recv_fds(conn, 1 << 16, 4)
        while len(message) < 1 << 22:  # the state can exceed one read; the runtime closes when it is done
            more = conn.recv(1 << 16)
            if not more:
                break
            message += more
    # One container per supervisor. With the socket gone, `podman exec` into the sandbox cannot get a
    # descriptor of its own, and the runtime refuses to start it.
    listener.close()
    os.unlink(listen)
    if len(fds) != 1:
        for fd in fds:
            os.close(fd)
        print(f"execlock: expected one descriptor from the runtime, got {len(fds)}", file=sys.stderr, flush=True)
        return 1
    init_pid = parse_state(message)
    _drop_privileges(uid, keep_kill=kill)
    print(f"execlock: supervising, container pid {init_pid}, uid {os.getuid()}, "
          f"{'kill mode (CAP_KILL only)' if kill else 'errno mode (no capabilities)'}", file=sys.stderr, flush=True)
    supervise(fds[0], Decider(init_pid), kill, _reporter(audit_fd, name))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="silo-execlock")
    ap.add_argument("--listen", required=True)
    ap.add_argument("--pidfile", required=True)
    ap.add_argument("--kill", action="store_true")
    ap.add_argument("--audit")
    ap.add_argument("--name", default="")
    ap.add_argument("--uid", type=int, default=SUPERVISOR_UID)
    args = ap.parse_args(argv)
    return serve(args.listen, args.pidfile, args.kill, args.audit, args.name, args.uid)


if __name__ == "__main__":
    sys.exit(main())
