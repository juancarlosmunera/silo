import errno
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import threading
import unittest
from unittest import mock

from silo import execlock

# What the kernel calls these (include/uapi/linux/seccomp.h); a wrong size or number would make every
# ioctl fail with EINVAL or ENOTTY at runtime.
SECCOMP_IOCTL_NOTIF_RECV = 0xC0502100
SECCOMP_IOCTL_NOTIF_SEND = 0xC0182101
SECCOMP_IOCTL_NOTIF_ID_VALID = 0x40082102

# (seccomp, execve, execveat) syscall numbers.
SYSCALLS = {"x86_64": (317, 59, 322), "aarch64": (277, 221, 281)}

# A process that puts itself under a filter sending execve and execveat to a listener, hands the
# listener to the test over an inherited socket, and then executes a second program. That first
# execve is the one a container runtime makes for the entrypoint.
CHILD = r"""
import ctypes, os, socket, sys
sock = socket.socket(fileno=int(sys.argv[1]))
seccomp_nr, execve, execveat = (int(n) for n in sys.argv[2:5])

class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]

class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]

program = [(0x20, 0, 0, 0),              # A = seccomp_data.nr
           (0x15, 2, 0, execve),         # execve   -> notify
           (0x15, 1, 0, execveat),       # execveat -> notify
           (0x06, 0, 0, 0x7FFF0000),     # SECCOMP_RET_ALLOW
           (0x06, 0, 0, 0x7FC00000)]     # SECCOMP_RET_USER_NOTIF
instructions = (SockFilter * len(program))(*[SockFilter(*i) for i in program])
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.prctl(38, 1, 0, 0, 0)               # PR_SET_NO_NEW_PRIVS, so that no privilege is needed
# SECCOMP_SET_MODE_FILTER with SECCOMP_FILTER_FLAG_NEW_LISTENER
fd = libc.syscall(seccomp_nr, 1, 8, ctypes.byref(SockFprog(len(program), instructions)))
if fd < 0:
    sock.sendall(b"skip: seccomp listener unavailable: " + os.strerror(ctypes.get_errno()).encode())
    sys.exit(0)
socket.send_fds(sock, [b"ok"], [fd])
os.close(fd)
sock.recv(1)                             # wait until the supervisor is running
try:
    os.execv(sys.executable, [sys.executable, "-I", "-c", sys.argv[5]])
except OSError as exc:
    print("first:" + str(exc.errno))
    sys.exit(9)
"""

# What the "entrypoint" does: try to run another program.
SECOND = r"""
import os, sys
try:
    os.execv("/bin/true", ["true"])
except OSError as exc:
    print("second:" + str(exc.errno))
    sys.exit(7)
"""


class LayoutTests(unittest.TestCase):
    def test_ioctl_numbers_match_the_kernel(self):
        self.assertEqual(execlock.NOTIF_RECV, SECCOMP_IOCTL_NOTIF_RECV)
        self.assertEqual(execlock.NOTIF_SEND, SECCOMP_IOCTL_NOTIF_SEND)
        self.assertEqual(execlock.NOTIF_ID_VALID, SECCOMP_IOCTL_NOTIF_ID_VALID)

    def test_struct_sizes(self):
        self.assertEqual(execlock.RESP.size, execlock.RESP_SIZE)
        self.assertLessEqual(execlock.NOTIF_HEAD.size, execlock.NOTIF_SIZE)
        # id, then pid and flags, then seccomp_data starting with nr and arch
        self.assertEqual(execlock.NOTIF_HEAD.unpack(b"\x07" + b"\0" * 7 + b"\x2a\0\0\0" + b"\0" * 4 + b"\x3b\0\0\0" + b"\0" * 4),
                         (7, 42, 0, 59, 0))


class StateTests(unittest.TestCase):
    def test_container_pid(self):
        state = {"ociVersion": "1.0.2", "fds": ["seccompFd"], "pid": 4242, "state": {"status": "creating"}}
        self.assertEqual(execlock.parse_state(json.dumps(state).encode()), 4242)

    def test_anything_else_is_refused(self):
        for message in (b"", b"not json", b"[]", b'{"pid": "4242"}', b'{"pid": 1}', b'{"pid": 0}', b'{"pid": -5}',
                        b'{"pid": true}', b'{"state": {}}', b'{"pid": 12.5}'):
            with self.subTest(message=message), self.assertRaises(ValueError):
                execlock.parse_state(message)


class DeciderTests(unittest.TestCase):
    def test_only_the_first_exec_and_only_by_the_first_process(self):
        decider = execlock.Decider(100)
        self.assertTrue(decider.allow(100))
        for pid in (100, 100, 101):
            self.assertFalse(decider.allow(pid))
        self.assertEqual(decider.seen, 4)

    def test_another_process_cannot_use_up_or_take_the_first_exec(self):
        decider = execlock.Decider(100)
        self.assertFalse(decider.allow(101))  # not the container's first process
        self.assertFalse(decider.allow(100))  # and the one allowance is gone with it: fail closed


@unittest.skipUnless(platform.machine() in SYSCALLS and os.path.exists("/bin/true"), "x86_64 or aarch64 Linux only")
class KernelTests(unittest.TestCase):
    """The supervisor loop against a real seccomp notification descriptor."""

    def run_child(self, kill: bool, init_pid_offset: int = 0, second: str = SECOND):
        ours, theirs = socket.socketpair()
        child = subprocess.Popen(
            [sys.executable, "-I", "-c", CHILD, str(theirs.fileno()), *map(str, SYSCALLS[platform.machine()]), second],
            pass_fds=[theirs.fileno()], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        theirs.close()
        listener = None
        try:
            ours.settimeout(20)
            message, fds, _flags, _addr = socket.recv_fds(ours, 256, 1)
            if not fds:
                child.wait(10)
                self.skipTest(message.decode() or "the child could not install a seccomp listener")
            listener = fds[0]
            refusals = []
            decider = execlock.Decider(child.pid + init_pid_offset)
            supervisor = threading.Thread(target=execlock.supervise, daemon=True,
                                          args=(listener, decider, kill, lambda *event: refusals.append(event)))
            supervisor.start()
            ours.sendall(b"g")
            out, err = child.communicate(timeout=30)
            supervisor.join(10)
            self.assertFalse(supervisor.is_alive(), "the supervisor did not stop when the last process exited")
            return child.returncode, out.strip(), err.strip(), refusals, decider
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(10)
            if listener is not None:
                os.close(listener)
            ours.close()

    def test_first_exec_continues_and_the_next_is_refused(self):
        code, out, err, refusals, decider = self.run_child(kill=False)
        self.assertEqual((code, out), (7, f"second:{errno.EPERM}"), err)
        self.assertEqual(decider.seen, 2)
        self.assertEqual(len(refusals), 1)
        pid, _syscall, count, outcome = refusals[0]
        self.assertEqual((count, outcome), (2, "refused (EPERM)"))
        self.assertGreater(pid, 1)

    def test_kill_mode_kills_the_caller(self):
        code, out, err, refusals, _decider = self.run_child(kill=True)
        self.assertEqual((code, out), (-signal.SIGKILL, ""), err)
        self.assertEqual([event[3] for event in refusals], ["killed"])

    def test_the_caller_chooses_its_thread_name_but_not_who_is_killed(self):
        # The thread name is the first line of /proc/<tid>/status and the sandbox sets it freely:
        # a carriage return and a fake field must not make the supervisor kill someone else, and
        # bytes that are not UTF-8 must not make it give up on killing the caller.
        victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(victim.wait)
        self.addCleanup(victim.kill)
        for name in (f"\\rTgid:\\t{victim.pid}", "\\xff\\xfe"):
            with self.subTest(name=name):
                second = ("import ctypes\n"
                          f"ctypes.CDLL(None).prctl(15, b'{name}', 0, 0, 0)\n") + SECOND
                code, out, err, refusals, _decider = self.run_child(kill=True, second=second)
                self.assertEqual((code, out), (-signal.SIGKILL, ""), err)
                self.assertEqual([event[3] for event in refusals], ["killed"])
                self.assertIsNone(victim.poll(), "the supervisor killed a process that never called execve")

    def test_refusals_are_recorded_one_by_one_then_sampled(self):
        lines = []
        with mock.patch("sys.stderr") as stderr:
            stderr.write.side_effect = lambda text: lines.append(text) if text.strip() else None
            report = execlock._reporter(None, "x")
            for count in range(2, 2 + 25_000):
                report(12, 59, count, "refused (EPERM)")
        recorded = [line for line in lines if line.startswith("execlock: execve #")]
        self.assertEqual(len(recorded), execlock.REPORT_FIRST + 2)  # the first hundred, then #10000 and #20000
        self.assertIn("20000 refused so far", recorded[-1])

    def test_exec_by_anything_but_the_first_process_is_refused_from_the_start(self):
        code, out, err, refusals, _decider = self.run_child(kill=False, init_pid_offset=1)
        self.assertEqual((code, out), (9, f"first:{errno.EPERM}"), err)
        self.assertEqual([event[2:] for event in refusals], [(1, "refused (EPERM)")])


class PrivilegeTests(unittest.TestCase):
    def test_capabilities_are_read_from_proc(self):
        effective, permitted = execlock._capabilities()
        self.assertIsInstance(effective, int)
        self.assertEqual(effective & ~permitted, 0)  # effective is always a subset of permitted


if __name__ == "__main__":
    unittest.main()
