"""Socket handoff between the gateway and the sandbox, with no directory shared between them.

llama-server listens on an abstract UNIX socket. Abstract sockets live in a network namespace, not
in the filesystem, so the one the runtime binds exists only inside its own `--network=none`
namespace: nothing on the host can see it, and the sandbox gets no host directory to write to.

To reach it, silo starts this module as a small connector process under `podman unshare` (root of
the rootless user namespace, which owns the container's namespaces):

  1. bind a control socket in the host user's private runtime directory (0700 parent, socket 0600);
  2. join the container's network namespace (setns), refusing the host's own;
  3. drop to an unprivileged UID of the user namespace, which leaves it with no capabilities;
  4. for each request on the control socket: connect to the runtime's abstract socket and pass the
     connected socket back over the control socket (SCM_RIGHTS), then forget it.

The connector never reads what the runtime sends, so there is nothing in it for the runtime to
attack except connect(). It exits when the container's process does.

The client side (`dial`) checks the control socket is a socket owned by this user and, on every
connection, that the peer is the sandbox's UID (SO_PEERCRED), so a squatter on the abstract name in
some other namespace would be refused even if the connector were pointed at the wrong one.

The server half runs from source text fed to `python3 -I -` and therefore imports nothing from silo.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import socket
import stat
import struct
import sys

REQUEST = b"\x01"
OK = b"ok"
CLONE_NEWNET = 0x40000000
CONNECTOR_UID = 65533  # container UID the connector drops to: unprivileged, and not the sandbox's 65534


class DialError(ConnectionRefusedError):
    pass


# ----------------------------------------------------------------------------------------- client

def dial(control: str, timeout: float, expect_uid: int | None = None) -> socket.socket:
    """Return a socket connected to the runtime, obtained from the connector at `control`."""
    try:
        st = os.lstat(control)
    except OSError as exc:
        raise FileNotFoundError(control) from exc
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.getuid():
        raise DialError(f"{control} is not a socket owned by this user")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as ctl:
        ctl.settimeout(timeout)
        ctl.connect(control)
        ctl.sendall(REQUEST)
        msg, fds, _flags, _addr = socket.recv_fds(ctl, 256, 1)
    if len(fds) != 1 or msg != OK:
        for fd in fds:
            os.close(fd)
        raise DialError(f"connector: {msg.decode('ascii', 'replace')[:120] or 'no answer'}")
    sock = socket.socket(fileno=fds[0])
    try:
        if sock.family != socket.AF_UNIX or sock.type != socket.SOCK_STREAM:
            raise DialError("connector handed over something that is not a UNIX stream socket")
        _check_peer(sock, expect_uid)
        sock.settimeout(timeout)
        return sock
    except BaseException:
        sock.close()
        raise


def dial_socket(path: str, timeout: float, expect_uid: int | None = None) -> socket.socket:
    """Connect to a runtime socket that exists on the host (gVisor sandboxes, see silo.runtime).

    The socket sits in a directory silo locked once the runtime had bound it: owned by this user and
    writable by nobody else. That, and the path itself being a socket, is checked with lstat on
    every connection, so it can never be a symlink to some other host socket.
    """
    parent = os.path.dirname(path)
    try:
        directory, st = os.lstat(parent), os.lstat(path)
    except OSError as exc:
        raise FileNotFoundError(path) from exc
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or directory.st_mode & 0o022:
        raise DialError(f"{parent} is not a locked directory owned by this user")
    if not stat.S_ISSOCK(st.st_mode):
        raise DialError(f"{path} is not a socket")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(path)
        _check_peer(sock, expect_uid)
        return sock
    except BaseException:
        sock.close()
        raise


def _check_peer(sock: socket.socket, expect_uid: int | None) -> None:
    if expect_uid is None:
        return
    _pid, uid, _gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != expect_uid:
        raise DialError(f"peer UID {uid} is not the sandbox's ({expect_uid})")


# ----------------------------------------------------------------------------------------- server

def _setns(fd: int) -> None:
    if hasattr(os, "setns"):  # Python 3.12+
        os.setns(fd, CLONE_NEWNET)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setns(fd, CLONE_NEWNET) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _join_netns(pid: int) -> None:
    fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    try:
        target = os.fstat(fd)
        own = os.stat("/proc/self/ns/net")
        if (target.st_dev, target.st_ino) == (own.st_dev, own.st_ino):
            raise RuntimeError(f"process {pid} shares this process's network namespace; refusing to serve it")
        _setns(fd)
    finally:
        os.close(fd)


def _drop_privileges(uid: int) -> None:
    os.setgroups([])
    os.setresgid(uid, uid, uid)
    os.setresuid(uid, uid, uid)
    with open("/proc/self/status") as fh:
        caps = {k: v.strip() for k, _, v in (line.partition(":") for line in fh) if k.startswith("Cap")}
    if int(caps.get("CapEff", "1"), 16) or int(caps.get("CapPrm", "1"), 16):
        raise RuntimeError(f"capabilities left after dropping privileges: {caps}")


def _answer(conn: socket.socket, address: str) -> None:
    conn.settimeout(5)
    if conn.recv(1) != REQUEST:
        return
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.settimeout(5)
        try:
            upstream.connect("\0" + address)
        except OSError as exc:
            conn.sendall(f"runtime not reachable ({errno.errorcode.get(exc.errno, exc.errno)})".encode())
            return
        socket.send_fds(conn, [OK], [upstream.fileno()])
    finally:
        upstream.close()


def serve(pid: int, address: str, control: str, pidfile: str, uid: int) -> int:
    os.umask(0o177)
    ctl = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ctl.bind(control)
    ctl.listen(64)
    with open(pidfile, "w") as fh:
        fh.write(f"{os.getpid()}\n")
    _join_netns(pid)
    _drop_privileges(uid)
    print(f"connector: ready, pid {os.getpid()}, uid {os.getuid()}", file=sys.stderr, flush=True)
    serve_requests(ctl, address, lambda: os.path.exists(f"/proc/{pid}"))
    return 0


def serve_requests(ctl: socket.socket, address: str, alive, poll: float = 1.0) -> None:
    """Answer handoff requests on `ctl` for as long as alive() holds."""
    ctl.settimeout(poll)
    while alive():
        try:
            conn, _ = ctl.accept()
        except OSError:  # includes the accept timeout
            continue
        with conn:
            try:
                _answer(conn, address)
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="silo-connector")
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--address", required=True)
    ap.add_argument("--control", required=True)
    ap.add_argument("--pidfile", required=True)
    ap.add_argument("--uid", type=int, default=CONNECTOR_UID)
    args = ap.parse_args(argv)
    return serve(args.pid, args.address, args.control, args.pidfile, args.uid)


if __name__ == "__main__":
    sys.exit(main())
