import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from silo import connector


class ConnectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.address = f"silo-conn-test-{os.getpid()}-{id(self)}"
        self.control = str(Path(self.tmp.name) / "control.sock")
        ctl = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        ctl.bind(self.control)
        ctl.listen(8)
        stop = threading.Event()
        thread = threading.Thread(target=connector.serve_requests, args=(ctl, self.address, lambda: not stop.is_set()),
                                  kwargs={"poll": 0.02}, daemon=True)
        thread.start()
        self.addCleanup(ctl.close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(stop.set)

    def listen(self):
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind("\0" + self.address)
        srv.listen(8)
        self.addCleanup(srv.close)
        return srv

    def test_hands_over_a_connected_socket(self):
        srv = self.listen()
        sock = connector.dial(self.control, 5, expect_uid=os.getuid())
        peer, _ = srv.accept()
        sock.sendall(b"ping")
        self.assertEqual(peer.recv(4), b"ping")
        peer.close()
        sock.close()

    def test_runtime_not_listening(self):
        with self.assertRaises(connector.DialError) as cm:
            connector.dial(self.control, 5)
        self.assertIn("not reachable", str(cm.exception))

    def test_peer_uid_checked(self):
        self.listen()
        with self.assertRaises(connector.DialError) as cm:
            connector.dial(self.control, 5, expect_uid=os.getuid() + 1)
        self.assertIn("peer UID", str(cm.exception))

    def test_control_must_be_our_socket(self):
        with self.assertRaises(FileNotFoundError):
            connector.dial(str(Path(self.tmp.name) / "missing.sock"), 1)
        link = Path(self.tmp.name) / "link.sock"
        link.symlink_to(self.control)
        with self.assertRaises(connector.DialError):
            connector.dial(str(link), 1)
        plain = Path(self.tmp.name) / "plain"
        plain.write_text("x")
        with self.assertRaises(connector.DialError):
            connector.dial(str(plain), 1)

    def test_bad_request_is_dropped(self):
        self.listen()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(self.control)
            s.sendall(b"\x02")
            self.assertEqual(s.recv(16), b"")  # closed without an answer
        connector.dial(self.control, 5).close()  # and it keeps serving

    def host_socket(self, mode=0o755):
        """A listening socket in a directory, as gVisor leaves one on the host for the runtime."""
        directory = Path(self.tmp.name) / "sock"
        directory.mkdir()
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(directory / "llama.sock"))
        srv.listen(4)
        self.addCleanup(srv.close)
        directory.chmod(mode)
        return directory / "llama.sock", srv

    def test_dial_socket(self):
        path, srv = self.host_socket()
        sock = connector.dial_socket(str(path), 5, expect_uid=os.getuid())
        peer, _ = srv.accept()
        sock.sendall(b"ping")
        self.assertEqual(peer.recv(4), b"ping")
        peer.close()
        sock.close()
        with self.assertRaises(connector.DialError) as cm:
            connector.dial_socket(str(path), 5, expect_uid=os.getuid() + 1)
        self.assertIn("peer UID", str(cm.exception))

    def test_dial_socket_needs_a_locked_directory(self):
        for mode in (0o777, 0o775, 0o757):  # still writable by somebody else: not locked
            with self.subTest(mode=oct(mode)):
                path, _ = self.host_socket(mode)
                with self.assertRaises(connector.DialError) as cm:
                    connector.dial_socket(str(path), 5)
                self.assertIn("locked directory", str(cm.exception))
                path.unlink()
                path.parent.rmdir()

    def test_dial_socket_refuses_what_is_not_the_socket_itself(self):
        path, _ = self.host_socket()
        link = path.parent / "link.sock"
        link.symlink_to(path)
        with self.assertRaises(connector.DialError):  # a symlink, even to a real socket
            connector.dial_socket(str(link), 5)
        plain = path.parent / "plain"
        plain.write_text("x")
        with self.assertRaises(connector.DialError):
            connector.dial_socket(str(plain), 5)
        with self.assertRaises(FileNotFoundError):
            connector.dial_socket(str(path.parent / "missing.sock"), 5)
        with self.assertRaises(FileNotFoundError):
            connector.dial_socket(str(Path(self.tmp.name) / "nodir" / "llama.sock"), 5)

    def test_dial_socket_cannot_be_raced_onto_another_socket(self):
        # The sandbox owns the runtime's socket file and may swap it for a symlink to another of the
        # user's sockets at any moment. No connection may ever end up there.
        path, srv = self.host_socket()
        other = Path(self.tmp.name) / "other.sock"
        decoy = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        decoy.bind(str(other))
        decoy.listen(512)
        decoy.setblocking(False)
        self.addCleanup(decoy.close)
        real, link = path.with_name("real.sock"), path.with_name("swap.sock")
        os.rename(path, real)
        stop = threading.Event()

        def swap():
            while not stop.is_set():
                os.link(real, link); os.replace(link, path)       # the runtime's socket itself
                os.symlink(other, link); os.replace(link, path)   # a symlink to the other one
        swapper = threading.Thread(target=swap, daemon=True)
        swapper.start()
        try:
            for _ in range(5000):
                try:
                    connector.dial_socket(str(path), 1).close()
                except (connector.DialError, FileNotFoundError, OSError):
                    pass
        finally:
            stop.set()
            swapper.join(5)
        with self.assertRaises(BlockingIOError):
            decoy.accept()

    def test_refuses_its_own_network_namespace(self):
        with self.assertRaises(RuntimeError):
            connector._join_netns(os.getpid())


if __name__ == "__main__":
    unittest.main()
