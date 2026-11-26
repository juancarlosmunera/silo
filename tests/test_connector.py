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

    def test_refuses_its_own_network_namespace(self):
        with self.assertRaises(RuntimeError):
            connector._join_netns(os.getpid())


if __name__ == "__main__":
    unittest.main()
