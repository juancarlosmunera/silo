import os
import socket
import threading
import unittest
from unittest import mock

from silo import doctor


class EgressProbeTests(unittest.TestCase):
    """The --sealed probes must say OPEN whenever anything comes back, and blocked otherwise."""

    def test_tcp_only_a_completed_connection_counts_as_open(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        self.assertEqual(doctor._tcp(socket.AF_INET, ("127.0.0.1", port)), (True, "connected"))
        closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed.bind(("127.0.0.1", 0))
        free_port = closed.getsockname()[1]
        closed.close()
        # A refusal is a firewall or router rejecting the attempt: the real targets are known to listen.
        self.assertEqual(doctor._tcp(socket.AF_INET, ("127.0.0.1", free_port)), (False, "rejected on the way"))

    def test_tcp_failure_modes_mean_blocked(self):
        for error in (TimeoutError("timed out"), PermissionError(1, "Operation not permitted"),
                      OSError(101, "Network is unreachable")):
            with self.subTest(error=error), mock.patch("socket.socket") as factory:
                factory.return_value.connect.side_effect = error
                reached, _ = doctor._tcp(socket.AF_INET, ("192.0.2.1", 443), timeout=0.1)
                self.assertIs(reached, False)

    def test_udp_dns_answer_and_silence(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        self.addCleanup(server.close)
        seen = []

        def answer_once():
            data, peer = server.recvfrom(2048)
            seen.append(data)
            server.sendto(data[:2] + b"\x81\x80" + data[4:], peer)

        threading.Thread(target=answer_once, daemon=True).start()
        self.assertEqual(doctor._udp_dns(server.getsockname(), timeout=2)[0], True)
        self.assertIn(b"\x07example\x03com\x00", seen[0])     # a well-formed query for example.com
        self.assertEqual(doctor._udp_dns(server.getsockname(), timeout=0.2)[0], False)  # nobody answers now

    def test_system_resolver_classification(self):
        cases = [
            (socket.gaierror(socket.EAI_NONAME, "Name or service not known"), True),
            (socket.gaierror(getattr(socket, "EAI_NODATA", socket.EAI_NONAME), "No address associated"), True),
            (socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution"), False),
            (OSError(101, "Network is unreachable"), False),
        ]
        for error, expected in cases:
            with self.subTest(error=error), mock.patch("socket.getaddrinfo", side_effect=error):
                self.assertIs(doctor._system_resolver(timeout=2)[0], expected)
        with mock.patch("socket.getaddrinfo", return_value=[("x",)]):
            self.assertIs(doctor._system_resolver(timeout=2)[0], True)

    def test_system_resolver_asks_for_a_name_nobody_has_cached(self):
        asked = []
        with mock.patch("socket.getaddrinfo", side_effect=lambda name, *a: asked.append(name) or []):
            doctor._system_resolver(timeout=2)
            doctor._system_resolver(timeout=2)
        self.assertEqual(len(set(asked)), 2)
        self.assertTrue(all(name.endswith(".example.com") and len(name) > 40 for name in asked))

    def test_sealed_checks_levels(self):
        blocked = (False, "Operation not permitted")
        with mock.patch.multiple(doctor, _tcp=mock.Mock(return_value=blocked), _udp_dns=mock.Mock(return_value=blocked),
                                 _icmp=mock.Mock(return_value=(None, "not testable")),
                                 _system_resolver=mock.Mock(return_value=blocked)):
            checks = doctor.sealed_checks()
        self.assertEqual({c.level for c in checks}, {doctor.OK})
        self.assertEqual(len(checks), 7)
        open_ = (True, "connected")
        with mock.patch.multiple(doctor, _tcp=mock.Mock(return_value=open_), _udp_dns=mock.Mock(return_value=open_),
                                 _icmp=mock.Mock(return_value=open_), _system_resolver=mock.Mock(return_value=open_)):
            checks = doctor.sealed_checks()
        levels = {c.name: c.level for c in checks}
        self.assertEqual(levels.pop("cloud metadata service"), doctor.WARN)  # often cannot be switched off
        self.assertEqual(set(levels.values()), {doctor.BAD})


class SessionCheckTests(unittest.TestCase):
    def checks(self, env, linger, virt=None):
        clean = {k: v for k, v in os.environ.items() if k not in ("SSH_CONNECTION", "SSH_AUTH_SOCK", "XDG_SESSION_TYPE")}
        with mock.patch.dict(os.environ, {**clean, **env}, clear=True), \
                mock.patch.object(doctor, "_linger", return_value=linger), \
                mock.patch.object(doctor, "_virtualization", return_value=virt):
            return {c.name: c for c in doctor.session_checks()}

    def test_desktop_session_is_quiet(self):
        self.assertEqual(self.checks({"XDG_SESSION_TYPE": "wayland"}, linger=False), {})

    def test_ssh_session_with_forwarded_agent(self):
        found = self.checks({"SSH_CONNECTION": "198.51.100.9 50000 203.0.113.4 22", "SSH_AUTH_SOCK": "/tmp/ssh-x/agent.1",
                             "XDG_SESSION_TYPE": "tty"}, linger=False)
        self.assertEqual(found["SSH agent forwarding"].level, doctor.WARN)
        self.assertIn("ssh -a", found["SSH agent forwarding"].fix)
        self.assertEqual(found["user lingering"].level, doctor.WARN)
        self.assertIn("enable-linger", found["user lingering"].fix)

    def test_ssh_session_set_up_properly(self):
        found = self.checks({"SSH_CONNECTION": "198.51.100.9 50000 203.0.113.4 22", "XDG_SESSION_TYPE": "tty"},
                            linger=True, virt="kvm (Hetzner)")
        self.assertEqual({c.level for c in found.values()}, {doctor.OK})
        self.assertIn("--sealed", found["virtual machine"].detail)

    def test_local_agent_on_a_desktop_is_not_agent_forwarding(self):
        self.assertNotIn("SSH agent forwarding",
                         self.checks({"SSH_AUTH_SOCK": "/run/user/1000/keyring/ssh", "XDG_SESSION_TYPE": "wayland"}, True))


if __name__ == "__main__":
    unittest.main()
