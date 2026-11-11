import os
import socket
import subprocess
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
    def checks(self, env, linger):
        clean = {k: v for k, v in os.environ.items() if k not in ("SSH_CONNECTION", "SSH_AUTH_SOCK", "XDG_SESSION_TYPE")}
        with mock.patch.dict(os.environ, {**clean, **env}, clear=True), \
                mock.patch.object(doctor, "_linger", return_value=linger):
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
                            linger=True)
        self.assertEqual(set(found), {"SSH agent forwarding", "user lingering"})
        self.assertEqual({c.level for c in found.values()}, {doctor.OK})

    def test_local_agent_on_a_desktop_is_not_agent_forwarding(self):
        self.assertNotIn("SSH agent forwarding",
                         self.checks({"SSH_AUTH_SOCK": "/run/user/1000/keyring/ssh", "XDG_SESSION_TYPE": "wayland"}, True))


class KernelIsolationTests(unittest.TestCase):
    """The one finding that says where a kernel exploit would land."""

    def test_physical_machine_points_at_the_boundaries_silo_ships(self):
        for sealed in (None, True, False):  # a sealed physical machine still shares its kernel with the sandbox
            check = doctor.kernel_isolation_check(None, sealed, [])
            self.assertEqual(check.level, doctor.WARN)
            self.assertIn("your own account", check.detail)
            self.assertIn("docs/LOCAL_VM.md", check.fix)
            self.assertIn("docs/VPS.md", check.fix)
            self.assertNotIn("roadmap", check.detail + check.fix)

    def test_installed_but_unused_runtimes_are_named(self):
        check = doctor.kernel_isolation_check(None, None, ["runsc"])
        self.assertIn("runsc is installed; silo does not use it yet", check.detail)
        self.assertNotIn("installed", doctor.kernel_isolation_check(None, None, []).detail)

    def test_virtual_machine_counts_only_once_it_is_shown_to_be_sealed(self):
        untested = doctor.kernel_isolation_check("kvm, QEMU", None, [])
        self.assertEqual(untested.level, doctor.WARN)
        self.assertIn("silo doctor --sealed", untested.fix)
        sealed = doctor.kernel_isolation_check("kvm, QEMU", True, [])
        self.assertEqual((sealed.level, sealed.fix), (doctor.OK, ""))
        self.assertIn("kvm, QEMU", sealed.detail)
        leaking = doctor.kernel_isolation_check("kvm, QEMU", False, [])
        self.assertEqual(leaking.level, doctor.WARN)
        self.assertIn("can reach the network", leaking.detail)


class RunChecksTests(unittest.TestCase):
    """run_checks end to end, with the host tools it shells out to replaced."""

    PODMAN = {"host": {"security": {"rootless": True, "selinuxEnabled": True}, "ociRuntime": {"name": "crun"},
                       "cgroupVersion": "v2", "cgroupControllers": ["cpu", "memory", "pids"]}}

    def run_checks(self, virt, sealed, systemctl_missing=False):
        def fake_run(cmd, *args, **kwargs):
            if cmd[0] == "systemctl" and systemctl_missing:
                raise FileNotFoundError("systemctl")
            return subprocess.CompletedProcess(cmd, 0, stdout="inactive\n", stderr="")

        from silo.config import Config
        with mock.patch.object(doctor.shutil, "which", side_effect=lambda name: "/usr/bin/podman" if name == "podman" else None), \
                mock.patch.object(doctor, "_podman_info", return_value=self.PODMAN), \
                mock.patch.object(doctor, "_virtualization", return_value=virt), \
                mock.patch.object(doctor, "_linger", return_value=None), \
                mock.patch.object(doctor.subprocess, "run", side_effect=fake_run):
            return {c.name: c for c in doctor.run_checks(Config(), sealed=sealed)}

    def test_sealed_result_reaches_the_kernel_isolation_finding(self):
        self.assertEqual(self.run_checks("kvm, QEMU", True)["kernel isolation"].level, doctor.OK)
        self.assertEqual(self.run_checks("kvm, QEMU", False)["kernel isolation"].level, doctor.WARN)
        self.assertEqual(self.run_checks("kvm, QEMU", None)["kernel isolation"].level, doctor.WARN)
        self.assertEqual(self.run_checks(None, True)["kernel isolation"].level, doctor.WARN)

    def test_there_is_exactly_one_line_about_virtualisation(self):
        names = list(self.run_checks("kvm, QEMU", None))
        self.assertEqual(names.count("kernel isolation"), 1)
        self.assertNotIn("virtual machine", names)

    def test_doctor_runs_without_systemd(self):
        checks = self.run_checks(None, None, systemctl_missing=True)
        self.assertIn("podman API socket", checks)
        self.assertIn("tool calling", checks)  # it got all the way to the end


if __name__ == "__main__":
    unittest.main()
