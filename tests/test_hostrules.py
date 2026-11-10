import os
import tempfile
import unittest
from pathlib import Path

from silo import hostrules


class HostRuleTests(unittest.TestCase):
    def subuid(self, text: str) -> Path:
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        self.addCleanup(os.unlink, path)
        return Path(path)

    def test_subuid_ranges_for_this_user_only(self):
        path = self.subuid("alice:100000:65536\n4242:300000:1000\nbob:200000:65536\nbroken line\n4242:x:1\n")
        self.assertEqual(hostrules.subuid_ranges(path, uid=4242), [(300000, 1000)])
        self.assertEqual(hostrules.subuid_ranges(path, uid=999999), [])

    def test_container_uid_mapping(self):
        # container UID 0 is the invoking user; container UID n is the (n-1)th subordinate UID
        self.assertEqual(hostrules.sandbox_host_uid([(524288, 65536)]), 589821)
        self.assertEqual(hostrules.sandbox_host_uid([(524288, 65536)], container_uid=1), 524288)
        self.assertEqual(hostrules.sandbox_host_uid([(100000, 1000), (200000, 65536)], container_uid=1000), 100999)
        self.assertEqual(hostrules.sandbox_host_uid([(100000, 1000), (200000, 65536)], container_uid=1001), 200000)
        for ranges, uid in (([], 65534), ([(100000, 1000)], 65534), ([(524288, 65536)], 0)):
            with self.subTest(ranges=ranges, uid=uid), self.assertRaises(hostrules.HostRuleError):
                hostrules.sandbox_host_uid(ranges, container_uid=uid)

    def test_ruleset(self):
        rules = hostrules.nft_ruleset(589821)
        self.assertIn("meta skuid 589821 counter drop", rules)
        self.assertIn("hook output", rules)
        self.assertIn("policy accept", rules)  # everything else on the host is untouched
        statements = [line for line in rules.splitlines() if line and not line.startswith("#")]
        # declare, delete, define: applying it twice replaces the table instead of failing or duplicating
        self.assertEqual(statements[:3], ["table inet silo", "delete table inet silo", "table inet silo {"])

    def test_sealed_ruleset(self):
        rules = hostrules.nft_ruleset(589821, sealed=True)
        body = [line.strip() for line in rules.splitlines() if line.strip() and not line.startswith("#")]
        self.assertIn("type filter hook output priority filter; policy drop;", body)
        self.assertNotIn("policy accept", rules)
        self.assertEqual(body[:3], ["table inet silo", "delete table inet silo", "table inet silo {"])
        # the sandbox UID is refused before loopback is allowed, so it gets no loopback either
        self.assertLess(body.index(next(l for l in body if l.startswith("meta skuid 589821"))),
                        body.index('oifname "lo" accept'))
        accepts = [l for l in body if " accept" in l]
        self.assertEqual(len(accepts), 5)  # loopback, SSH replies, DHCP, DHCPv6, IPv6 neighbour discovery
        self.assertTrue(accepts[1].startswith("tcp sport 22 accept"))
        self.assertTrue(any(l.startswith("udp sport 68 udp dport 67 accept") for l in accepts))
        self.assertTrue(any("nd-neighbor-solicit" in l for l in accepts))

    def test_sealed_ruleset_is_stateless(self):
        # "ct state established accept" would let an escaped process that listens on a port be reached
        # from outside, and would freeze the SSH session the rules are loaded from.
        body = "\n".join(l for l in hostrules.nft_ruleset(589821, sealed=True).splitlines() if not l.startswith("#"))
        self.assertNotIn("ct state", body)
        self.assertNotIn("established", body)

    def test_sealed_ruleset_ssh_port(self):
        rules = hostrules.nft_ruleset(589821, sealed=True, ssh_port=2222)
        self.assertIn("tcp sport 2222 accept", rules)
        self.assertNotIn("tcp sport 22 accept", rules)
        self.assertIn("SSH SERVER PORT: 2222", rules)  # stated in the file, where the reviewer reads it
        for bad in (0, -1, 65536):
            with self.subTest(port=bad), self.assertRaises(hostrules.HostRuleError):
                hostrules.nft_ruleset(589821, sealed=True, ssh_port=bad)
        self.assertNotIn("sport", hostrules.nft_ruleset(589821, ssh_port=2222))  # the plain rule has no SSH part

    def test_missing_subuid_file(self):
        with self.assertRaises(hostrules.HostRuleError):
            hostrules.subuid_ranges(Path("/nonexistent/subuid"))


if __name__ == "__main__":
    unittest.main()
