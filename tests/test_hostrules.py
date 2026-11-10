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

    def test_missing_subuid_file(self):
        with self.assertRaises(hostrules.HostRuleError):
            hostrules.subuid_ranges(Path("/nonexistent/subuid"))


if __name__ == "__main__":
    unittest.main()
