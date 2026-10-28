"""Offline guards for the funded legacy Binohash subset comparison."""

import copy
import json
import unittest
from pathlib import Path

from binohash_core_regtest import POLICY_REJECTION, RELEASE, report_passed

REPORT = Path(__file__).resolve().parents[1] / "tests/data/binohash-core-v30.3.json"


class BinohashCoreHarnessTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads(REPORT.read_text())

    def test_checked_report_passes(self):
        self.assertTrue(self.report["run_passed"])
        self.assertTrue(report_passed(self.report))
        self.assertEqual(self.report["bitcoin_core"]["commit"], RELEASE["commit"])

    def test_consensus_and_policy_are_distinct(self):
        for row in self.report["results"]:
            self.assertTrue(row["valid"]["consensus"]["accepted"])
            self.assertFalse(row["valid"]["policy"]["allowed"])
            self.assertEqual(row["valid"]["policy"]["reject-reason"], POLICY_REJECTION)
            self.assertFalse(row["wrong_selection"]["consensus"]["accepted"])

    def test_mutated_report_cannot_pass(self):
        mutations = [
            ("bitcoin_core", "commit", "unknown"),
            ("results", 0, "local_digest_hex", self.report["results"][1]["local_digest_hex"]),
            ("results", 0, "valid", "consensus", "accepted", False),
            ("results", 1, "wrong_selection", "consensus", "rpc_code", -26),
            ("results", 0, "wrong_selection", "consensus", "reason", "script failed"),
            ("results", 0, "valid", "policy", "allowed", True),
            ("results", 1, "valid", "policy", "reject-reason", "some other rule"),
            ("results", 0, "valid", "decoded", "txid", "00" * 32),
        ]
        for *path, value in mutations:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.report)
                target = changed
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assertFalse(report_passed(changed))


if __name__ == "__main__":
    unittest.main()
