"""Offline guards for the stored absolute-finality/Core comparison."""

import copy
import json
import unittest
from pathlib import Path

from tapscript_finality_regtest import BLOCK_REJECTION, NAMES, report_passed

REPORT = Path(__file__).resolve().parents[1] / "tests/data/tapscript-finality-v30.3.json"


class AbsoluteFinalityReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT.read_text())

    def test_stored_comparison_passes(self):
        self.assertTrue(self.report["run_passed"])
        self.assertTrue(report_passed(self.report))
        self.assertEqual({row["name"] for row in self.report["results"]}, set(NAMES))

    def test_rejects_changed_source_and_boundary(self):
        for key, value in (("source_manifest_experiment", "wrong"),
                           ("source_manifest_fixture_count", 2)):
            report = copy.deepcopy(self.report)
            report[key] = value
            self.assertFalse(report_passed(report))
        report = copy.deepcopy(self.report)
        report["bitcoin_core"]["commit"] = "wrong"
        self.assertFalse(report_passed(report))
        report = copy.deepcopy(self.report)
        report["first_eligible_context"]["candidate_parent_mtp"] = \
            report["equality_context"]["candidate_parent_mtp"]
        self.assertFalse(report_passed(report))

    def test_rejects_wrong_local_identity_and_core_category(self):
        report = copy.deepcopy(self.report)
        report["results"][0]["equality"]["local_absolute_finality"]["txid"] = "00" * 32
        self.assertFalse(report_passed(report))
        report = copy.deepcopy(self.report)
        report["results"][0]["equality"]["core"]["consensus"]["reason"] = \
            BLOCK_REJECTION.replace("bad-txns-nonfinal", "bad-txns-inputs-missingorspent")
        self.assertFalse(report_passed(report))
        report = copy.deepcopy(self.report)
        report["results"][1]["first_eligible"]["local_absolute_finality"]["verdict"] = "nonfinal"
        self.assertFalse(report_passed(report))


if __name__ == "__main__":
    unittest.main()
