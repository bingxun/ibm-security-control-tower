import unittest

from agent.graph import make_initial_state
from agent.nodes.ingest import ingest_node


def vuln(cve, severity):
    return {"VulnerabilityID": cve, "Severity": severity, "PkgName": "pkg", "InstalledVersion": "1",
            "CVSS": {"nvd": {"V3Score": 5.0}}}


TRIVY = {"Results": [{"Vulnerabilities": [
    vuln("CVE-C", "CRITICAL"), vuln("CVE-H", "HIGH"), vuln("CVE-M", "MEDIUM"), vuln("CVE-L", "LOW")]}]}


def run(**kwargs):
    state = make_initial_state(TRIVY, image_ref="img", **kwargs)
    return sorted(c["id"] for c in ingest_node(state)["cves"])


class TestSeveritySelection(unittest.TestCase):
    def test_all_severities_selected(self):
        self.assertEqual(run(severities=["critical", "high", "medium", "low"]),
                         ["CVE-C", "CVE-H", "CVE-L", "CVE-M"])

    def test_any_combination_not_just_a_minimum(self):
        self.assertEqual(run(severities=["critical", "medium"]), ["CVE-C", "CVE-M"])
        self.assertEqual(run(severities=["low"]), ["CVE-L"])

    def test_old_threshold_still_works_when_no_severities_given(self):
        self.assertEqual(run(severity_threshold="high"), ["CVE-C", "CVE-H"])


if __name__ == "__main__":
    unittest.main()
