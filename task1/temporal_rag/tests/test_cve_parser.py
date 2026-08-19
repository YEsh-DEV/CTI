import unittest
from pathlib import Path
from ingestion.parsers.cve_parser import parse_cve_file, parse_cve_dict

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class TestCVEParser(unittest.TestCase):

    def test_parse_sample_cve(self):
        cve_path = FIXTURES_DIR / "sample_cve.json"
        cve = parse_cve_file(cve_path)
        self.assertIsNotNone(cve)
        self.assertEqual(cve.cve_id, "CVE-2026-74234")
        self.assertEqual(cve.title, "Legora < 2026-08-14 XSS via Mermaid gray-matter JavaScript Engine")
        self.assertEqual(cve.cwe_id, "CWE-95")
        self.assertEqual(cve.affected_vendor, "Legora")
        self.assertEqual(cve.affected_product, "Legora")
        self.assertIn("<2026-08-14", cve.affected_versions)
        self.assertEqual(cve.references, ["https://legora.com/"])

    def test_cvss_priority_cvss31_over_cvss40(self):
        cve_path = FIXTURES_DIR / "sample_cve.json"
        cve = parse_cve_file(cve_path)
        self.assertIsNotNone(cve)
        # sample_cve.json has both cvssV4_0 (5.1) and cvssV3_1 (7.7). Must prefer 3.1.
        self.assertEqual(cve.cvss_version, "3.1")
        self.assertEqual(cve.cvss_score, 7.7)
        self.assertEqual(cve.cvss_severity, "HIGH")

    def test_cvss40_fallback_when_cvss31_absent(self):
        raw_dict = {
            "cveMetadata": {
                "cveId": "CVE-2026-99999",
                "datePublished": "2026-01-01T00:00:00Z"
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Test description"}],
                    "metrics": [
                        {
                            "cvssV4_0": {
                                "version": "4.0",
                                "baseScore": 6.5,
                                "baseSeverity": "MEDIUM",
                                "vectorString": "CVSS:4.0/..."
                            }
                        }
                    ]
                }
            }
        }
        cve = parse_cve_dict(raw_dict)
        self.assertIsNotNone(cve)
        self.assertEqual(cve.cvss_version, "4.0")
        self.assertEqual(cve.cvss_score, 6.5)
        self.assertEqual(cve.cvss_severity, "MEDIUM")

    def test_missing_optional_fields(self):
        minimal_dict = {
            "cveMetadata": {
                "cveId": "CVE-2026-00001",
                "datePublished": "2026-01-01T00:00:00Z"
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Minimal vulnerability description"}]
                }
            }
        }
        cve = parse_cve_dict(minimal_dict)
        self.assertIsNotNone(cve)
        self.assertEqual(cve.cve_id, "CVE-2026-00001")
        self.assertEqual(cve.cvss_version, "none")
        self.assertIsNone(cve.cvss_score)
        self.assertIsNone(cve.cwe_id)
        self.assertEqual(cve.affected_versions, [])
        self.assertEqual(cve.references, [])


if __name__ == "__main__":
    unittest.main()
