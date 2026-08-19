import unittest
from pathlib import Path
from ingestion.parsers.cti_misp_xml_parser import parse_cti_xml_file, merge_cti_events

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class TestCTIParser(unittest.TestCase):

    def test_xml_entity_unescaping(self):
        malware_file = FIXTURES_DIR / "sample_malware.xml"
        events = parse_cti_xml_file(malware_file)
        # Key is (year, event_id)
        matching_key = next((k for k in events.keys() if k[1] == 1976), None)
        self.assertIsNotNone(matching_key)
        event_1976 = events[matching_key]
        
        # Check that &lt;MWS_SAMPLE_DIR&gt; was properly unescaped to <MWS_SAMPLE_DIR>
        values = [attr.value for attr in event_1976["attributes"]]
        self.assertTrue(any("<MWS_SAMPLE_DIR>/events.exe" in v for v in values))

    def test_empty_root_handling(self):
        empty_file = FIXTURES_DIR / "sample_empty.xml"
        events = parse_cti_xml_file(empty_file)
        self.assertEqual(events, {})

    def test_merge_by_composite_key(self):
        malware_file = FIXTURES_DIR / "sample_malware.xml"
        report_file = FIXTURES_DIR / "sample_report.xml"

        parsed_malware = parse_cti_xml_file(malware_file)
        parsed_report = parse_cti_xml_file(report_file)

        merged = merge_cti_events([parsed_malware, parsed_report])
        
        # We should have 2 distinct merged events: 1976 and 9999
        self.assertEqual(len(merged), 2)

        event_map = {e.event_id: e for e in merged}
        self.assertIn(1976, event_map)
        self.assertIn(9999, event_map)

        e1976 = event_map[1976]
        # Should have source files from both
        self.assertEqual(set(e1976.source_files), {"sample_malware.xml", "sample_report.xml"})

        # Check attribute union and deduplication
        self.assertEqual(len(e1976.iocs), 3)

        ioc_types = {ioc.type for ioc in e1976.iocs}
        self.assertEqual(ioc_types, {"filename", "md5", "ip-src"})

        # Event 9999 appeared in only one file; ensure it merged cleanly
        e9999 = event_map[9999]
        self.assertEqual(e9999.source_files, ["sample_malware.xml"])
        self.assertEqual(len(e9999.iocs), 1)


if __name__ == "__main__":
    unittest.main()
