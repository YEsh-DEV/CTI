import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
import json

from tasks.task2_temporal_graph import (
    clean_relation_type,
    parse_temporal_expression,
    resolve_entity,
    prepare_graph_payload,
    write_file_to_graph_tx,
    ingest_extracted_file,
)
from common.neo4j_client import Neo4jClient


class TestTask2TemporalGraph(unittest.TestCase):

    def test_clean_relation_type(self):
        self.assertEqual(clean_relation_type("has_hash"), "HAS_HASH")
        self.assertEqual(clean_relation_type("uses"), "USES")
        self.assertEqual(clean_relation_type("communicates_with"), "COMMUNICATES_WITH")
        self.assertEqual(clean_relation_type("drops-file"), "DROPS_FILE")
        self.assertEqual(clean_relation_type("spies on"), "SPIES_ON")
        self.assertEqual(clean_relation_type(""), "RELATES_TO")
        self.assertEqual(clean_relation_type(None), "RELATES_TO")
        self.assertEqual(clean_relation_type("123_rel"), "REL_123_REL")

    def test_parse_temporal_expression(self):
        # Full date
        tau, raw, prec = parse_temporal_expression("2019-01-30")
        self.assertEqual(tau, "2019-01-30T00:00:00Z")
        self.assertEqual(raw, "2019-01-30")
        self.assertEqual(prec, "day")

        # Partial date: month
        tau, raw, prec = parse_temporal_expression("2018-05")
        self.assertEqual(tau, "2018-05-01T00:00:00Z")
        self.assertEqual(raw, "2018-05")
        self.assertEqual(prec, "month")

        # Partial date: year
        tau, raw, prec = parse_temporal_expression("2018")
        self.assertEqual(tau, "2018-01-01T00:00:00Z")
        self.assertEqual(raw, "2018")
        self.assertEqual(prec, "year")

        # Unknown / None / Invalid
        tau, raw, prec = parse_temporal_expression("unknown")
        self.assertIsNone(tau)
        self.assertEqual(raw, "unknown")
        self.assertEqual(prec, "unknown")

        tau, raw, prec = parse_temporal_expression(None)
        self.assertIsNone(tau)
        self.assertEqual(raw, "unknown")
        self.assertEqual(prec, "unknown")

    def test_resolve_entity_lookup(self):
        entities_lookup = {
            "patchwork": {"name": "Patchwork APT", "type": "ThreatActor", "raw_text": "Patchwork"},
            "powershell": {"name": "PowerShell", "type": "Tool", "raw_text": "PowerShell"},
        }
        warnings = []

        # Hit by text
        name, etype, raw = resolve_entity("patchwork", entities_lookup, "test_source", warnings)
        self.assertEqual(name, "Patchwork APT")
        self.assertEqual(etype, "ThreatActor")
        self.assertEqual(len(warnings), 0)

        # Hit by canonical_name
        name, etype, raw = resolve_entity("PowerShell", entities_lookup, "test_source", warnings)
        self.assertEqual(name, "PowerShell")
        self.assertEqual(etype, "Tool")
        self.assertEqual(len(warnings), 0)

        # Miss -> Unknown fallback with warning
        name, etype, raw = resolve_entity("UnknownActor", entities_lookup, "test_source", warnings)
        self.assertEqual(name, "UnknownActor")
        self.assertEqual(etype, "Unknown")
        self.assertEqual(len(warnings), 1)

    def test_prepare_graph_payload(self):
        extracted_data = {
            "id": "2019_1976",
            "entities": [
                {"text": "Chafer", "type": "ThreatActor", "canonical_name": "Chafer", "confidence": 0.95},
                {"text": "Remexi", "type": "Malware", "canonical_name": "Remexi", "confidence": 0.92},
                {"text": "events.exe", "type": "IOC", "canonical_name": "events.exe", "confidence": 1.0},
            ],
            "relations": [
                {
                    "head": "Chafer",
                    "relation": "uses",
                    "tail": "Remexi",
                    "time": "2019-01-30",
                    "evidence": "Chafer used Remexi malware",
                    "confidence": 0.93,
                },
                {
                    "head": "Remexi",
                    "relation": "drops_file",
                    "tail": "events.exe",
                    "time": "2019-01-30",
                    "evidence": "IOC filename events.exe",
                    "confidence": 1.0,
                },
            ],
        }

        # Mock reading from temporary file
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as tmp:
            json.dump(extracted_data, tmp)
            tmp_path = Path(tmp.name)

        try:
            warnings = []
            source_id, entities_payload, relations_by_type = prepare_graph_payload(tmp_path, warnings)

            self.assertEqual(source_id, "2019_1976")
            self.assertEqual(len(entities_payload), 3)

            ent_names = {e["name"] for e in entities_payload}
            self.assertEqual(ent_names, {"Chafer", "Remexi", "events.exe"})

            # Relations grouped by type
            self.assertIn("USES", relations_by_type)
            self.assertIn("DROPS_FILE", relations_by_type)
            self.assertEqual(len(relations_by_type["USES"]), 1)
            self.assertEqual(len(relations_by_type["DROPS_FILE"]), 1)

            use_rel = relations_by_type["USES"][0]
            self.assertEqual(use_rel["head_name"], "Chafer")
            self.assertEqual(use_rel["tail_name"], "Remexi")
            self.assertEqual(use_rel["tau"], "2019-01-30T00:00:00Z")
            self.assertEqual(use_rel["tau_precision"], "day")
            self.assertEqual(use_rel["confidence"], 0.93)
            self.assertEqual(use_rel["source"], "2019_1976")
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_write_file_to_graph_tx_mocked(self):
        mock_tx = MagicMock()
        entities_payload = [
            {"name": "Legora", "type": "Product", "raw_text": "Legora", "tau": "2026-08-17T00:00:00Z"},
            {"name": "CVE-2026-74234", "type": "Vulnerability", "raw_text": "CVE-2026-74234", "tau": "2026-08-17T00:00:00Z"},
        ]
        relations_by_type = {
            "HAS_VULNERABILITY": [
                {
                    "head_name": "Legora",
                    "head_type": "Product",
                    "tail_name": "CVE-2026-74234",
                    "tail_type": "Vulnerability",
                    "source": "CVE-2026-74234",
                    "tau": "2026-08-17T00:00:00Z",
                    "tau_raw": "2026-08-17",
                    "tau_precision": "day",
                    "evidence": "XSS vulnerability in Legora",
                    "confidence": 1.0,
                    "created_at": "2026-08-18T22:00:00Z",
                }
            ]
        }

        write_file_to_graph_tx(mock_tx, entities_payload, relations_by_type)

        # 1 run for entities + 1 run for HAS_VULNERABILITY
        self.assertEqual(mock_tx.run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
