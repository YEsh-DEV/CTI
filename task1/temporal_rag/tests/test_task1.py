import unittest
from unittest.mock import MagicMock
from datetime import date, datetime
from schemas.normalized import IOC, NormalizedCTIEvent, NormalizedCVE
from schemas.extraction import (
    ExtractedEntity,
    ExtractedRelation,
    UnifiedExtractionResult,
)
from common.llm_client import strip_think_tags, extract_json_object, OllamaClient
from tasks.task1_extraction import (
    extract_deterministic_cti_iocs,
    extract_llm_cti_knowledge,
    extract_cve_knowledge,
    _parse_confidence,
)


class TestTask1UnifiedExtraction(unittest.TestCase):

    def test_strip_think_tags(self):
        raw = "<think>\nReasoning text\n</think>\n```json\n{\"entities\": []}\n```"
        cleaned = strip_think_tags(raw)
        self.assertNotIn("<think>", cleaned)
        self.assertNotIn("Reasoning", cleaned)
        self.assertTrue(cleaned.startswith("```json"))

    def test_parse_confidence_floats_and_ranges(self):
        self.assertEqual(_parse_confidence(0.95), 0.95)
        self.assertEqual(_parse_confidence("0.85"), 0.85)
        self.assertEqual(_parse_confidence("0.7-0.8"), 0.75)
        self.assertEqual(_parse_confidence("invalid", default=0.8), 0.8)

    def test_extract_deterministic_cti_iocs(self):
        event = NormalizedCTIEvent(
            id="2019_1976",
            year=2019,
            event_id=1976,
            date=date(2019, 1, 30),
            info_title="Chafer used Remexi malware.pdf",
            iocs=[
                IOC(category="Payload installation", type="md5", value="44d88612fea8a8f36de82e1278abb02f"),
                IOC(category="Network activity", type="ip-src", value="108.61.189.174"),
                IOC(category="External analysis", type="filename", value="events.exe"),
                IOC(category="Network activity", type="url", value="http://malicious.com/api"),
            ],
            source_files=["sample.xml"],
        )
        entities, relations = extract_deterministic_cti_iocs(event)
        
        # 4 IOC entities + 1 EvidenceSource head entity
        self.assertEqual(len(entities), 5)
        ent_types = {e.type for e in entities}
        self.assertEqual(ent_types, {"IOC", "EvidenceSource"})

        # 4 relations
        self.assertEqual(len(relations), 4)
        rel_map = {r.tail: r.relation for r in relations}
        self.assertEqual(rel_map["44d88612fea8a8f36de82e1278abb02f"], "has_hash")
        self.assertEqual(rel_map["108.61.189.174"], "communicates_with")
        self.assertEqual(rel_map["events.exe"], "drops_file")
        self.assertEqual(rel_map["http://malicious.com/api"], "uses_domain")

        for r in relations:
            self.assertEqual(r.confidence, 1.0)
            self.assertEqual(r.time, "2019-01-30")

    def test_cve_deduplication_legora(self):
        cve = NormalizedCVE(
            cve_id="CVE-2026-74234",
            date_published=datetime(2026, 8, 17, 19, 38, 5),
            date_public=datetime(2026, 8, 17, 0, 0, 0),
            title="Legora XSS",
            description="Legora before 2026-08-14 contains an eval XSS vulnerability.",
            affected_vendor="Legora",
            affected_product="Legora",
            affected_versions=["<2026-08-14"],
            cvss_score=7.7,
            cvss_version="3.1",
        )
        entities, relations = extract_cve_knowledge(cve)
        self.assertEqual(len(entities), 2)
        # Should be "Legora", NOT "Legora Legora"
        product_entity = next(e for e in entities if e.type == "Product")
        self.assertEqual(product_entity.text, "Legora")
        self.assertEqual(product_entity.canonical_name, "Legora")

        self.assertEqual(len(relations), 1)
        rel = relations[0]
        self.assertEqual(rel.head, "Legora")
        self.assertEqual(rel.relation, "has_vulnerability")
        self.assertEqual(rel.tail, "CVE-2026-74234")
        self.assertEqual(rel.time, "2026-08-17")
        self.assertEqual(rel.confidence, 1.0)

    def test_llm_extraction_mocked(self):
        event = NormalizedCTIEvent(
            id="2019_1976",
            year=2019,
            event_id=1976,
            date=date(2019, 1, 30),
            info_title="Chafer used Remexi malware to spy on Iran-based foreign diplomatic entities.pdf",
            iocs=[],
            source_files=["sample.xml"],
        )

        mock_client = MagicMock(spec=OllamaClient)
        mock_client.extract_structured_json.return_value = (
            {
                "entities": [
                    {"text": "Chafer", "type": "ThreatActor", "canonical_name": "Chafer", "confidence": 0.95},
                    {"text": "Remexi", "type": "Malware", "canonical_name": "Remexi", "confidence": 0.92},
                    {"text": "Iran-based foreign diplomatic entities", "type": "Target", "canonical_name": "Iran Foreign Diplomatic Entities", "confidence": 0.88},
                ],
                "relations": [
                    {
                        "head": "Chafer",
                        "relation": "uses",
                        "tail": "Remexi",
                        "time": "2019-01-30",
                        "evidence": "Chafer used Remexi malware to spy on Iran-based foreign diplomatic entities.",
                        "confidence": 0.93,
                    },
                    {
                        "head": "Chafer",
                        "relation": "spies_on",
                        "tail": "Iran-based foreign diplomatic entities",
                        "time": "2019-01-30",
                        "evidence": "Chafer used Remexi malware to spy on Iran-based foreign diplomatic entities.",
                        "confidence": 0.89,
                    },
                ],
            },
            "<think>mock reasoning</think>json_output",
        )

        entities, relations = extract_llm_cti_knowledge(event, mock_client)
        self.assertEqual(len(entities), 3)
        self.assertEqual(len(relations), 2)
        self.assertEqual(entities[0].confidence, 0.95)
        self.assertEqual(entities[2].confidence, 0.88)
        self.assertEqual(relations[0].confidence, 0.93)
        self.assertEqual(relations[1].confidence, 0.89)

    def test_llm_extraction_null_negative_control(self):
        event = NormalizedCTIEvent(
            id="2019_9999",
            year=2019,
            event_id=9999,
            date=date(2019, 2, 1),
            info_title="1234567890abcdef.exe",
            iocs=[],
            source_files=["sample.xml"],
        )

        mock_client = MagicMock(spec=OllamaClient)
        mock_client.extract_structured_json.return_value = (
            {"entities": [], "relations": []},
            "<think>No threat actor found</think>json_output",
        )

        entities, relations = extract_llm_cti_knowledge(event, mock_client)
        self.assertEqual(len(entities), 0)
        self.assertEqual(len(relations), 0)


if __name__ == "__main__":
    unittest.main()
