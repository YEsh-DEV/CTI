"""
Unit and Integration Tests for Task 5: Temporal-Causal GraphRAG.
"""

import datetime
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import faiss
import numpy as np

from common.embedding_client import EmbeddingClient
from common.faiss_index import FAISSIndexManager, get_faiss_manager
from common.llm_client import OllamaClient
from common.neo4j_client import Neo4jClient
from tasks.task5_graph_rag import (
    GraphRAGPipeline,
    approx_token_count,
    _parse_date,
)


class TestTask5FAISSIndex(unittest.TestCase):
    """Tests for FAISS index construction, persistence, and semantic search."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.index_path = Path(self.temp_dir.name) / "test_index.faiss"
        self.metadata_path = Path(self.temp_dir.name) / "test_metadata.jsonl"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_faiss_build_and_search_synthetic(self):
        """Test building FAISS index with synthetic embeddings and querying nearest neighbor."""
        mock_embedding_client = MagicMock(spec=EmbeddingClient)
        # 3 entities with 4-dim unit vectors
        mock_vectors = np.array([
            [1.0, 0.0, 0.0, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [0.7071, 0.7071, 0.0, 0.0],
        ], dtype=np.float32)
        mock_embedding_client.encode.return_value = mock_vectors

        mock_neo4j = MagicMock(spec=Neo4jClient)
        mock_neo4j.execute_query.return_value = [
            {"node_id": "4:0", "name": "APT28", "type": "ThreatActor", "canonical_id": "APT28"},
            {"node_id": "4:1", "name": "Cobalt Strike", "type": "Tool", "canonical_id": "Cobalt Strike"},
            {"node_id": "4:2", "name": "APT29", "type": "ThreatActor", "canonical_id": "APT29"},
        ]

        manager = FAISSIndexManager(
            index_path=self.index_path,
            metadata_path=self.metadata_path,
            embedding_client=mock_embedding_client,
        )
        count = manager.build_index(client=mock_neo4j)
        self.assertEqual(count, 3)
        self.assertTrue(self.index_path.exists())
        self.assertTrue(self.metadata_path.exists())

        # Test search query closest to APT28
        mock_embedding_client.encode.return_value = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
        results = manager.search("Find Russian APT", k=2)
        self.assertGreaterEqual(len(results), 1)
        self.assertEqual(results[0]["canonical_id"], "APT28")
        self.assertAlmostEqual(results[0]["similarity"], 1.0, places=3)


class TestTask5GraphTraversalAndTemporal(unittest.TestCase):
    """Tests for graph traversal, temporal chain extraction, and context assembly."""

    def test_parse_date_formats(self):
        """Test _parse_date handles diverse date formats properly."""
        self.assertEqual(_parse_date("2021-05-18"), datetime.date(2021, 5, 18))
        self.assertEqual(_parse_date("2018-09-13T00:00:00Z"), datetime.date(2018, 9, 13))
        dt = datetime.datetime(2020, 1, 1, 12, 0, 0)
        self.assertEqual(_parse_date(dt), datetime.date(2020, 1, 1))
        self.assertIsNone(_parse_date(None))
        self.assertIsNone(_parse_date("unknown"))

    def test_extract_temporal_chains_synthetic(self):
        """Test identifying chronological paths vs falling back to structural paths."""
        pipeline = GraphRAGPipeline(
            neo4j_client=MagicMock(),
            faiss_manager=MagicMock(),
            llm_client=MagicMock(),
        )

        synthetic_paths = [
            {
                "hops": [
                    {
                        "head_canonical": "APT28", "head_type": "ThreatActor",
                        "rel_type": "USES", "tail_canonical": "X-Agent", "tail_type": "Malware",
                        "tau_date": datetime.date(2018, 1, 1), "evidence": "Used X-Agent",
                        "trust": 0.85, "trusted": True, "source": "2018_1", "confidence": 0.9,
                    },
                    {
                        "head_canonical": "X-Agent", "head_type": "Malware",
                        "rel_type": "EXPLOITS", "tail_canonical": "CVE-2018-1234", "tail_type": "Vulnerability",
                        "tau_date": datetime.date(2018, 6, 1), "evidence": "Exploited CVE",
                        "trust": 0.82, "trusted": True, "source": "2018_1", "confidence": 0.9,
                    },
                ],
                "path_trust": 0.697,
                "length": 2,
            },
            {
                "hops": [
                    {
                        "head_canonical": "Lazarus", "head_type": "ThreatActor",
                        "rel_type": "TARGETS", "tail_canonical": "Finance", "tail_type": "Target",
                        "tau_date": None, "evidence": "Targeted Finance",
                        "trust": 0.70, "trusted": False, "source": "2019_2", "confidence": 0.8,
                    }
                ],
                "path_trust": 0.70,
                "length": 1,
            }
        ]

        temporal_chains = pipeline.extract_temporal_paths(synthetic_paths, max_chains=5)
        self.assertGreaterEqual(len(temporal_chains), 1)
        self.assertEqual(temporal_chains[0]["type"], "temporal_causal")
        self.assertEqual(len(temporal_chains[0]["hops"]), 2)

    def test_build_context_and_truncation(self):
        """Test constructing GraphRAG prompt context and token budget enforcement."""
        pipeline = GraphRAGPipeline(
            neo4j_client=MagicMock(),
            faiss_manager=MagicMock(),
            llm_client=MagicMock(),
        )

        temporal_paths = [{
            "type": "temporal_causal",
            "path_trust": 0.85,
            "hops": [{
                "head_type": "ThreatActor", "head_canonical": "APT10",
                "rel_type": "USES", "tail_type": "Tool", "tail_canonical": "Chチ",
                "tau_raw": "2019-02-06", "evidence": "Observed in report", "source": "2019_1805"
            }]
        }]

        facts = [
            {
                "head_type": "ThreatActor", "head_canonical": "APT10",
                "rel_type": "TARGETS", "tail_type": "Target", "tail_canonical": "US MSP",
                "trust": 0.85, "confidence": 0.9, "source": "2019_1805", "trusted": True
            },
            {
                "head_type": "ThreatActor", "head_canonical": "APT10",
                "rel_type": "COMMUNICATES_WITH", "tail_type": "IOC", "tail_canonical": "1.2.3.4",
                "trust": 0.65, "confidence": 0.8, "source": "2019_1805", "trusted": False
            },
        ]

        context, stats = pipeline.build_context(
            query="Tell me about APT10",
            temporal_paths=temporal_paths,
            facts=facts,
            max_tokens=4096,
        )

        self.assertIn("=== RETRIEVED GRAPH CONTEXT ===", context)
        self.assertIn("APT10", context)
        self.assertIn("[Temporal & Causal Paths]", context)
        self.assertIn("[Supporting Facts & Relations]", context)
        self.assertEqual(stats["trusted_facts_used"], 1)
        self.assertEqual(stats["untrusted_facts_used"], 1)
        self.assertGreater(stats["token_count"], 10)

    def test_llm_reasoning_mocked(self):
        """Test LLM reasoning stage with mocked Ollama response and think-tag removal."""
        mock_llm = MagicMock(spec=OllamaClient)
        mock_llm.generate_chat_completion.return_value = (
            "<think>\nAnalyzing the graph paths for APT10...\n</think>\n"
            "Based on the provided graph context, APT10 targeted US MSPs in 2019 using specific tools (Source: 2019_1805)."
        )

        pipeline = GraphRAGPipeline(
            neo4j_client=MagicMock(),
            faiss_manager=MagicMock(),
            llm_client=mock_llm,
        )

        answer = pipeline.generate_reasoning("What did APT10 target?", "Graph context...")
        self.assertNotIn("<think>", answer)
        self.assertIn("APT10 targeted US MSPs", answer)
        self.assertIn("2019_1805", answer)


class TestTask5Integration(unittest.TestCase):
    """Integration tests running against live Neo4j and FAISS."""

    def test_stage1_semantic_retrieval_real(self):
        """Test real FAISS retrieval with live index."""
        faiss_mgr = get_faiss_manager()
        if not faiss_mgr.index_path.exists():
            faiss_mgr.build_index()

        results = faiss_mgr.search("APT28 Fancy Bear cyber espionage", k=5)
        self.assertGreater(len(results), 0)
        self.assertTrue(any("APT" in r.get("canonical_id", "") or r.get("type") == "ThreatActor" for r in results))

    def test_stage2_graph_traversal_real_neo4j(self):
        """Test real Neo4j multi-hop graph traversal."""
        pipeline = GraphRAGPipeline()
        seeds = [{"canonical_id": "APT10", "type": "ThreatActor", "name": "APT10"}]
        paths, facts = pipeline.traverse_graph_paths(seeds, depth=2)
        # Graph should return at least some paths or facts for APT10
        self.assertIsInstance(paths, list)
        self.assertIsInstance(facts, list)


if __name__ == "__main__":
    unittest.main()
