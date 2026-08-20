"""
Unit tests for Task 4: Entity Alignment & Canonicalization.
"""

import datetime
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common.embedding_client import EmbeddingClient
from tasks.task4_alignment import (
    DisjointSetUnion,
    EntityAlignmentPipeline,
    check_temporal_overlap,
    normalize_entity_name,
)


class TestTask4Alignment(unittest.TestCase):

    def test_normalize_entity_name(self):
        """Test normalization removes punctuation and excess spaces and lowercases."""
        self.assertEqual(normalize_entity_name("APT-28"), "apt 28")
        self.assertEqual(normalize_entity_name("Cobalt Strike..."), "cobalt strike")
        self.assertEqual(normalize_entity_name("  Fancy   Bear_v2 "), "fancy bear v2")
        self.assertEqual(normalize_entity_name(""), "")

    def test_check_temporal_overlap(self):
        """Test temporal overlap and 730-day gap rule."""
        d2020 = datetime.date(2020, 1, 1)
        d2021 = datetime.date(2021, 1, 1)
        d2022 = datetime.date(2022, 1, 1)
        d2025 = datetime.date(2025, 1, 1)

        # Overlapping / adjacent activity within 730 days
        ok, msg = check_temporal_overlap(d2020, d2021, d2021, d2022)
        self.assertTrue(ok)

        # Gap of 3 years (> 730 days)
        ok, msg = check_temporal_overlap(d2020, d2021, d2025, d2025)
        self.assertFalse(ok)
        self.assertIn("exceeds limit", msg)

        # Missing date on one side -> should allow merge
        ok, msg = check_temporal_overlap(d2020, d2021, None, None)
        self.assertTrue(ok)
        self.assertIn("missing dates", msg)

    def test_disjoint_set_union(self):
        """Test Union-Find clustering logic."""
        elements = ["APT28", "Fancy Bear", "Sofacy", "Lazarus", "Hidden Cobra"]
        dsu = DisjointSetUnion(elements)

        dsu.union("APT28", "Fancy Bear")
        dsu.union("Fancy Bear", "Sofacy")
        dsu.union("Lazarus", "Hidden Cobra")

        clusters = dsu.get_clusters()
        # Should form 2 clusters
        self.assertEqual(len(clusters), 2)

        # Check grouping
        apt28_cluster = next(c for c in clusters.values() if "APT28" in c)
        self.assertEqual(set(apt28_cluster), {"APT28", "Fancy Bear", "Sofacy"})

        lazarus_cluster = next(c for c in clusters.values() if "Lazarus" in c)
        self.assertEqual(set(lazarus_cluster), {"Lazarus", "Hidden Cobra"})

    def test_canonical_id_selection_highest_degree(self):
        """Test that representative with highest degree is selected as canonical."""
        # Simulated entity map
        entity_map = {
            "Fancy Bear": {"degree": 12},
            "APT28": {"degree": 45},
            "Sofacy": {"degree": 5},
        }
        cluster = ["Fancy Bear", "APT28", "Sofacy"]
        best_name = sorted(
            cluster,
            key=lambda n: (-entity_map[n].get("degree", 0), n),
        )[0]
        self.assertEqual(best_name, "APT28")

    def test_canonical_id_selection_alphabetical_tiebreak(self):
        """Test alphabetical tiebreak when degrees are equal."""
        entity_map = {
            "Bravo": {"degree": 10},
            "Alpha": {"degree": 10},
        }
        cluster = ["Bravo", "Alpha"]
        best_name = sorted(
            cluster,
            key=lambda n: (-entity_map[n].get("degree", 0), n),
        )[0]
        self.assertEqual(best_name, "Alpha")

    def test_embedding_client_encoding(self):
        """Test embedding client returns normalized vectors of correct shape."""
        client = EmbeddingClient()
        texts = ["APT28 threat actor", "Fancy Bear cyber espionage group"]
        embs = client.encode(texts, normalize_embeddings=True)
        self.assertEqual(embs.shape[0], 2)
        self.assertEqual(embs.shape[1], 768)

        # Check L2 norm is ~1.0
        norm0 = np.linalg.norm(embs[0])
        self.assertAlmostEqual(norm0, 1.0, places=4)

        # Single string encoding
        single_emb = client.encode("Cobalt Strike malware")
        self.assertEqual(single_emb.shape, (768,))

    def test_pipeline_exact_and_alias_matching(self):
        """Test pipeline logic for merging aliases and assigning canonical IDs."""
        mock_neo4j = MagicMock()
        mock_neo4j.execute_query.return_value = [
            {"name": "APT28", "type": "ThreatActor", "first_seen": "2020-01-01", "last_seen": "2022-01-01", "degree": 50},
            {"name": "fancy bear", "type": "ThreatActor", "first_seen": "2021-01-01", "last_seen": "2023-01-01", "degree": 20},
            {"name": "APT 28", "type": "ThreatActor", "first_seen": "2020-05-01", "last_seen": "2021-05-01", "degree": 10},
        ]

        pipeline = EntityAlignmentPipeline(client=mock_neo4j)
        result = pipeline.align_entity_type("ThreatActor")

        self.assertEqual(result["total_entities"], 3)
        self.assertEqual(result["canonical_count"], 1)
        self.assertEqual(result["merged_count"], 2)


if __name__ == "__main__":
    unittest.main()
