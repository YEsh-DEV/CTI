"""
Task 4: Entity Alignment & Canonicalization for TemporalRAG.

Identifies different surface forms referring to the same real-world entity
(e.g., "APT28" / "Fancy Bear", "Cobalt Strike" / "CS Beacon") and assigns
a canonical_id property to all :Entity nodes in Neo4j.
"""

import argparse
import datetime
import json
import logging
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import faiss
import numpy as np

# Ensure module path resolution
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common.embedding_client import EmbeddingClient
from common.neo4j_client import Neo4jClient
from config.settings import (
    ALIGNMENT_DATA_DIR,
    ALIGNMENT_SIMILARITY_THRESHOLD,
    ENTITY_ALIASES,
)

logger = logging.getLogger("temporal_rag.alignment")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# Entity types to align
ALIGNABLE_TYPES = [
    "ThreatActor",
    "Malware",
    "Tool",
    "AttackTechnique",
    "ATT&CKTactic",
    "Target",
    "Location",
    "Campaign",
]

# Entity types that skip embedding alignment (canonical_id = name)
SKIPPED_TYPES = [
    "IOC",
    "EvidenceSource",
    "Time",
    "Vulnerability",
    "Product",
    "Unknown",
]

DECISIONS_LOG_PATH = ALIGNMENT_DATA_DIR / "alignment_decisions.jsonl"


def normalize_entity_name(name: str) -> str:
    """
    Normalize entity name for surface string matching:
    - Lowercase
    - Strip punctuation and symbols (including underscores, dashes, etc.)
    - Collapse multiple whitespaces
    """
    if not name:
        return ""
    text = name.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _parse_date(val: Any) -> Optional[datetime.date]:
    """Helper to convert Neo4j Date, DateTime, or string to datetime.date."""
    if val is None:
        return None
    if isinstance(val, datetime.date) and not isinstance(val, datetime.datetime):
        return val
    if isinstance(val, datetime.datetime):
        return val.date()
    if hasattr(val, "to_native"):
        native = val.to_native()
        if isinstance(native, datetime.datetime):
            return native.date()
        if isinstance(native, datetime.date):
            return native
    if hasattr(val, "year") and hasattr(val, "month") and hasattr(val, "day"):
        try:
            return datetime.date(val.year, val.month, val.day)
        except Exception:
            return None
    if isinstance(val, str):
        try:
            return datetime.date.fromisoformat(val[:10])
        except Exception:
            return None
    return None


def check_temporal_overlap(
    first_seen_a: Any,
    last_seen_a: Any,
    first_seen_b: Any,
    last_seen_b: Any,
    max_gap_days: int = 730,
) -> Tuple[bool, str]:
    """
    Check whether two entities have compatible temporal activity.
    If both entities have timestamps, maximum gap between periods must be <= max_gap_days (2 years).
    If either entity lacks timestamps, allow merge.
    """
    fa = _parse_date(first_seen_a)
    la = _parse_date(last_seen_a) or fa
    fb = _parse_date(first_seen_b)
    lb = _parse_date(last_seen_b) or fb

    if fa is None or fb is None or la is None or lb is None:
        return True, "No timeline constraint (missing dates)"

    # Overlap or gap check:
    # Gap exists if la < fb or lb < fa
    if la < fb:
        gap = (fb - la).days
        if gap > max_gap_days:
            return False, f"Temporal gap of {gap} days exceeds limit ({max_gap_days} days)"
    elif lb < fa:
        gap = (fa - lb).days
        if gap > max_gap_days:
            return False, f"Temporal gap of {gap} days exceeds limit ({max_gap_days} days)"

    return True, "Temporal overlap/gap within 730 days"


class DisjointSetUnion:
    """Disjoint Set Union (Union-Find) with path compression and rank."""

    def __init__(self, elements: List[str]):
        self.parent = {elem: elem for elem in elements}
        self.rank = {elem: 0 for elem in elements}

    def find(self, x: str) -> str:
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x: str, y: str):
        root_x = self.find(x)
        root_y = self.find(y)
        if root_x != root_y:
            if self.rank[root_x] < self.rank[root_y]:
                self.parent[root_x] = root_y
            elif self.rank[root_x] > self.rank[root_y]:
                self.parent[root_y] = root_x
            else:
                self.parent[root_y] = root_x
                self.rank[root_x] += 1

    def get_clusters(self) -> Dict[str, List[str]]:
        clusters = defaultdict(list)
        for elem in self.parent:
            root = self.find(elem)
            clusters[root].append(elem)
        return clusters


class EntityAlignmentPipeline:
    """Orchestrates entity canonicalization and alignment in Neo4j."""

    def __init__(
        self,
        client: Optional[Neo4jClient] = None,
        embedding_client: Optional[EmbeddingClient] = None,
        threshold: float = ALIGNMENT_SIMILARITY_THRESHOLD,
    ):
        self.client = client or Neo4jClient()
        self.embedding_client = embedding_client or EmbeddingClient()
        self.threshold = threshold

    def log_decision(self, decision_data: Dict[str, Any]):
        """Append decision record to JSONL audit log."""
        try:
            with open(DECISIONS_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(decision_data, default=str) + "\n")
        except Exception as e:
            logger.warning(f"Failed to log alignment decision: {e}")

    def fetch_entities_by_type(self, entity_type: str) -> List[Dict[str, Any]]:
        """Fetch all entities of given type from Neo4j along with degree and timestamps."""
        query = """
        MATCH (e:Entity {type: $entity_type})
        RETURN e.name AS name,
               e.type AS type,
               e.first_seen AS first_seen,
               e.last_seen AS last_seen,
               count { (e)--() } AS degree
        ORDER BY degree DESC, e.name ASC
        """
        return self.client.execute_query(query, {"entity_type": entity_type})

    def align_entity_type(self, entity_type: str) -> Dict[str, Any]:
        """Align all entities of a specific entity type."""
        logger.info(f"--- Aligning Entity Type: {entity_type} ---")
        entities = self.fetch_entities_by_type(entity_type)
        if not entities:
            logger.info(f"No entities found for type {entity_type}.")
            return {"entity_type": entity_type, "total_entities": 0, "clusters": 0, "merged_count": 0}

        names = [e["name"] for e in entities]
        entity_map = {e["name"]: e for e in entities}
        dsu = DisjointSetUnion(names)

        # 1. Exact string normalization and manual alias matching
        normalized_groups = defaultdict(list)
        for name in names:
            norm = normalize_entity_name(name)
            # Check manual aliases
            alias_target = ENTITY_ALIASES.get(norm, None)
            if alias_target:
                norm = normalize_entity_name(alias_target)
            normalized_groups[norm].append(name)

        exact_merge_count = 0
        for norm, group in normalized_groups.items():
            if len(group) > 1:
                first = group[0]
                for other in group[1:]:
                    dsu.union(first, other)
                    exact_merge_count += 1
                    self.log_decision({
                        "entity_a": first,
                        "entity_b": other,
                        "type": entity_type,
                        "method": "exact_or_alias_match",
                        "similarity": 1.0,
                        "decision": "merged",
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    })

        logger.info(f"Exact/Alias matching merged {exact_merge_count} entity pairs.")

        # 2. Embedding similarity with FAISS
        # To avoid redundancy, pick one representative per current cluster
        current_clusters = dsu.get_clusters()
        representatives = [group[0] for group in current_clusters.values()]

        # For geographic types (Location, Target), use stricter threshold (0.95) to prevent merging different countries
        effective_threshold = 0.95 if entity_type in ("Location", "Target") else self.threshold

        if len(representatives) > 1:
            # Prefix with entity type for contextual discrimination
            texts_to_embed = [f"{entity_type}: {name}" for name in representatives]
            embeddings = self.embedding_client.encode(texts_to_embed, normalize_embeddings=True)

            dim = embeddings.shape[1]
            index = faiss.IndexFlatIP(dim)
            index.add(embeddings)

            k = min(50, len(representatives))
            distances, indices = index.search(embeddings, k)

            embedding_merge_count = 0
            for i in range(len(representatives)):
                name_a = representatives[i]
                for rank in range(1, k):
                    j = indices[i][rank]
                    if j <= i or j >= len(representatives):
                        continue
                    sim = float(distances[i][rank])
                    if sim < effective_threshold:
                        break

                    name_b = representatives[j]
                    ent_a = entity_map[name_a]
                    ent_b = entity_map[name_b]

                    # Check temporal overlap
                    is_temporal_ok, reason = check_temporal_overlap(
                        ent_a.get("first_seen"),
                        ent_a.get("last_seen"),
                        ent_b.get("first_seen"),
                        ent_b.get("last_seen"),
                    )

                    decision_record = {
                        "entity_a": name_a,
                        "entity_b": name_b,
                        "type": entity_type,
                        "method": "faiss_embedding",
                        "similarity": round(sim, 4),
                        "temporal_check": is_temporal_ok,
                        "temporal_reason": reason,
                        "decision": "merged" if is_temporal_ok else "rejected",
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    }
                    self.log_decision(decision_record)

                    if is_temporal_ok:
                        dsu.union(name_a, name_b)
                        embedding_merge_count += 1
                        logger.info(f"  [MERGED] '{name_a}' <-> '{name_b}' (sim={sim:.4f})")
                    else:
                        logger.info(f"  [REJECTED] '{name_a}' <-> '{name_b}' (sim={sim:.4f}) - {reason}")

            logger.info(f"Embedding similarity merged {embedding_merge_count} candidate clusters.")

        # 3. Canonical ID Assignment
        final_clusters = dsu.get_clusters()
        updates = []
        for root, cluster_names in final_clusters.items():
            # Pick canonical representative: highest degree, tiebreak alphabetically first
            best_name = sorted(
                cluster_names,
                key=lambda n: (-entity_map[n].get("degree", 0), n),
            )[0]

            for name in cluster_names:
                updates.append({
                    "name": name,
                    "type": entity_type,
                    "canonical_id": best_name,
                })

        # 4. Write back canonical_id to Neo4j in batches
        self._write_canonical_ids(updates)

        total_entities = len(entities)
        num_canonical = len(final_clusters)
        merged_entities = total_entities - num_canonical

        logger.info(
            f"Type {entity_type} Complete: {total_entities} entities -> "
            f"{num_canonical} canonical IDs ({merged_entities} merged)."
        )

        return {
            "entity_type": entity_type,
            "total_entities": total_entities,
            "canonical_count": num_canonical,
            "merged_count": merged_entities,
        }

    def _write_canonical_ids(self, updates: List[Dict[str, str]], batch_size: int = 1000):
        """Batch write canonical_id properties to Neo4j."""
        if not updates:
            return

        query = """
        UNWIND $batch AS item
        MATCH (e:Entity {name: item.name, type: item.type})
        SET e.canonical_id = item.canonical_id
        """
        for i in range(0, len(updates), batch_size):
            batch = updates[i : i + batch_size]
            self.client.execute_query(query, {"batch": batch})

    def align_skipped_types(self):
        """Set canonical_id = name for skipped entity types and any unassigned entities."""
        logger.info("Setting canonical_id = name for skipped / unaligned entity types...")
        query = """
        MATCH (e:Entity)
        WHERE e.canonical_id IS NULL
        SET e.canonical_id = e.name
        """
        self.client.execute_query(query)
        logger.info("Default canonical_ids set.")

    def ensure_index(self):
        """Ensure entity_canonical_idx exists on :Entity(canonical_id)."""
        logger.info("Creating index on :Entity(canonical_id)...")
        self.client.execute_query(
            "CREATE INDEX entity_canonical_idx IF NOT EXISTS FOR (e:Entity) ON (e.canonical_id)"
        )
        logger.info("Index entity_canonical_idx ready.")

    def run_all(self, types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Run alignment across all specified or eligible entity types."""
        target_types = types or ALIGNABLE_TYPES
        results = []
        for etype in target_types:
            res = self.align_entity_type(etype)
            results.append(res)

        self.align_skipped_types()
        self.ensure_index()
        return results

    def verify_alignment(self) -> Dict[str, Any]:
        """Print and return summary verification of canonical IDs across the graph."""
        total_nodes_query = "MATCH (e:Entity) RETURN count(e) AS cnt"
        total_nodes = self.client.execute_query(total_nodes_query)[0]["cnt"]

        canonical_nodes_query = "MATCH (e:Entity) RETURN count(DISTINCT e.canonical_id) AS cnt"
        canonical_nodes = self.client.execute_query(canonical_nodes_query)[0]["cnt"]

        by_type_query = """
        MATCH (e:Entity)
        RETURN e.type AS type,
               count(e) AS total,
               count(DISTINCT e.canonical_id) AS canonical,
               count(e) - count(DISTINCT e.canonical_id) AS merged
        ORDER BY total DESC
        """
        by_type = self.client.execute_query(by_type_query)

        top_clusters_query = """
        MATCH (e:Entity)
        WITH e.type AS type, e.canonical_id AS canonical_id, collect(e.name) AS aliases, count(e) AS cluster_size
        WHERE cluster_size > 1
        RETURN type, canonical_id, cluster_size, aliases
        ORDER BY cluster_size DESC, canonical_id ASC
        LIMIT 20
        """
        top_clusters = self.client.execute_query(top_clusters_query)

        print("\n" + "=" * 70)
        print("=== TASK 4: ENTITY ALIGNMENT VERIFICATION REPORT ===")
        print("=" * 70)
        print(f"Total Entity Nodes:     {total_nodes:,}")
        print(f"Unique Canonical IDs:   {canonical_nodes:,}")
        compression = ((total_nodes - canonical_nodes) / total_nodes * 100.0) if total_nodes else 0.0
        print(f"Entities Merged:        {(total_nodes - canonical_nodes):,} ({compression:.2f}% compression)")
        print("\n--- Breakdown by Entity Type ---")
        print(f"{'Type':<20} | {'Total':<10} | {'Canonical':<10} | {'Merged':<10}")
        print("-" * 60)
        for row in by_type:
            print(f"{row['type']:<20} | {row['total']:<10} | {row['canonical']:<10} | {row['merged']:<10}")

        print("\n--- Top Merged Clusters (Sample) ---")
        if top_clusters:
            for c in top_clusters:
                print(f"[{c['type']}] Canonical: '{c['canonical_id']}' (Size: {c['cluster_size']})")
                print(f"  Aliases: {c['aliases']}")
        else:
            print("No multi-entity clusters found.")
        print("=" * 70 + "\n")

        return {
            "total_nodes": total_nodes,
            "canonical_nodes": canonical_nodes,
            "by_type": by_type,
            "top_clusters": top_clusters,
        }

    def show_decisions(self, limit: int = 20):
        """Print recent decisions from the audit log."""
        if not DECISIONS_LOG_PATH.exists():
            print(f"No decisions log found at {DECISIONS_LOG_PATH}")
            return

        lines = []
        with open(DECISIONS_LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    lines.append(json.loads(line.strip()))

        print("\n" + "=" * 70)
        print(f"=== RECENT ALIGNMENT DECISIONS (Last {min(limit, len(lines))}) ===")
        print("=" * 70)
        for item in lines[-limit:]:
            status = item.get("decision", "unknown").upper()
            sim = item.get("similarity", 1.0)
            method = item.get("method", "unknown")
            ea = item.get("entity_a")
            eb = item.get("entity_b")
            etype = item.get("type")
            reason = item.get("temporal_reason", "")
            print(f"[{status}] ({etype}) '{ea}' <-> '{eb}' | Method: {method} | Sim: {sim}")
            if reason:
                print(f"       Note: {reason}")
        print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Task 4: Entity Alignment & Canonicalization")
    parser.add_argument("--align", action="store_true", help="Run entity alignment")
    parser.add_argument("--type", type=str, default=None, help="Align specific entity type")
    parser.add_argument("--verify", action="store_true", help="Verify canonical IDs in Neo4j")
    parser.add_argument("--show-decisions", action="store_true", help="Show recent alignment decisions")
    parser.add_argument("--threshold", type=float, default=ALIGNMENT_SIMILARITY_THRESHOLD, help="Similarity threshold")

    args = parser.parse_args()

    pipeline = EntityAlignmentPipeline(threshold=args.threshold)

    if args.align:
        types = [args.type] if args.type else None
        pipeline.run_all(types=types)
        pipeline.verify_alignment()
    elif args.verify:
        pipeline.verify_alignment()
    elif args.show_decisions:
        pipeline.show_decisions()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
