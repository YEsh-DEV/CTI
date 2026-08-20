"""
FAISS Vector Retrieval Index for TemporalRAG (Task 5).

Builds and queries a persistent FAISS cosine-similarity index over
all non-IOC/EvidenceSource/Time/Unknown entities in Neo4j.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import faiss
import numpy as np

# Ensure module path resolution
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common.embedding_client import EmbeddingClient
from common.neo4j_client import Neo4jClient
from config.settings import (
    FAISS_INDEX_PATH,
    FAISS_METADATA_PATH,
    TOP_K_RETRIEVAL,
)

logger = logging.getLogger("temporal_rag.faiss_index")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


class FAISSIndexManager:
    """Manages persistent FAISS vector index and node metadata for query retrieval."""

    def __init__(
        self,
        index_path: Path = FAISS_INDEX_PATH,
        metadata_path: Path = FAISS_METADATA_PATH,
        embedding_client: Optional[EmbeddingClient] = None,
    ):
        self.index_path = Path(index_path)
        self.metadata_path = Path(metadata_path)
        self.embedding_client = embedding_client or EmbeddingClient()
        self.index: Optional[faiss.IndexFlatIP] = None
        self.metadata: List[Dict[str, Any]] = []

    def build_index(self, client: Optional[Neo4jClient] = None) -> int:
        """
        Extract alignable entities from Neo4j, compute embeddings, build FAISS IndexFlatIP,
        and save index and metadata to disk.
        """
        neo4j = client or Neo4jClient()

        query = """
        MATCH (e:Entity)
        WHERE NOT e.type IN ['IOC', 'EvidenceSource', 'Time', 'Unknown']
        RETURN elementId(e) AS node_id,
               e.name AS name,
               e.type AS type,
               coalesce(e.canonical_id, e.name) AS canonical_id,
               e.first_seen AS first_seen,
               e.last_seen AS last_seen
        ORDER BY e.type ASC, e.name ASC
        """
        logger.info("Fetching non-IOC/Time/EvidenceSource entity nodes from Neo4j...")
        nodes = neo4j.execute_query(query)
        if not nodes:
            logger.warning("No alignable entities found in Neo4j to index.")
            return 0

        logger.info(f"Retrieved {len(nodes)} entity nodes. Generating embeddings...")

        # Format texts for embedding using type prefix
        texts = [f"{n['type']}: {n['canonical_id']}" for n in nodes]
        embeddings = self.embedding_client.encode(texts, normalize_embeddings=True, show_progress_bar=False)

        dim = embeddings.shape[1]
        self.index = faiss.IndexFlatIP(dim)
        self.index.add(embeddings)

        self.metadata = []
        for i, n in enumerate(nodes):
            self.metadata.append({
                "index": i,
                "node_id": n.get("node_id"),
                "name": n.get("name"),
                "canonical_id": n.get("canonical_id"),
                "type": n.get("type"),
                "first_seen": str(n.get("first_seen")) if n.get("first_seen") else None,
                "last_seen": str(n.get("last_seen")) if n.get("last_seen") else None,
            })

        # Save index and metadata
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        faiss.write_index(self.index, str(self.index_path))

        with open(self.metadata_path, "w", encoding="utf-8") as f:
            for item in self.metadata:
                f.write(json.dumps(item, default=str) + "\n")

        logger.info(
            f"FAISS index successfully built and saved: {len(self.metadata)} entities "
            f"indexed to {self.index_path}"
        )
        return len(self.metadata)

    def load_index(self) -> bool:
        """Load persistent FAISS index and metadata from disk."""
        if not self.index_path.exists() or not self.metadata_path.exists():
            logger.warning(
                f"FAISS index or metadata missing at {self.index_path} / {self.metadata_path}"
            )
            return False

        logger.info(f"Loading FAISS index from {self.index_path}...")
        self.index = faiss.read_index(str(self.index_path))

        self.metadata = []
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    self.metadata.append(json.loads(line.strip()))

        logger.info(f"Loaded FAISS index with {len(self.metadata)} entries (ntotal={self.index.ntotal}).")
        return True

    def search(self, query_text: str, k: int = TOP_K_RETRIEVAL) -> List[Dict[str, Any]]:
        """
        Embed query text, search FAISS index for top-k cosine similarity matches,
        and return matched entity metadata.
        """
        if self.index is None or not self.metadata:
            loaded = self.load_index()
            if not loaded:
                raise RuntimeError("FAISS index is not built or loaded. Run --build-index first.")

        if not query_text.strip():
            return []

        query_vector = self.embedding_client.encode(query_text.strip(), normalize_embeddings=True)
        query_matrix = np.expand_dims(query_vector, axis=0).astype(np.float32)

        actual_k = min(k, self.index.ntotal)
        if actual_k <= 0:
            return []

        distances, indices = self.index.search(query_matrix, actual_k)

        results = []
        seen_canonical = set()

        for dist, idx in zip(distances[0], indices[0]):
            if idx < 0 or idx >= len(self.metadata):
                continue
            meta = dict(self.metadata[idx])
            meta["similarity"] = round(float(dist), 4)

            # Deduplicate by (type, canonical_id) so we get diverse distinct entities
            canon_key = (meta["type"], meta["canonical_id"])
            if canon_key not in seen_canonical:
                seen_canonical.add(canon_key)
                results.append(meta)

        return results


# Module-level convenience functions
_default_manager: Optional[FAISSIndexManager] = None


def get_faiss_manager() -> FAISSIndexManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = FAISSIndexManager()
    return _default_manager


def build_index(client: Optional[Neo4jClient] = None) -> int:
    return get_faiss_manager().build_index(client=client)


def load_index() -> bool:
    return get_faiss_manager().load_index()


def search(query_text: str, k: int = TOP_K_RETRIEVAL) -> List[Dict[str, Any]]:
    return get_faiss_manager().search(query_text, k=k)
