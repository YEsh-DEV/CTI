"""
Task 5: Temporal-Causal GraphRAG Reasoning Pipeline.

Implements multi-hop graph traversal, temporal-causal chain extraction,
trust-weighted path prioritization, context assembly, and LLM reasoning
using Ollama deepseek-r1:1.5b.
"""

import argparse
import datetime
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure module path resolution
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from common.embedding_client import EmbeddingClient
from common.faiss_index import FAISSIndexManager, get_faiss_manager
from common.llm_client import OllamaClient, strip_think_tags
from common.neo4j_client import Neo4jClient
from config.settings import (
    GRAPH_TRAVERSAL_DEPTH,
    MAX_CONTEXT_TOKENS,
    TOP_K_RETRIEVAL,
)

logger = logging.getLogger("temporal_rag.graph_rag")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# Relationship priority ranks (lower number = higher priority)
REL_PRIORITY = {
    "PRECEDES": 1,
    "ENABLES": 1,
    "EVOLVES_TO": 1,
    "EXPLOITS": 2,
    "USES_VULNERABILITY": 2,
    "HAS_VULNERABILITY": 2,
    "BELONGS_TO_TACTIC": 2,
    "BELONGS_TO_TECHNIQUE": 2,
    "USES": 3,
    "TARGETS": 3,
    "TARGETED": 3,
    "TARGETED_IN": 3,
    "OBSERVED_IN": 3,
    "OBSERVES_IN": 3,
    "SAME_AS": 4,
    "INDICATES": 4,
    "RELATES_TO": 4,
    "DROPS_FILE": 5,
    "USES_DOMAIN": 5,
    "COMMUNICATES_WITH": 6,
    "HAS_HASH": 6,
    "HAS_IOC": 6,
}


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


def approx_token_count(text: str) -> int:
    """Approximate token count using word-count * 1.3 heuristic."""
    if not text:
        return 0
    words = len(text.split())
    return int(words * 1.3)


class GraphRAGPipeline:
    """
    Temporal-Causal GraphRAG Pipeline implementing:
    1. Semantic Seed Entity Retrieval (FAISS)
    2. Multi-Hop Graph Traversal (Neo4j)
    3. Temporal-Causal Path Extraction
    4. Trust-Weighted Context Construction
    5. LLM Synthesis & Reasoning (Ollama)
    """

    def __init__(
        self,
        neo4j_client: Optional[Neo4jClient] = None,
        faiss_manager: Optional[FAISSIndexManager] = None,
        llm_client: Optional[OllamaClient] = None,
    ):
        self.neo4j = neo4j_client or Neo4jClient()
        self.faiss = faiss_manager or get_faiss_manager()
        self.llm = llm_client or OllamaClient()

    # =========================================================================
    # STAGE 1 — Semantic Entity Retrieval
    # =========================================================================
    def retrieve_seed_entities(
        self, query_text: str, top_k: int = TOP_K_RETRIEVAL
    ) -> List[Dict[str, Any]]:
        """Retrieve top matching seed entities from FAISS index."""
        logger.info(f"Stage 1: Searching FAISS for seed entities (top_k={top_k})...")
        results = self.faiss.search(query_text, k=top_k)
        logger.info(f"Retrieved {len(results)} seed entities.")
        return results

    # =========================================================================
    # STAGE 2 — Graph Traversal
    # =========================================================================
    def traverse_graph_paths(
        self,
        entities: List[Dict[str, Any]],
        depth: int = GRAPH_TRAVERSAL_DEPTH,
        limit_per_entity: int = 25,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Traverse graph up to `depth` hops from retrieved entities.
        Returns:
            (structured_paths, unique_facts)
        """
        if not entities:
            return [], []

        canonical_ids = list({e["canonical_id"] for e in entities if e.get("canonical_id")})
        logger.info(
            f"Stage 2: Traversing Neo4j graph up to {depth} hops for {len(canonical_ids)} canonical entities..."
        )

        query = f"""
        MATCH path = (start:Entity)-[*1..{depth}]-(neighbor:Entity)
        WHERE start.canonical_id IN $cids AND ALL(r IN relationships(path) WHERE r.trust IS NOT NULL)
        WITH path, relationships(path) AS rels, nodes(path) AS nds,
             reduce(score=1.0, r IN relationships(path) | score * r.trust) AS path_trust
        WHERE path_trust > 0.0
        ORDER BY path_trust DESC
        LIMIT 100
        RETURN [n IN nds | {{
                  name: n.name,
                  canonical_id: coalesce(n.canonical_id, n.name),
                  type: n.type
               }}] AS nodes,
               [r IN rels | {{
                  type: type(r),
                  source: r.source,
                  tau: r.tau,
                  tau_raw: r.tau_raw,
                  evidence: r.evidence,
                  confidence: r.confidence,
                  trust: r.trust,
                  trusted: r.trusted
               }}] AS rels,
               path_trust
        """
        records = self.neo4j.execute_query(query, {"cids": canonical_ids})

        structured_paths: List[Dict[str, Any]] = []
        unique_facts_map: Dict[str, Dict[str, Any]] = {}

        for rec in records:
            nodes = rec.get("nodes", [])
            rels = rec.get("rels", [])
            path_trust = float(rec.get("path_trust", 0.0))

            if not nodes or not rels or len(nodes) < len(rels) + 1:
                continue

            path_hops = []
            for i, r in enumerate(rels):
                start_n = nodes[i]
                end_n = nodes[i + 1]

                h_name = start_n.get("name", "Unknown")
                h_canon = start_n.get("canonical_id", h_name)
                h_type = start_n.get("type", "Unknown")

                t_name = end_n.get("name", "Unknown")
                t_canon = end_n.get("canonical_id", t_name)
                t_type = end_n.get("type", "Unknown")

                rel_type = r.get("type", "RELATED_TO")
                tau_val = r.get("tau")
                tau_raw = r.get("tau_raw")
                tau_date = _parse_date(tau_val) or _parse_date(tau_raw)

                hop_info = {
                    "rel_id": f"{h_canon}_{rel_type}_{t_canon}_{r.get('source', '')}",
                    "head_name": h_name,
                    "head_canonical": h_canon,
                    "head_type": h_type,
                    "rel_type": rel_type,
                    "tail_name": t_name,
                    "tail_canonical": t_canon,
                    "tail_type": t_type,
                    "tau": tau_val,
                    "tau_raw": tau_raw,
                    "tau_date": tau_date,
                    "evidence": r.get("evidence", ""),
                    "confidence": float(r.get("confidence", 1.0) if r.get("confidence") is not None else 1.0),
                    "trust": float(r.get("trust", 0.5) if r.get("trust") is not None else 0.5),
                    "trusted": bool(r.get("trusted", False)),
                    "source": r.get("source", "unknown"),
                }
                path_hops.append(hop_info)

                fact_key = f"{h_canon}::{rel_type}::{t_canon}::{hop_info['source']}"
                if fact_key not in unique_facts_map:
                    unique_facts_map[fact_key] = hop_info

            if path_hops:
                structured_paths.append({
                    "hops": path_hops,
                    "path_trust": round(path_trust, 4),
                    "length": len(path_hops),
                })

        # Prioritize facts:
        # 1. Relation Priority (causal/semantic > IOC)
        # 2. Trust score (desc)
        # 3. Recency (more recent tau first)
        def _fact_sort_key(f: Dict[str, Any]):
            prio = REL_PRIORITY.get(f["rel_type"], 10)
            trust = f.get("trust", 0.0)
            d = f.get("tau_date")
            d_val = d.toordinal() if d else 0
            return (prio, -trust, -d_val)

        unique_facts = sorted(unique_facts_map.values(), key=_fact_sort_key)

        logger.info(
            f"Stage 2 Complete: Found {len(structured_paths)} paths and {len(unique_facts)} unique facts."
        )
        return structured_paths, unique_facts

    # =========================================================================
    # STAGE 3 — Temporal Path Extraction
    # =========================================================================
    def extract_temporal_paths(
        self, paths: List[Dict[str, Any]], max_chains: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Identify temporal-causal chains where relationship timestamps form a progression
        (T1 <= T2 <= ... <= Tn). Fallback to top-trust structural paths if no temporal chains exist.
        """
        temporal_chains = []

        for p in paths:
            hops = p.get("hops", [])
            if len(hops) < 2:
                continue

            # Extract valid dates
            dates = [h.get("tau_date") for h in hops]
            valid_dates = [d for d in dates if d is not None]

            # If at least 2 hops have dates and are in chronological order:
            if len(valid_dates) >= 2:
                is_chronological = True
                last_d = None
                for d in dates:
                    if d is not None:
                        if last_d is not None and d < last_d:
                            is_chronological = False
                            break
                        last_d = d

                if is_chronological:
                    temporal_chains.append({
                        "type": "temporal_causal",
                        "hops": hops,
                        "path_trust": p["path_trust"],
                        "length": len(hops),
                    })
                    if len(temporal_chains) >= max_chains:
                        break

        # If not enough temporal chains, pad with top structural paths
        if len(temporal_chains) < max_chains:
            for p in sorted(paths, key=lambda x: -x["path_trust"]):
                if p not in temporal_chains:
                    temporal_chains.append({
                        "type": "structural",
                        "hops": p.get("hops", []),
                        "path_trust": p["path_trust"],
                        "length": p.get("length", 1),
                    })
                    if len(temporal_chains) >= max_chains:
                        break

        logger.info(f"Stage 3 Complete: Extracted {len(temporal_chains)} paths for context.")
        return temporal_chains

    # =========================================================================
    # STAGE 4 — Context Construction
    # =========================================================================
    def build_context(
        self,
        query: str,
        temporal_paths: List[Dict[str, Any]],
        facts: List[Dict[str, Any]],
        max_tokens: int = MAX_CONTEXT_TOKENS,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Construct structured context string truncated to max_tokens.
        Prioritizes:
        1. Temporal / causal paths
        2. Trusted facts (trusted=True)
        3. Untrusted / lower-trust facts
        """
        sections = ["=== RETRIEVED GRAPH CONTEXT ==="]
        used_sources = set()
        trusted_facts_used = 0
        untrusted_facts_used = 0

        # 1. Temporal / Structural Paths
        if temporal_paths:
            sections.append("\n[Temporal & Causal Paths]")
            for idx, path in enumerate(temporal_paths, start=1):
                ptype = path.get("type", "path").replace("_", " ").title()
                p_trust = path.get("path_trust", 0.0)
                sections.append(f"Path {idx} ({ptype}, Trust={p_trust:.2f}):")
                for h in path.get("hops", []):
                    d_str = str(h.get("tau_raw") or h.get("tau") or "Date Unknown")
                    ev = h.get("evidence") or "No direct text evidence."
                    src = h.get("source")
                    if src:
                        used_sources.add(src)
                    sections.append(
                        f"  ({h['head_type']}: {h['head_canonical']}) --[{h['rel_type']}]--> "
                        f"({h['tail_type']}: {h['tail_canonical']}) | Date: {d_str} | Evidence: \"{ev}\""
                    )

        # 2. Supporting Facts (split into trusted vs lower-trust)
        sections.append("\n[Supporting Facts & Relations]")
        trusted_facts = [f for f in facts if f.get("trusted", False)]
        untrusted_facts = [f for f in facts if not f.get("trusted", False)]

        fact_lines = []
        for f in trusted_facts:
            src = f.get("source", "unknown")
            used_sources.add(src)
            trusted_facts_used += 1
            line = (
                f"- ({f['head_type']}: {f['head_canonical']}) {f['rel_type']} "
                f"({f['tail_type']}: {f['tail_canonical']}) "
                f"[Trust={f['trust']:.2f}, Conf={f['confidence']:.2f}, Source={src}, Trusted=YES]"
            )
            fact_lines.append((line, True))

        for f in untrusted_facts:
            src = f.get("source", "unknown")
            used_sources.add(src)
            untrusted_facts_used += 1
            line = (
                f"- ({f['head_type']}: {f['head_canonical']}) {f['rel_type']} "
                f"({f['tail_type']}: {f['tail_canonical']}) "
                f"[Trust={f['trust']:.2f}, Conf={f['confidence']:.2f}, Source={src}, Trusted=NO]"
            )
            fact_lines.append((line, False))

        # Check token budget and append facts
        current_context = "\n".join(sections)
        query_section = f"\n\n[Query]\n{query}\n"

        for line, is_trusted in fact_lines:
            test_context = current_context + "\n" + line + query_section
            if approx_token_count(test_context) > max_tokens:
                logger.info(f"Context budget reached ({max_tokens} tokens). Truncating remaining facts.")
                if not is_trusted:
                    untrusted_facts_used -= 1
                else:
                    trusted_facts_used -= 1
                break
            current_context += "\n" + line

        final_context = current_context + query_section
        stats = {
            "token_count": approx_token_count(final_context),
            "sources": sorted(list(used_sources)),
            "temporal_paths_count": len(temporal_paths),
            "trusted_facts_used": trusted_facts_used,
            "untrusted_facts_used": untrusted_facts_used,
        }
        return final_context, stats

    # =========================================================================
    # STAGE 5 — LLM Reasoning
    # =========================================================================
    def generate_reasoning(
        self, query: str, context: str, temperature: float = 0.0
    ) -> str:
        """Call Ollama deepseek-r1:1.5b with grounded system prompt."""
        system_prompt = (
            "You are an expert cybersecurity threat intelligence analyst. "
            "Answer the user query based ONLY on the provided graph context. "
            "If the context does not contain enough information to answer, say so explicitly. "
            "Do not hallucinate or assume facts that are not present in the graph context. "
            "Cite sources and entity names clearly in your explanation."
        )
        user_prompt = f"Answer the following threat intelligence query using only the evidence provided:\n\n{context}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        logger.info("Stage 5: Sending context to Ollama for reasoning...")
        raw_output = self.llm.generate_chat_completion(messages, temperature=temperature)
        cleaned_answer = strip_think_tags(raw_output)
        return cleaned_answer

    # =========================================================================
    # Full End-to-End Query Execution
    # =========================================================================
    def query(
        self,
        query_text: str,
        top_k: int = TOP_K_RETRIEVAL,
        depth: int = GRAPH_TRAVERSAL_DEPTH,
        verbose: bool = False,
    ) -> Dict[str, Any]:
        """Execute full GraphRAG pipeline for a given query string."""
        logger.info(f"=== Starting GraphRAG for query: '{query_text}' ===")

        # Stage 1
        seeds = self.retrieve_seed_entities(query_text, top_k=top_k)

        # Stage 2
        paths, facts = self.traverse_graph_paths(seeds, depth=depth)

        # Stage 3
        temporal_paths = self.extract_temporal_paths(paths)

        # Stage 4
        context_str, context_stats = self.build_context(query_text, temporal_paths, facts)

        # Stage 5
        answer = self.generate_reasoning(query_text, context_str)

        result = {
            "query": query_text,
            "answer": answer,
            "sources": context_stats["sources"],
            "seed_entities": seeds,
            "temporal_paths_count": context_stats["temporal_paths_count"],
            "trusted_facts_used": context_stats["trusted_facts_used"],
            "untrusted_facts_used": context_stats["untrusted_facts_used"],
            "context_tokens_approx": context_stats["token_count"],
            "context": context_str if verbose else None,
        }

        if verbose:
            print("\n" + "=" * 70)
            print("=== GRAPHRAG VERBOSE EXECUTION DETAILS ===")
            print("=" * 70)
            print(f"Query: {query_text}\n")
            print(f"Top-K Seed Entities ({len(seeds)}):")
            for s in seeds[:5]:
                print(f"  - [{s['type']}] {s['canonical_id']} (Sim: {s['similarity']:.4f})")
            print(f"\nAssembled Context ({context_stats['token_count']} tokens):")
            print("-" * 50)
            print(context_str[:1500] + ("\n... [truncated for display]" if len(context_str) > 1500 else ""))
            print("-" * 50)
            print(f"\nFinal Answer:\n{answer}")
            print("=" * 70 + "\n")

        return result


# =============================================================================
# CLI and Verification
# =============================================================================
VERIFY_QUERIES = [
    "What malware has been used by APT groups targeting government?",
    "Which vulnerabilities were exploited in 2018 campaigns?",
    "What tools are associated with Lazarus Group?",
]


def run_verify(pipeline: GraphRAGPipeline):
    """Run built-in verification queries and display benchmark performance."""
    print("\n" + "=" * 75)
    print("=== TASK 5: TEMPORAL-CAUSAL GRAPHRAG VERIFICATION BENCHMARK ===")
    print("=" * 75)

    for i, q in enumerate(VERIFY_QUERIES, start=1):
        print(f"\n>>> Benchmark Query {i}: \"{q}\"")
        res = pipeline.query(q, verbose=False)

        print(f"  [+] Seed Entities Retrieved : {len(res['seed_entities'])}")
        print(f"  [+] Temporal Paths Extracted: {res['temporal_paths_count']}")
        print(f"  [+] Trusted Facts Used      : {res['trusted_facts_used']}")
        print(f"  [+] Untrusted Facts Used    : {res['untrusted_facts_used']}")
        print(f"  [+] Approx Context Tokens   : {res['context_tokens_approx']}")
        print(f"  [+] Sources Referenced      : {res['sources']}")
        print(f"\n  --- Ollama Synthesis Answer ---")
        print(f"  {res['answer']}\n")
        print("-" * 75)

    print("=" * 75 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Task 5: Temporal-Causal GraphRAG")
    parser.add_argument("--build-index", action="store_true", help="Build and save FAISS retrieval index")
    parser.add_argument("--query", type=str, default=None, help="Query the GraphRAG pipeline")
    parser.add_argument("--verbose", action="store_true", help="Print verbose intermediate graph context")
    parser.add_argument("--verify", action="store_true", help="Run 3 benchmark verification queries")
    parser.add_argument("--top-k", type=int, default=TOP_K_RETRIEVAL, help="Top-K seed entities")
    parser.add_argument("--depth", type=int, default=GRAPH_TRAVERSAL_DEPTH, help="Max traversal depth hops")

    args = parser.parse_args()

    pipeline = GraphRAGPipeline()

    if args.build_index:
        cnt = pipeline.faiss.build_index(client=pipeline.neo4j)
        print(f"Successfully built and saved FAISS index with {cnt} entities.")
    elif args.query:
        res = pipeline.query(args.query, top_k=args.top_k, depth=args.depth, verbose=args.verbose)
        if not args.verbose:
            print("\n=== GRAPHRAG ANSWER ===")
            print(res["answer"])
            print(f"\nMetadata: {res['trusted_facts_used']} trusted facts | {res['temporal_paths_count']} paths | Sources: {res['sources']}\n")
    elif args.verify:
        run_verify(pipeline)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
