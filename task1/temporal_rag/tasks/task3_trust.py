"""Task 3: Trust Scoring & Temporal Verification for Knowledge Graph Triples.

Computes multi-factor trust scores for all temporal relationships in Neo4j:
Trust(h,r,t) = α×LLM_conf + β×source_rel + γ×ATT&CK_sim + δ×cross_src + ε×temp_cons - λ×contradiction

Sub-score definitions:
1. LLM_confidence (α): Rel confidence property (0.0 - 1.0)
2. source_reliability (β): Lookup table based on source type (CVE: 0.90, CTI_REPORT: 0.80, MISP_IOC: 0.65, UNKNOWN: 0.50)
3. ATT&CK_similarity (γ): Match against MITRE ATT&CK taxonomy (1.0 exact/fuzzy>=80, 0.5 partial 60-79, 0.0 none, 0.9 for tactic/tech rels, 0.3 for IOC rels, 0.5 default)
4. cross_source_support (δ): Multi-source corroboration (3+ sources: 1.0, 2 sources: 0.6, 1 source: 0.3)
5. temporal_consistency (ε): Timeline alignment (1.0 consistent, 0.7 <=6mo drift, 0.3 >6mo drift, 0.5 unknown/null)
6. contradiction_penalty (λ): Same triple with day-precision tau > 365 days apart (0.5 if detected, 0.0 otherwise)
"""

import argparse
import datetime
import logging
import math
from typing import Any, Dict, List, Optional, Set, Tuple

from common.neo4j_client import Neo4jClient
from config.settings import (
    SOURCE_RELIABILITY,
    TRUST_ALPHA,
    TRUST_BETA,
    TRUST_DELTA,
    TRUST_EPSILON,
    TRUST_GAMMA,
    TRUST_LAMBDA,
    TRUST_THRESHOLD,
)
from reference_data.attck_loader import ATTCKLoader, get_attck_loader

logger = logging.getLogger("task3_trust")
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

IOC_RELATION_TYPES: Set[str] = {
    "HAS_HASH",
    "COMMUNICATES_WITH",
    "DROPS_FILE",
    "USES_DOMAIN",
    "HAS_IOC",
}

TACTIC_TECH_RELATION_TYPES: Set[str] = {
    "BELONGS_TO_TACTIC",
    "BELONGS_TO_TECHNIQUE",
}

REPORT_ENTITY_TYPES: Set[str] = {
    "ThreatActor",
    "Malware",
    "Tool",
    "Target",
    "Vulnerability",
    "Campaign",
    "AttackTechnique",
    "ATT&CKTactic",
    "Location",
    "Product",
}


def compute_llm_confidence(confidence: Optional[float], default: float = 1.0) -> float:
    """Read LLM confidence sub-score s1 (α)."""
    if confidence is None:
        return default
    try:
        val = float(confidence)
        return max(0.0, min(1.0, val))
    except (ValueError, TypeError):
        return default


import re

def compute_source_reliability(
    source: Optional[str],
    head_type: str = "Unknown",
    tail_type: str = "Unknown",
    rel_type: str = "RELATED_TO",
) -> float:
    """Classify source and lookup source reliability sub-score s2 (β).

    PLACEHOLDER — requires real expert curation, defaults are illustrative.
    """
    src = str(source or "").strip()
    if not src:
        return SOURCE_RELIABILITY.get("UNKNOWN", 0.50)

    if src.startswith("CVE-") or src.startswith("cve-"):
        return SOURCE_RELIABILITY.get("CVE", 0.90)

    # Check if source looks like {year}_{id}
    is_composite_year_id = bool(re.match(r"^\d{4}_\d+$", src))
    if is_composite_year_id:
        rel_upper = rel_type.upper()
        if (
            rel_upper in IOC_RELATION_TYPES
            or head_type == "IOC"
            or tail_type == "IOC"
        ):
            return SOURCE_RELIABILITY.get("MISP_IOC", 0.65)
        elif (
            head_type in REPORT_ENTITY_TYPES
            or tail_type in REPORT_ENTITY_TYPES
        ):
            return SOURCE_RELIABILITY.get("CTI_REPORT", 0.80)
        else:
            return SOURCE_RELIABILITY.get("MISP_IOC", 0.65)
    else:
        return SOURCE_RELIABILITY.get("UNKNOWN", 0.50)



def compute_attck_similarity(
    head_name: str,
    head_type: str,
    tail_name: str,
    tail_type: str,
    rel_type: str,
    attck_loader: Optional[ATTCKLoader] = None,
) -> float:
    """Compute ATT&CK similarity sub-score s3 (γ)."""
    if attck_loader is None:
        attck_loader = get_attck_loader()

    # If entity is directly AttackTechnique or ATT&CKTactic
    if head_type in ("AttackTechnique", "ATT&CKTactic") or tail_type in ("AttackTechnique", "ATT&CKTactic"):
        score_h = attck_loader.match_attck(head_name) if head_type in ("AttackTechnique", "ATT&CKTactic") else 0.0
        score_t = attck_loader.match_attck(tail_name) if tail_type in ("AttackTechnique", "ATT&CKTactic") else 0.0
        return max(score_h, score_t)

    rel_upper = rel_type.upper()
    if rel_upper in TACTIC_TECH_RELATION_TYPES:
        return 0.9
    elif rel_upper in IOC_RELATION_TYPES:
        return 0.3
    else:
        return 0.5


def compute_cross_source_support(source_count: int) -> float:
    """Compute cross-source support sub-score s4 (δ).

    NOTE: Under-counts support because entity names are not yet canonicalized
    (Task 4 will improve this).
    """
    if source_count >= 3:
        return 1.0
    elif source_count == 2:
        return 0.6
    else:
        return 0.3


def _normalize_date(val: Any) -> Optional[datetime.date]:
    """Helper to convert Neo4j DateTime, datetime, date, or ISO string to date."""
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
        return datetime.date(val.year, val.month, val.day)
    if isinstance(val, str):
        try:
            return datetime.date.fromisoformat(val[:10])
        except Exception:
            return None
    return None


def compute_temporal_consistency(
    tau: Any,
    head_type: str,
    head_first_seen: Any,
    head_last_seen: Any,
) -> float:
    """Compute temporal consistency sub-score s5 (ε)."""
    tau_date = _normalize_date(tau)
    if tau_date is None:
        return 0.5

    first_date = _normalize_date(head_first_seen)
    last_date = _normalize_date(head_last_seen)

    if first_date is None or last_date is None:
        return 1.0

    # Single-event IOC
    if head_type == "IOC" and first_date == last_date:
        return 1.0 if tau_date == first_date else 0.5

    # Entity timeline check (within [first_seen, last_seen + 365 days])
    expanded_last = last_date + datetime.timedelta(days=365)
    if first_date <= tau_date <= expanded_last:
        return 1.0

    # Drift calculation
    if tau_date < first_date:
        drift_days = (first_date - tau_date).days
    else:
        drift_days = (tau_date - expanded_last).days

    if drift_days <= 180:  # <= 6 months
        return 0.7
    else:  # > 6 months
        return 0.3


def compute_contradiction_penalty(is_contradiction: bool) -> float:
    """Compute contradiction penalty sub-score s6 (λ).

    Flagged when two relationships exist with SAME (head, rel, tail) but
    DIFFERENT tau values > 365 days apart with tau_precision='day'.
    """
    return 0.5 if is_contradiction else 0.0


def calculate_trust_score(
    s1: float,
    s2: float,
    s3: float,
    s4: float,
    s5: float,
    s6: float,
    alpha: float = TRUST_ALPHA,
    beta: float = TRUST_BETA,
    gamma: float = TRUST_GAMMA,
    delta: float = TRUST_DELTA,
    epsilon: float = TRUST_EPSILON,
    lambda_weight: float = TRUST_LAMBDA,
    threshold: float = TRUST_THRESHOLD,
) -> Tuple[float, bool]:
    """Calculate final trust score and trusted boolean flag.

    Trust(h,r,t) = α×s1 + β×s2 + γ×s3 + δ×s4 + ε×s5 - λ×s6
    Clamped to [0.0, 1.0].
    """
    raw_trust = (
        alpha * s1
        + beta * s2
        + gamma * s3
        + delta * s4
        + epsilon * s5
        - lambda_weight * s6
    )
    trust = max(0.0, min(1.0, raw_trust))
    trusted = trust >= threshold
    return round(trust, 4), trusted


class TrustScoringPipeline:
    """Orchestrates batch trust scoring over the Neo4j Temporal Graph."""

    def __init__(self, client: Optional[Neo4jClient] = None):
        self.client = client or Neo4jClient()
        self.attck_loader = get_attck_loader()

    def process_relationships(
        self,
        sample_limit: Optional[int] = None,
        batch_size: int = 500,
        force_recompute: bool = False,
    ) -> Dict[str, Any]:
        """Fetch relationships in batches, compute trust sub-scores, and write back to Neo4j."""
        total_processed = 0
        total_trusted = 0
        total_untrusted = 0
        contradiction_count = 0
        scores: List[float] = []

        logger.info(
            f"Starting Trust Scoring (Sample Limit: {sample_limit or 'ALL'}, "
            f"Batch Size: {batch_size}, Threshold: {TRUST_THRESHOLD})"
        )

        # If force_recompute is requested, we can clear trust properties first
        if force_recompute:
            logger.info("Resetting existing trust properties...")
            self.client.execute_query(
                "MATCH ()-[r]->() SET r.trust = null, r.trusted = null"
            )

        while True:
            remaining_limit = batch_size
            if sample_limit is not None:
                remaining = sample_limit - total_processed
                if remaining <= 0:
                    break
                remaining_limit = min(batch_size, remaining)

            # Fetch batch of uncalculated relationships
            fetch_query = """
            MATCH (h:Entity)-[r]->(t:Entity)
            WHERE r.trust IS NULL
            RETURN elementId(r) AS rel_id,
                   type(r) AS rel_type,
                   r.source AS source,
                   r.confidence AS confidence,
                   r.tau AS tau,
                   r.tau_precision AS tau_precision,
                   h.name AS head_name,
                   h.type AS head_type,
                   h.first_seen AS head_first_seen,
                   h.last_seen AS head_last_seen,
                   t.name AS tail_name,
                   t.type AS tail_type,
                   t.first_seen AS tail_first_seen,
                   t.last_seen AS tail_last_seen
            LIMIT $limit
            """
            batch = self.client.execute_query(fetch_query, {"limit": remaining_limit})
            if not batch:
                break

            # 1. Extract unique triples to batch-query cross-source support and contradictions
            unique_triples = {}
            for row in batch:
                key = (row["head_name"], row["rel_type"], row["tail_name"])
                if key not in unique_triples:
                    unique_triples[key] = {
                        "head": row["head_name"],
                        "rel_type": row["rel_type"],
                        "tail": row["tail_name"],
                    }

            triple_stats = self._query_triple_stats(list(unique_triples.values()))

            # 2. Score relationships in batch
            update_payload = []
            for row in batch:
                h_name = row["head_name"]
                r_type = row["rel_type"]
                t_name = row["tail_name"]
                t_key = (h_name, r_type, t_name)

                # Sub-score 1: LLM Confidence
                s1 = compute_llm_confidence(row.get("confidence"))

                # Sub-score 2: Source Reliability
                s2 = compute_source_reliability(
                    row.get("source"),
                    head_type=row.get("head_type", "Unknown"),
                    tail_type=row.get("tail_type", "Unknown"),
                    rel_type=r_type,
                )

                # Sub-score 3: ATT&CK Similarity
                s3 = compute_attck_similarity(
                    head_name=h_name,
                    head_type=row.get("head_type", "Unknown"),
                    tail_name=t_name,
                    tail_type=row.get("tail_type", "Unknown"),
                    rel_type=r_type,
                    attck_loader=self.attck_loader,
                )

                # Sub-score 4: Cross Source Support
                t_stat = triple_stats.get(t_key, {"src_cnt": 1, "is_contradiction": False})
                s4 = compute_cross_source_support(t_stat["src_cnt"])

                # Sub-score 5: Temporal Consistency
                s5 = compute_temporal_consistency(
                    tau=row.get("tau"),
                    head_type=row.get("head_type", "Unknown"),
                    head_first_seen=row.get("head_first_seen"),
                    head_last_seen=row.get("head_last_seen"),
                )

                # Sub-score 6: Contradiction Penalty
                is_contra = t_stat["is_contradiction"]
                s6 = compute_contradiction_penalty(is_contra)
                if is_contra:
                    contradiction_count += 1

                # Final composite score
                trust, trusted = calculate_trust_score(s1, s2, s3, s4, s5, s6)
                scores.append(trust)
                if trusted:
                    total_trusted += 1
                else:
                    total_untrusted += 1

                update_payload.append({
                    "rel_id": row["rel_id"],
                    "trust": trust,
                    "trusted": trusted,
                    "s1": round(s1, 4),
                    "s2": round(s2, 4),
                    "s3": round(s3, 4),
                    "s4": round(s4, 4),
                    "s5": round(s5, 4),
                    "s6": round(s6, 4),
                })

            # 3. Write updates back to Neo4j
            self._write_batch_scores(update_payload)
            total_processed += len(batch)
            logger.info(
                f"Scored {total_processed} relationships | "
                f"Batch: {len(batch)} | Trusted: {total_trusted} | Untrusted: {total_untrusted}"
            )

        # Statistical calculations
        mean_score = sum(scores) / len(scores) if scores else 0.0
        min_score = min(scores) if scores else 0.0
        max_score = max(scores) if scores else 0.0
        variance = sum((x - mean_score) ** 2 for x in scores) / len(scores) if scores else 0.0
        std_score = math.sqrt(variance)

        results = {
            "total_processed": total_processed,
            "trusted_count": total_trusted,
            "trusted_percentage": round((total_trusted / total_processed * 100.0), 2) if total_processed else 0.0,
            "untrusted_count": total_untrusted,
            "untrusted_percentage": round((total_untrusted / total_processed * 100.0), 2) if total_processed else 0.0,
            "mean_trust": round(mean_score, 4),
            "min_trust": round(min_score, 4),
            "max_trust": round(max_score, 4),
            "std_trust": round(std_score, 4),
            "contradiction_count": contradiction_count,
        }
        return results

    def _query_triple_stats(self, triples: List[Dict[str, str]]) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
        """Query Neo4j for source count and day-precision dates for given triples."""
        if not triples:
            return {}

        query = """
        UNWIND $triples AS t
        MATCH (h:Entity {name: t.head})-[r]->(tail:Entity {name: t.tail})
        WHERE type(r) = t.rel_type
        RETURN t.head AS head, t.rel_type AS rel_type, t.tail AS tail,
               count(DISTINCT r.source) AS src_cnt,
               collect(DISTINCT CASE WHEN r.tau IS NOT NULL AND r.tau_precision = 'day' THEN r.tau ELSE null END) AS day_taus
        """
        results = self.client.execute_query(query, {"triples": triples})
        stats_map = {}
        for row in results:
            key = (row["head"], row["rel_type"], row["tail"])
            taus = [t for t in row.get("day_taus", []) if t is not None]
            is_contradiction = False
            if len(taus) > 1:
                dates = sorted([_normalize_date(t) for t in taus if _normalize_date(t) is not None])
                if len(dates) > 1 and (dates[-1] - dates[0]).days > 365:
                    is_contradiction = True

            stats_map[key] = {
                "src_cnt": row.get("src_cnt", 1),
                "is_contradiction": is_contradiction,
            }
        return stats_map

    def _write_batch_scores(self, update_payload: List[Dict[str, Any]]) -> None:
        """Write trust score properties back to relationships via UNWIND."""
        if not update_payload:
            return

        query = """
        UNWIND $batch AS item
        MATCH ()-[r]->() WHERE elementId(r) = item.rel_id
        SET r.trust = item.trust,
            r.trusted = item.trusted,
            r.score_llm_confidence = item.s1,
            r.score_source_reliability = item.s2,
            r.score_attck_similarity = item.s3,
            r.score_cross_source = item.s4,
            r.score_temporal_consistency = item.s5,
            r.score_contradiction_penalty = item.s6
        """
        self.client.execute_query(query, {"batch": update_payload})

    def verify_graph_trust(self) -> Dict[str, Any]:
        """Compute and display comprehensive trust verification statistics."""
        # Total counts
        stats_query = """
        MATCH ()-[r]->()
        RETURN count(r) AS total,
               count(r.trust) AS scored_count,
               sum(CASE WHEN r.trusted = true THEN 1 ELSE 0 END) AS trusted_count,
               sum(CASE WHEN r.trusted = false THEN 1 ELSE 0 END) AS untrusted_count,
               avg(r.trust) AS avg_trust,
               min(r.trust) AS min_trust,
               max(r.trust) AS max_trust,
               stDev(r.trust) AS std_trust,
               sum(CASE WHEN r.score_contradiction_penalty > 0 THEN 1 ELSE 0 END) AS contradictions
        """
        res = self.client.execute_query(stats_query)
        base = res[0] if res else {}

        total = base.get("total", 0)
        scored = base.get("scored_count", 0)
        trusted = base.get("trusted_count", 0)
        untrusted = base.get("untrusted_count", 0)
        avg_trust = base.get("avg_trust", 0.0) or 0.0
        min_trust = base.get("min_trust", 0.0) or 0.0
        max_trust = base.get("max_trust", 0.0) or 0.0
        std_trust = base.get("std_trust", 0.0) or 0.0
        contradictions = base.get("contradictions", 0)

        # Breakdown of trusted by relationship type
        type_query = """
        MATCH ()-[r]->()
        RETURN type(r) AS rel_type,
               count(r) AS total_type,
               sum(CASE WHEN r.trusted = true THEN 1 ELSE 0 END) AS trusted_type,
               avg(r.trust) AS avg_type_trust
        ORDER BY total_type DESC
        """
        type_res = self.client.execute_query(type_query)

        print("\n" + "=" * 80)
        print("NEO4J TEMPORAL GRAPH TRUST SCORING VERIFICATION")
        print("=" * 80)
        print(f"\n--- Overview ---")
        print(f"  Total Relationships in Graph : {total}")
        print(f"  Scored Relationships        : {scored}")
        print(f"  Trusted (trust >= {TRUST_THRESHOLD:.2f})       : {trusted} ({trusted/total*100.0:.2f}%)" if total else "0")
        print(f"  Untrusted (trust < {TRUST_THRESHOLD:.2f})      : {untrusted} ({untrusted/total*100.0:.2f}%)" if total else "0")
        print(f"  Contradictions Detected     : {contradictions}")

        print(f"\n--- Score Distribution ---")
        print(f"  Mean Trust Score            : {avg_trust:.4f}")
        print(f"  Min Trust Score             : {min_trust:.4f}")
        print(f"  Max Trust Score             : {max_score:.4f}" if "max_score" in locals() else f"  Max Trust Score             : {max_trust:.4f}")
        print(f"  Standard Deviation          : {std_trust:.4f}")

        print(f"\n--- Trusted Breakdown by Relationship Type ---")
        print(f"  {'Relationship Type':<30} {'Total':<10} {'Trusted':<10} {'% Trusted':<12} {'Avg Trust':<10}")
        print(f"  {'-'*30} {'-'*10} {'-'*10} {'-'*12} {'-'*10}")
        for row in type_res:
            rtype = row["rel_type"]
            t_tot = row["total_type"]
            t_tru = row["trusted_type"]
            pct = (t_tru / t_tot * 100.0) if t_tot else 0.0
            avg_t = row["avg_type_trust"] or 0.0
            print(f"  {rtype:<30} {t_tot:<10} {t_tru:<10} {pct:<11.2f}% {avg_t:<10.4f}")
        print("=" * 80 + "\n")

        return {
            "total": total,
            "scored": scored,
            "trusted": trusted,
            "untrusted": untrusted,
            "avg_trust": avg_trust,
            "min_trust": min_trust,
            "max_trust": max_trust,
            "std_trust": std_trust,
            "contradictions": contradictions,
            "by_type": type_res,
        }


def main():
    parser = argparse.ArgumentParser(description="Task 3: Trust Scoring & Temporal Verification")
    parser.add_argument("--all", action="store_true", help="Score all relationships in the graph")
    parser.add_argument("--sample", type=int, default=None, help="Score a sample of N relationships")
    parser.add_argument("--batch-size", type=int, default=500, help="Batch size for processing (default: 500)")
    parser.add_argument("--verify", action="store_true", help="Print trust distribution summary")
    parser.add_argument("--force", action="store_true", help="Force recomputation of all relationships")

    args = parser.parse_args()
    pipeline = TrustScoringPipeline()

    if args.verify:
        pipeline.verify_graph_trust()
        return

    if args.sample:
        results = pipeline.process_relationships(
            sample_limit=args.sample,
            batch_size=min(args.batch_size, args.sample),
            force_recompute=args.force,
        )
        print(f"Sample processing completed: {results}")
    elif args.all:
        results = pipeline.process_relationships(
            sample_limit=None,
            batch_size=args.batch_size,
            force_recompute=args.force,
        )
        print(f"Full processing completed: {results}")
        pipeline.verify_graph_trust()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
