import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from config.settings import (
    NORMALIZED_EXTRACTED_DIR,
    BASE_DIR,
)
from common.neo4j_client import Neo4jClient
from common.logging_utils import setup_logger

logger = setup_logger("task2_temporal_graph", "task2_graph.log")

SCHEMA_CQL_PATH = BASE_DIR / "tasks" / "cypher" / "schema_setup.cql"

# Professor's complete ontology entity types
VALID_ENTITY_TYPES = {
    "ThreatActor",
    "Malware",
    "Tool",
    "Vulnerability",
    "Product",
    "AttackTechnique",
    "ATT&CKTactic",
    "Target",
    "Location",
    "IOC",
    "Campaign",
    "Time",
    "EvidenceSource",
}


def clean_relation_type(relation_str: str) -> str:
    """
    Converts a relation string into an UPPER_SNAKE_CASE Cypher relationship type.
    Examples:
      'has_hash' -> 'HAS_HASH'
      'uses' -> 'USES'
      'communicates_with' -> 'COMMUNICATES_WITH'
      'belongs_to_tactic' -> 'BELONGS_TO_TACTIC'
      'drops-file' -> 'DROPS_FILE'
      'spies on' -> 'SPIES_ON'
    """
    if not relation_str:
        return "RELATES_TO"

    # Replace any non-alphanumeric character with underscore
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", relation_str.strip())
    # Collapse multiple consecutive underscores
    cleaned = re.sub(r"_+", "_", cleaned)
    cleaned = cleaned.strip("_").upper()

    if not cleaned:
        return "RELATES_TO"
    # Ensure relationship type starts with an alphabetic character
    if not cleaned[0].isalpha():
        cleaned = f"REL_{cleaned}"
    return cleaned


def parse_temporal_expression(time_val: Any) -> Tuple[Optional[str], str, str]:
    """
    Parses temporal string into (tau_iso, tau_raw, tau_precision).
    Supports:
      - Full date 'YYYY-MM-DD' -> ('YYYY-MM-DDT00:00:00Z', 'YYYY-MM-DD', 'day')
      - ISO datetime 'YYYY-MM-DDTHH:MM:SS...' -> ('...', '...', 'day')
      - Year-Month 'YYYY-MM' -> ('YYYY-MM-01T00:00:00Z', 'YYYY-MM', 'month')
      - Year only 'YYYY' -> ('YYYY-01-01T00:00:00Z', 'YYYY', 'year')
      - 'unknown' / null -> (None, 'unknown', 'unknown')
    """
    if time_val is None:
        return None, "unknown", "unknown"

    raw_str = str(time_val).strip()
    if not raw_str or raw_str.lower() in ("unknown", "null", "none", ""):
        return None, "unknown", "unknown"

    # Full date pattern: YYYY-MM-DD
    full_date_match = re.match(r"^(\d{4})-(\d{2})-(\d{2})(?:T.*)?$", raw_str)
    if full_date_match:
        year, month, day = full_date_match.groups()
        try:
            # Validate calendar correctness
            dt = datetime(int(year), int(month), int(day))
            iso_str = dt.strftime("%Y-%m-%dT00:00:00Z")
            return iso_str, raw_str, "day"
        except ValueError:
            return None, raw_str, "unknown"

    # Month pattern: YYYY-MM
    month_match = re.match(r"^(\d{4})-(\d{2})$", raw_str)
    if month_match:
        year, month = month_match.groups()
        try:
            dt = datetime(int(year), int(month), 1)
            iso_str = dt.strftime("%Y-%m-%dT00:00:00Z")
            return iso_str, raw_str, "month"
        except ValueError:
            return None, raw_str, "unknown"

    # Year pattern: YYYY
    year_match = re.match(r"^(\d{4})$", raw_str)
    if year_match:
        year = int(year_match.group(1))
        if 1970 <= year <= 2100:
            dt = datetime(year, 1, 1)
            iso_str = dt.strftime("%Y-%m-%dT00:00:00Z")
            return iso_str, raw_str, "year"

    return None, raw_str, "unknown"


def _clean_entity_text(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, dict):
        return str(val.get("text") or val.get("canonical_name") or "").strip()
    s = str(val).strip()
    dict_match = re.match(r"^\{['\"](?:text|canonical_name)['\"]\s*:\s*['\"]([^'\"]+)['\"]\}$", s)
    if dict_match:
        return dict_match.group(1).strip()
    return s


def resolve_entity(
    name_or_text: str,
    entities_lookup: Dict[str, Dict[str, Any]],
    file_id: str,
    warning_collector: Optional[List[str]] = None,
) -> Tuple[str, str, str]:
    """
    Resolves a head/tail relation reference to (resolved_name, resolved_type, raw_text).
    If not found in the file's entities list, defaults type to 'Unknown' and logs a warning.
    """
    cleaned_ref = _clean_entity_text(name_or_text)
    lookup_key = cleaned_ref.lower()

    if lookup_key in entities_lookup:
        ent = entities_lookup[lookup_key]
        return ent["name"], ent["type"], ent["raw_text"]

    # Fallback to Unknown
    warn_msg = f"[{file_id}] Entity reference '{cleaned_ref}' not found in entities list. Defaulting type to 'Unknown'."
    logger.warning(warn_msg)
    if warning_collector is not None:
        warning_collector.append(warn_msg)

    return cleaned_ref, "Unknown", cleaned_ref


def prepare_graph_payload(
    file_path: Path,
    warning_collector: Optional[List[str]] = None,
) -> Tuple[str, List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    """
    Reads an extracted JSON file and prepares structured payloads for Neo4j batch writing.
    Accepts all ontology types dynamically and validates against VALID_ENTITY_TYPES.
    Returns (source_id, entities_payload, relations_by_type_payload).
    """
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    source_id = str(data.get("id", file_path.stem))
    raw_entities = data.get("entities", [])
    raw_relations = data.get("relations", [])

    # 1. Build Entity Lookup and Entity Payload
    entities_lookup: Dict[str, Dict[str, Any]] = {}
    entities_by_key: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for ent in raw_entities:
        raw_text = str(ent.get("text", "")).strip()
        canon_name = str(ent.get("canonical_name", "")).strip() if ent.get("canonical_name") else ""
        name = canon_name if canon_name else raw_text
        ent_type = str(ent.get("type", "Unknown")).strip()
        if not name:
            continue

        # Check if type is in the valid ontology list; if not, log warning but keep type
        if ent_type not in VALID_ENTITY_TYPES and ent_type != "Unknown":
            warn_msg = f"[{source_id}] Entity '{name}' has non-standard type '{ent_type}'."
            logger.warning(warn_msg)
            if warning_collector is not None:
                warning_collector.append(warn_msg)

        ent_record = {
            "name": name,
            "type": ent_type,
            "raw_text": raw_text,
            "tau": None,  # Will be populated from relations if applicable
        }

        # Index by both text and canonical_name
        entities_lookup[raw_text.lower()] = ent_record
        if canon_name:
            entities_lookup[canon_name.lower()] = ent_record

        key = (name, ent_type)
        if key not in entities_by_key:
            entities_by_key[key] = ent_record

    # 2. Process Relations and collect earliest/latest tau for entities
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    relations_by_type: Dict[str, List[Dict[str, Any]]] = {}

    for rel in raw_relations:
        head_ref = str(rel.get("head", "")).strip()
        tail_ref = str(rel.get("tail", "")).strip()
        rel_raw = str(rel.get("relation", "")).strip()
        if not head_ref or not tail_ref:
            continue

        rel_type = clean_relation_type(rel_raw)
        head_name, head_type, head_raw_text = resolve_entity(
            head_ref, entities_lookup, source_id, warning_collector
        )
        tail_name, tail_type, tail_raw_text = resolve_entity(
            tail_ref, entities_lookup, source_id, warning_collector
        )

        # Ensure head & tail exist in entities_by_key
        h_key = (head_name, head_type)
        if h_key not in entities_by_key:
            entities_by_key[h_key] = {
                "name": head_name,
                "type": head_type,
                "raw_text": head_raw_text,
                "tau": None,
            }
        t_key = (tail_name, tail_type)
        if t_key not in entities_by_key:
            entities_by_key[t_key] = {
                "name": tail_name,
                "type": tail_type,
                "raw_text": tail_raw_text,
                "tau": None,
            }

        tau_iso, tau_raw, tau_precision = parse_temporal_expression(rel.get("time"))

        # Propagate tau to entity records for first_seen/last_seen initialization
        if tau_iso:
            for k in (h_key, t_key):
                if entities_by_key[k]["tau"] is None:
                    entities_by_key[k]["tau"] = tau_iso

        rel_payload = {
            "head_name": head_name,
            "head_type": head_type,
            "tail_name": tail_name,
            "tail_type": tail_type,
            "source": source_id,
            "tau": tau_iso,
            "tau_raw": tau_raw,
            "tau_precision": tau_precision,
            "evidence": str(rel.get("evidence", "")).strip(),
            "confidence": float(rel.get("confidence", 1.0)),
            "created_at": now_iso,
        }

        if rel_type not in relations_by_type:
            relations_by_type[rel_type] = []
        relations_by_type[rel_type].append(rel_payload)

    entities_payload = list(entities_by_key.values())
    return source_id, entities_payload, relations_by_type


def write_file_to_graph_tx(
    tx: Any,
    entities_payload: List[Dict[str, Any]],
    relations_by_type: Dict[str, List[Dict[str, Any]]],
):
    """
    Executes node merges and dynamic relationship merges in a single transactional unit.
    """
    # 1. Merge Entities
    if entities_payload:
        entity_cypher = """
        UNWIND $entities AS ent
        MERGE (e:Entity {name: ent.name, type: ent.type})
        ON CREATE SET
          e.raw_text = ent.raw_text,
          e.canonical_id = null,
          e.first_seen = CASE WHEN ent.tau IS NOT NULL THEN datetime(ent.tau) ELSE null END,
          e.last_seen = CASE WHEN ent.tau IS NOT NULL THEN datetime(ent.tau) ELSE null END
        ON MATCH SET
          e.raw_text = CASE WHEN e.raw_text IS NULL THEN ent.raw_text ELSE e.raw_text END,
          e.first_seen = CASE 
            WHEN ent.tau IS NOT NULL AND (e.first_seen IS NULL OR datetime(ent.tau) < e.first_seen) THEN datetime(ent.tau) 
            ELSE e.first_seen 
          END,
          e.last_seen = CASE 
            WHEN ent.tau IS NOT NULL AND (e.last_seen IS NULL OR datetime(ent.tau) > e.last_seen) THEN datetime(ent.tau) 
            ELSE e.last_seen 
          END
        """
        tx.run(entity_cypher, entities=entities_payload)

    # 2. Merge Relationships grouped by type
    for rel_type, rel_list in relations_by_type.items():
        rel_cypher = f"""
        UNWIND $relations AS rel
        MATCH (h:Entity {{name: rel.head_name, type: rel.head_type}})
        MATCH (t:Entity {{name: rel.tail_name, type: rel.tail_type}})
        MERGE (h)-[r:{rel_type} {{source: rel.source}}]->(t)
        ON CREATE SET
          r.tau = CASE WHEN rel.tau IS NOT NULL THEN datetime(rel.tau) ELSE null END,
          r.tau_raw = rel.tau_raw,
          r.tau_precision = rel.tau_precision,
          r.evidence = rel.evidence,
          r.confidence = rel.confidence,
          r.trust = null,
          r.created_at = datetime(rel.created_at)
        ON MATCH SET
          r.tau = CASE WHEN rel.tau IS NOT NULL THEN datetime(rel.tau) ELSE null END,
          r.tau_raw = rel.tau_raw,
          r.tau_precision = rel.tau_precision,
          r.evidence = rel.evidence,
          r.confidence = rel.confidence
        """
        tx.run(rel_cypher, relations=rel_list)


def ingest_batch_files(
    file_paths: List[Path],
    client: Neo4jClient,
    warning_collector: Optional[List[str]] = None,
) -> Tuple[int, int]:
    """
    Ingests multiple extracted JSON files in a single multi-file transaction using UNWIND.
    """
    combined_entities: Dict[Tuple[str, str], Dict[str, Any]] = {}
    combined_relations: Dict[str, List[Dict[str, Any]]] = {}

    for f_path in file_paths:
        source_id, entities_payload, relations_by_type = prepare_graph_payload(
            f_path, warning_collector
        )
        for ent in entities_payload:
            key = (ent["name"], ent["type"])
            if key not in combined_entities:
                combined_entities[key] = ent
            else:
                if ent["tau"]:
                    if combined_entities[key]["tau"] is None or ent["tau"] < combined_entities[key]["tau"]:
                        combined_entities[key]["tau"] = ent["tau"]

        for rel_type, rel_list in relations_by_type.items():
            if rel_type not in combined_relations:
                combined_relations[rel_type] = []
            combined_relations[rel_type].extend(rel_list)

    total_entities = len(combined_entities)
    total_relations = sum(len(rels) for rels in combined_relations.values())

    if total_entities > 0 or total_relations > 0:
        client.execute_write_transaction(
            write_file_to_graph_tx,
            entities_payload=list(combined_entities.values()),
            relations_by_type=combined_relations,
        )

    return total_entities, total_relations


def ingest_extracted_file(
    file_path: Path | str,
    client: Neo4jClient,
    warning_collector: Optional[List[str]] = None,
) -> Tuple[int, int]:
    """
    Ingests a single extracted JSON file into Neo4j in a single transaction.
    Returns (num_entities, num_relations).
    """
    path = Path(file_path)
    if not path.exists():
        logger.error(f"Extracted JSON file not found: {path}")
        return 0, 0

    return ingest_batch_files([path], client, warning_collector)


def ingest_all(
    extracted_dir: Path = NORMALIZED_EXTRACTED_DIR,
    client: Optional[Neo4jClient] = None,
    limit: Optional[int] = None,
    batch_size: int = 100,
) -> Dict[str, Any]:
    """
    Ingests all extracted JSON files into Neo4j using multi-file UNWIND batches (default: 100 files/batch).
    """
    neo4j_client = client or Neo4jClient()
    files = sorted(list(extracted_dir.glob("*.json")))
    if limit is not None and limit > 0:
        files = files[:limit]

    logger.info(f"Starting Task 2 Graph Ingestion for {len(files)} files in {extracted_dir} (batch size: {batch_size})")
    warnings: List[str] = []
    total_nodes = 0
    total_edges = 0
    start_time = datetime.now(timezone.utc)

    for i in range(0, len(files), batch_size):
        chunk = files[i : i + batch_size]
        try:
            n_count, e_count = ingest_batch_files(chunk, neo4j_client, warnings)
            total_nodes += n_count
            total_edges += e_count

            processed_count = min(i + batch_size, len(files))
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.info(
                f"Progress: [{processed_count}/{len(files)}] files processed | Batch Nodes: {n_count} | Batch Edges: {e_count} | Elapsed: {elapsed:.1f}s"
            )
        except Exception as e:
            logger.error(f"Error ingesting batch at index {i}: {e}")

    total_time = (datetime.now(timezone.utc) - start_time).total_seconds()
    stats = {
        "total_files": len(files),
        "total_nodes_ingested": total_nodes,
        "total_edges_ingested": total_edges,
        "warning_count": len(warnings),
        "warnings_sample": warnings[:5],
        "elapsed_seconds": total_time,
    }
    logger.info(f"Task 2 Ingestion Complete. Stats: {stats}")
    return stats


def print_verification_summary(client: Neo4jClient, warnings_sample: Optional[List[str]] = None):
    """
    Executes and prints verification queries against the active Neo4j graph.
    """
    print("\n" + "=" * 80)
    print("NEO4J TEMPORAL GRAPH VERIFICATION SUMMARY")
    print("=" * 80)

    # 1. Total node count by type
    node_stats = client.execute_query(
        "MATCH (e:Entity) RETURN e.type AS type, count(*) AS count ORDER BY count DESC"
    )
    total_nodes = sum(r["count"] for r in node_stats)
    print(f"\n--- Total Entities ({total_nodes} nodes) ---")
    for r in node_stats:
        print(f"  {r['type']:25}: {r['count']}")

    # 2. Total relationship count by type
    rel_stats = client.execute_query(
        "MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS count ORDER BY count DESC"
    )
    total_rels = sum(r["count"] for r in rel_stats)
    print(f"\n--- Total Relationships ({total_rels} edges) ---")
    for r in rel_stats:
        print(f"  {r['type']:25}: {r['count']}")

    # 3. Relationships with tau populated vs null
    tau_stats = client.execute_query(
        """
        MATCH ()-[r]->() 
        RETURN 
          CASE WHEN r.tau IS NULL THEN 'Unknown / Null' ELSE 'Populated (Tau)' END AS tau_status, 
          count(*) AS count
        """
    )
    print("\n--- Temporal (Tau) Distribution ---")
    for r in tau_stats:
        print(f"  {r['tau_status']:25}: {r['count']}")

    # 4. Warnings summary
    if warnings_sample:
        print(f"\n--- Head/Tail Resolution Warnings Sample ({len(warnings_sample)} sampled) ---")
        for w in warnings_sample[:5]:
            print(f"  * {w}")
    print("\n" + "=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Task 2 Temporal Knowledge Graph Builder")
    parser.add_argument("--setup-schema", action="store_true", help="Apply Cypher constraints and indexes")
    parser.add_argument("--input", type=str, help="Single extracted record ID (e.g. 2019_1976 or CVE-2026-74234)")
    parser.add_argument("--all", action="store_true", help="Ingest all files in data/normalized/extracted/")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of files to ingest")
    parser.add_argument("--batch-size", type=int, default=100, help="Number of files per UNWIND batch transaction")
    parser.add_argument("--verify", action="store_true", help="Run verification queries on active Neo4j graph")
    args = parser.parse_args()

    client = Neo4jClient()

    if args.setup_schema:
        print(f"Applying schema from {SCHEMA_CQL_PATH}...")
        results = client.apply_schema(SCHEMA_CQL_PATH)
        for r in results:
            print(" ", r)

    if args.input:
        f_path = NORMALIZED_EXTRACTED_DIR / f"{args.input}.json"
        warnings = []
        n, e = ingest_extracted_file(f_path, client, warnings)
        print(f"Ingested {args.input}: {n} entities, {e} relations.")
        if warnings:
            print(f"Warnings ({len(warnings)}):", warnings[:3])

    if args.all or args.limit:
        stats = ingest_all(NORMALIZED_EXTRACTED_DIR, client, limit=args.limit, batch_size=args.batch_size)
        print("\nIngestion Summary:", json.dumps(stats, indent=2))
        print_verification_summary(client, stats.get("warnings_sample"))

    if args.verify and not args.all and not args.limit:
        print_verification_summary(client)


if __name__ == "__main__":
    main()
