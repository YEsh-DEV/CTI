import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config.settings import (
    NORMALIZED_CTI_DIR,
    NORMALIZED_CVE_DIR,
    NORMALIZED_EXTRACTED_DIR,
    OLLAMA_HOST,
    OLLAMA_MODEL,
)
from schemas.normalized import NormalizedCTIEvent, NormalizedCVE
from schemas.extraction import (
    ExtractedEntity,
    ExtractedRelation,
    UnifiedExtractionResult,
)
from common.llm_client import OllamaClient
from common.logging_utils import setup_logger

logger = setup_logger("task1_extraction", "task1_extraction.log")

# Mapping from IOC types to relationship labels
IOC_TYPE_RELATION_MAP = {
    "md5": "has_hash",
    "sha1": "has_hash",
    "sha256": "has_hash",
    "ip-src": "communicates_with",
    "ip-dst": "communicates_with",
    "url": "uses_domain",
    "domain": "uses_domain",
    "hostname": "uses_domain",
    "filename": "drops_file",
}

# Mapping from IOC types to entity types (single 'IOC' type per professor's ontology)
IOC_TYPE_ENTITY_MAP = {
    "md5": "IOC",
    "sha1": "IOC",
    "sha256": "IOC",
    "ip-src": "IOC",
    "ip-dst": "IOC",
    "url": "IOC",
    "domain": "IOC",
    "hostname": "IOC",
    "filename": "IOC",
}

EXTRACTION_PROMPT_TEMPLATE = """You are a cybersecurity threat intelligence analyst.
Extract CTI knowledge from the given report text.
Return ONLY valid JSON with root keys "entities" and "relations".

Extract these entity types when present:
1. ThreatActor: threat actor, APT group, hacker gang name
2. Malware: malware families, trojans, ransomware, backdoors
3. Tool: legitimate administration or offensive software used (e.g. PowerShell, Cobalt Strike, Mimikatz)
4. Vulnerability: CVE identifiers (e.g. CVE-2017-11882)
5. Product: software or hardware product affected (e.g. Windows, Office)
6. ATT&CKTactic: MITRE ATT&CK tactic names (e.g. Initial Access, Persistence, Execution)
7. AttackTechnique: MITRE ATT&CK technique names or IDs (e.g. Spearphishing Attachment, T1059)
8. Target: targeted entities, victims, organizations, or industry sectors
9. Location: countries, regions, cities targeted or originating attacks (e.g. Ukraine, Middle East)
10. Campaign: named operation or campaign (e.g. Operation Ghost, SolarWinds Campaign)
11. Time: temporal expressions mentioned (e.g. "May 2018", "Q3 2019", "2019-01-30")
12. EvidenceSource: report titles, security vendors, blogs, or PDFs

Use these relation types where appropriate:
precedes, enables, observed_in, same_as, evolves_to, indicates, belongs_to_tactic, belongs_to_technique, uses, exploits, targets, drops_file, communicates_with, has_hash, uses_domain, has_vulnerability

Instructions:
- Only extract entities and relations that are EXPLICITLY mentioned in the input text.
- If the input text contains no narrative entities or relations (e.g. only a raw hash or filename), return empty lists: {"entities": [], "relations": []}.
- For confidence, assign a single floating-point number between 0.0 and 1.0 (e.g. 0.95 for high certainty, 0.75 for moderate, 0.55 for low). Never output range strings like 0.7-0.8. Do NOT default to 1.0.
- Do NOT hallucinate or invent entities not written in the text.

Expected JSON output format schema:
{
  "entities": [
    {"text": "<verbatim text>", "type": "<ThreatActor|Malware|Tool|Vulnerability|Product|AttackTechnique|ATT&CKTactic|Target|Location|IOC|Campaign|Time|EvidenceSource>", "canonical_name": "<standardized name>", "confidence": <float between 0.0 and 1.0>}
  ],
  "relations": [
    {
      "head": "<head entity>",
      "relation": "<uses|exploits|targets|precedes|enables|observed_in|same_as|evolves_to|indicates|belongs_to_tactic|belongs_to_technique|drops_file|communicates_with|has_hash|uses_domain|has_vulnerability>",
      "tail": "<tail entity>",
      "time": "<date or time expression if mentioned, else null>",
      "evidence": "<verbatim sentence from input>",
      "confidence": <float between 0.0 and 1.0>
    }
  ]
}

Input CTI text:
{cti_report_chunk}
"""


def _parse_confidence(val: Any, default: float = 0.8) -> float:
    """Parses raw confidence from model output (handling floats, ints, or range strings like '0.7-0.8')."""
    if val is None:
        return default
    if isinstance(val, (int, float)):
        return max(0.0, min(1.0, float(val)))
    if isinstance(val, str):
        val_str = val.strip()
        range_match = re.match(r"^([0-9\.]+)\s*[-–]\s*([0-9\.]+)$", val_str)
        if range_match:
            try:
                low = float(range_match.group(1))
                high = float(range_match.group(2))
                return max(0.0, min(1.0, (low + high) / 2.0))
            except ValueError:
                pass
        try:
            parsed = float(val_str)
            return max(0.0, min(1.0, parsed))
        except ValueError:
            return default
    return default


def extract_deterministic_cti_iocs(event: NormalizedCTIEvent) -> Tuple[List[ExtractedEntity], List[ExtractedRelation]]:
    """
    Extracts deterministic entities and relations directly from normalized IOC attributes.
    All IOCs are typed as 'IOC' in accordance with the professor's ontology.
    """
    entities: List[ExtractedEntity] = []
    relations: List[ExtractedRelation] = []

    tau_str = event.date.strftime("%Y-%m-%d") if hasattr(event.date, "strftime") else str(event.date)
    head_entity = event.info_title.strip() if event.info_title.strip() else f"Event_{event.id}"

    seen_entities = set()

    if event.iocs:
        head_key = (head_entity, "EvidenceSource")
        if head_key not in seen_entities:
            entities.append(
                ExtractedEntity(
                    text=head_entity,
                    type="EvidenceSource",
                    canonical_name=head_entity,
                    confidence=1.0,
                )
            )
            seen_entities.add(head_key)

    for ioc in event.iocs:
        ioc_type_lower = ioc.type.lower().strip()
        rel_label = IOC_TYPE_RELATION_MAP.get(ioc_type_lower)
        ent_type = IOC_TYPE_ENTITY_MAP.get(ioc_type_lower, "IOC")

        if not rel_label:
            if ioc_type_lower in ("comment", "other", "text"):
                continue
            rel_label = "has_ioc"

        ioc_val = ioc.value.strip()

        # Add IOC Entity
        ent_key = (ioc_val, ent_type)
        if ent_key not in seen_entities:
            entities.append(
                ExtractedEntity(
                    text=ioc_val,
                    type=ent_type,
                    canonical_name=ioc_val,
                    confidence=1.0,  # Deterministic parse has full confidence
                )
            )
            seen_entities.add(ent_key)

        # Add IOC Relation
        relations.append(
            ExtractedRelation(
                head=head_entity,
                relation=rel_label,
                tail=ioc_val,
                time=tau_str,
                evidence=f"IOC of type {ioc.type} found in event {event.id}",
                confidence=1.0,
            )
        )

    return entities, relations


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


def is_likely_narrative(text: str) -> bool:
    """Checks if text contains narrative sentences/phrases rather than a bare hash or filename."""
    if not text:
        return False
    tokens = text.strip().split()
    if len(tokens) <= 2:
        first = tokens[0].lower()
        # Bare MD5 / SHA1 / SHA256
        if re.match(r"^[a-f0-9]{32,64}$", first):
            return False
        # Bare IP
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", first):
            return False
        # Bare single filename / extension
        if re.match(r"^[a-z0-9_\-\.]+\.(exe|dll|pdf|doc|docx|zip|rar|bin|apk|sh|py|vbs|bat|cab)$", first, re.I):
            return False
    return True


def extract_llm_cti_knowledge(
    event: NormalizedCTIEvent, llm_client: OllamaClient
) -> Tuple[List[ExtractedEntity], List[ExtractedRelation]]:
    """
    Extracts high-level relational entities and triples from event.info_title using Ollama LLM.
    Preserves model's genuine confidence output without artificial overrides.
    """
    title = event.info_title.strip()
    if not title or not is_likely_narrative(title):
        return [], []

    user_prompt = EXTRACTION_PROMPT_TEMPLATE.replace("{cti_report_chunk}", title)
    context_id = f"cti_event_{event.id}"

    extracted_dict, raw_response = llm_client.extract_structured_json(
        system_prompt="You are a strict Cyber Threat Intelligence analyst. Output ONLY valid JSON according to the ontology schema. Never invent entities.",
        user_prompt=user_prompt,
        context_id=context_id,
    )

    if not extracted_dict:
        return [], []

    tau_str = event.date.strftime("%Y-%m-%d") if hasattr(event.date, "strftime") else str(event.date)

    entities: List[ExtractedEntity] = []
    for ent in extracted_dict.get("entities", []):
        if isinstance(ent, dict):
            raw_t = _clean_entity_text(ent.get("text"))
            canon_t = _clean_entity_text(ent.get("canonical_name")) or raw_t
            if raw_t:
                conf = _parse_confidence(ent.get("confidence"), default=0.85)
                entities.append(
                    ExtractedEntity(
                        text=raw_t,
                        type=str(ent.get("type", "Unknown")).strip(),
                        canonical_name=canon_t,
                        confidence=conf,
                    )
                )

    relations: List[ExtractedRelation] = []
    for rel in extracted_dict.get("relations", []):
        if isinstance(rel, dict):
            h_text = _clean_entity_text(rel.get("head"))
            t_text = _clean_entity_text(rel.get("tail"))
            if h_text and t_text:
                conf = _parse_confidence(rel.get("confidence"), default=0.85)
                time_val = rel.get("time")
                if time_val is None or time_val in ("null", "None", ""):
                    time_val = tau_str

                relations.append(
                    ExtractedRelation(
                        head=h_text,
                        relation=str(rel.get("relation", "relates_to")).strip(),
                        tail=t_text,
                        time=str(time_val),
                        evidence=_clean_entity_text(rel.get("evidence")) or title,
                        confidence=conf,
                    )
                )

    return entities, relations


def extract_cve_knowledge(cve: NormalizedCVE) -> Tuple[List[ExtractedEntity], List[ExtractedRelation]]:
    """
    Extracts deterministic vulnerability entities and relations from NormalizedCVE.
    Deduplicates vendor and product if they are identical (e.g. 'Legora' rather than 'Legora Legora').
    """
    vendor = (cve.affected_vendor or "").strip()
    product = (cve.affected_product or "").strip()

    if vendor and product:
        if vendor.lower() == product.lower():
            affected_name = product
        else:
            affected_name = f"{vendor} {product}".strip()
    else:
        affected_name = product or vendor or cve.cve_id

    tau_date = cve.date_public or cve.date_published
    tau_str = tau_date.strftime("%Y-%m-%d") if tau_date else None
    evidence_snippet = cve.description[:200] if cve.description else f"Vulnerability {cve.cve_id}"

    entities = [
        ExtractedEntity(
            text=affected_name,
            type="Product",
            canonical_name=affected_name,
            confidence=1.0,
        ),
        ExtractedEntity(
            text=cve.cve_id,
            type="Vulnerability",
            canonical_name=cve.cve_id,
            confidence=1.0,
        ),
    ]

    relations = [
        ExtractedRelation(
            head=affected_name,
            relation="has_vulnerability",
            tail=cve.cve_id,
            time=tau_str,
            evidence=evidence_snippet,
            confidence=1.0,
        )
    ]

    return entities, relations


def save_unified_extraction_result(
    result: UnifiedExtractionResult,
    output_dir: Path = NORMALIZED_EXTRACTED_DIR,
) -> Path:
    """Saves the unified extraction result to data/normalized/extracted/{id}.json."""
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{result.id}.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result.model_dump(mode="json"), f, indent=2, default=str)
    return out_path


def process_cti_event(
    event_identifier: str | int,
    cti_dir: Path = NORMALIZED_CTI_DIR,
    output_dir: Path = NORMALIZED_EXTRACTED_DIR,
    llm_client: Optional[OllamaClient] = None,
) -> Optional[UnifiedExtractionResult]:
    """
    Loads a normalized CTI event by composite identifier (e.g. '2019_1976') or raw event_id,
    runs hybrid extraction, and saves unified result.
    """
    ident_str = str(event_identifier).strip()
    event_file = cti_dir / f"{ident_str}.json"

    if not event_file.exists():
        matching = list(cti_dir.glob(f"*_{ident_str}.json"))
        if matching:
            event_file = matching[0]
        else:
            logger.error(f"Normalized CTI event file not found for identifier '{ident_str}' in {cti_dir}")
            return None

    with open(event_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    event = NormalizedCTIEvent(**data)

    client = llm_client or OllamaClient()

    # 1. Deterministic IOC entities & relations
    det_entities, det_relations = extract_deterministic_cti_iocs(event)

    # 2. LLM Narrative entities & relations
    llm_entities, llm_relations = extract_llm_cti_knowledge(event, client)

    # Combine into unified result
    all_entities = det_entities + llm_entities
    all_relations = det_relations + llm_relations

    result = UnifiedExtractionResult(
        id=event.id,
        entities=all_entities,
        relations=all_relations,
    )

    save_unified_extraction_result(result, output_dir)
    logger.info(
        f"CTI Event {event.id}: extracted {len(all_entities)} entities "
        f"({len(det_entities)} IOCs, {len(llm_entities)} LLM) and {len(all_relations)} relations "
        f"({len(det_relations)} IOCs, {len(llm_relations)} LLM)."
    )
    return result


def process_cve_record(
    cve_id: str,
    cve_dir: Path = NORMALIZED_CVE_DIR,
    output_dir: Path = NORMALIZED_EXTRACTED_DIR,
) -> Optional[UnifiedExtractionResult]:
    """Loads a normalized CVE record, extracts facts, and saves unified result."""
    cve_file = cve_dir / f"{cve_id}.json"
    if not cve_file.exists():
        logger.error(f"Normalized CVE file not found: {cve_file}")
        return None

    with open(cve_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    cve = NormalizedCVE(**data)

    entities, relations = extract_cve_knowledge(cve)
    result = UnifiedExtractionResult(
        id=cve.cve_id,
        entities=entities,
        relations=relations,
    )

    save_unified_extraction_result(result, output_dir)
    logger.info(f"CVE {cve_id}: extracted {len(entities)} entities and {len(relations)} relations.")
    return result


def process_all(
    cti_dir: Path = NORMALIZED_CTI_DIR,
    cve_dir: Path = NORMALIZED_CVE_DIR,
    output_dir: Path = NORMALIZED_EXTRACTED_DIR,
) -> Dict[str, Any]:
    """Processes all normalized CTI and CVE records into unified extraction format."""
    client = OllamaClient()

    cti_files = sorted(list(cti_dir.glob("*.json")))
    cve_files = sorted(list(cve_dir.glob("*.json")))

    stats = {
        "total_cti": len(cti_files),
        "total_cve": len(cve_files),
        "cti_processed": 0,
        "cve_processed": 0,
        "llm_non_null": 0,
        "llm_null_or_empty": 0,
        "total_entities": 0,
        "total_relations": 0,
    }

    logger.info(f"Processing all records: {len(cti_files)} CTI events, {len(cve_files)} CVE records")

    for cti_path in cti_files:
        try:
            event_ident = cti_path.stem
            res = process_cti_event(event_ident, cti_dir, output_dir, client)
            if res:
                stats["cti_processed"] += 1
                stats["total_entities"] += len(res.entities)
                stats["total_relations"] += len(res.relations)
        except Exception as e:
            logger.error(f"Error processing CTI file {cti_path.name}: {e}")

    for cve_path in cve_files:
        try:
            cve_id = cve_path.stem
            res = process_cve_record(cve_id, cve_dir, output_dir)
            if res:
                stats["cve_processed"] += 1
                stats["total_entities"] += len(res.entities)
                stats["total_relations"] += len(res.relations)
        except Exception as e:
            logger.error(f"Error processing CVE file {cve_path.name}: {e}")

    logger.info(f"Task 1 Extraction Completed. Stats: {stats}")
    return stats


def main():
    parser = argparse.ArgumentParser(description="Task 1 Extraction CLI (Single Source of Truth)")
    parser.add_argument("--cti-event", type=str, help="Composite CTI event identifier (e.g. 2019_1976)")
    parser.add_argument("--cve", type=str, help="Single CVE ID to extract knowledge from (e.g. CVE-2026-74234)")
    parser.add_argument("--all", action="store_true", help="Process all normalized CTI and CVE records")
    args = parser.parse_args()

    if args.cti_event:
        process_cti_event(args.cti_event)
    elif args.cve:
        process_cve_record(args.cve)
    elif args.all:
        process_all()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
