from typing import List, Optional, Literal
from pydantic import BaseModel, ConfigDict, Field

EntityType = Literal[
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
]


class ExtractedEntity(BaseModel):
    text: str = Field(description="Exact entity text from report / IOC value")
    type: str = Field(
        description="Entity type (ThreatActor | Malware | Tool | Vulnerability | Product | AttackTechnique | ATT&CKTactic | Target | Location | IOC | Campaign | Time | EvidenceSource)"
    )
    canonical_name: Optional[str] = Field(default=None, description="Standardized canonical name")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Extraction confidence score")

    model_config = ConfigDict(extra="ignore")


class ExtractedRelation(BaseModel):
    head: str = Field(description="Head entity name")
    relation: str = Field(
        description="Relationship label (e.g. uses, exploits, targets, precedes, enables, observed_in, same_as, evolves_to, indicates, belongs_to_tactic, belongs_to_technique, has_hash, communicates_with, drops_file, uses_domain, has_vulnerability)"
    )
    tail: str = Field(description="Tail entity name or IOC value")
    time: Optional[str] = Field(default=None, description="Timestamp or temporal expression (e.g. YYYY-MM-DD)")
    evidence: str = Field(description="Verbatim evidence text from the report / IOC trace")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Extraction confidence score")

    model_config = ConfigDict(extra="ignore")


class UnifiedExtractionResult(BaseModel):
    """
    Unified extraction envelope for all CTI events and CVE records.
    Single source of truth for downstream Task 2 Neo4j ingestion.
    """
    id: str = Field(description="Identifier (composite CTI event_id e.g. 2019_1976 or cve_id)")
    entities: List[ExtractedEntity] = Field(default_factory=list)
    relations: List[ExtractedRelation] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")
