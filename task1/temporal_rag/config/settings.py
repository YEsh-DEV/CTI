import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory for the temporal_rag project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file if it exists
env_path = BASE_DIR / ".env"
load_dotenv(dotenv_path=env_path)

# LLM / Ollama settings
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "deepseek-r1:1.5b")

# Neo4j settings
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER") or os.getenv("NEO4J_USERNAME") or "neo4j"
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

# Data directories
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
RAW_CTI_DIR = Path(os.getenv("RAW_CTI_DIR", str(DATA_DIR / "raw" / "cti")))
RAW_CVE_DIR = Path(os.getenv("RAW_CVE_DIR", str(DATA_DIR / "raw" / "cve")))

NORMALIZED_CTI_DIR = Path(os.getenv("NORMALIZED_CTI_DIR", str(DATA_DIR / "normalized" / "cti")))
NORMALIZED_CVE_DIR = Path(os.getenv("NORMALIZED_CVE_DIR", str(DATA_DIR / "normalized" / "cve")))
NORMALIZED_EXTRACTED_DIR = Path(os.getenv("NORMALIZED_EXTRACTED_DIR", str(DATA_DIR / "normalized" / "extracted")))
NORMALIZED_REJECTED_DIR = Path(os.getenv("NORMALIZED_REJECTED_DIR", str(DATA_DIR / "normalized" / "_rejected")))

# Log directory
LOG_DIR = Path(os.getenv("LOG_DIR", str(BASE_DIR / "logs")))

# Ensure directories exist
for directory in [
    DATA_DIR,
    RAW_CTI_DIR,
    RAW_CVE_DIR,
    NORMALIZED_CTI_DIR,
    NORMALIZED_CVE_DIR,
    NORMALIZED_EXTRACTED_DIR,
    NORMALIZED_REJECTED_DIR,
    LOG_DIR,
]:
    directory.mkdir(parents=True, exist_ok=True)

# ==============================================================================
# Phase 3: Trust Scoring & Temporal Verification (Professor's Formula)
# Trust(h,r,t) = α×LLM_confidence + β×source_reliability + γ×ATT&CK_similarity
#              + δ×cross_source_support + ε×temporal_consistency - λ×contradiction_penalty
# ==============================================================================

# ADJUSTED v2 — still experimental, not validated research values.
# Rationale: reduced ATT&CK weight to avoid penalizing IOC-heavy MISP dataset.
# Increased cross-source support weight as multi-source corroboration is strongest 
# signal in this dataset. Requires proper ablation study for final values.
TRUST_ALPHA = float(os.getenv("TRUST_ALPHA", "0.25"))
# ADJUSTED v2 — still experimental, not validated research values.
# Rationale: reduced ATT&CK weight to avoid penalizing IOC-heavy MISP dataset.
# Increased cross-source support weight as multi-source corroboration is strongest 
# signal in this dataset. Requires proper ablation study for final values.
TRUST_BETA = float(os.getenv("TRUST_BETA", "0.20"))
# ADJUSTED v2 — still experimental, not validated research values.
# Rationale: reduced ATT&CK weight to avoid penalizing IOC-heavy MISP dataset.
# Increased cross-source support weight as multi-source corroboration is strongest 
# signal in this dataset. Requires proper ablation study for final values.
TRUST_GAMMA = float(os.getenv("TRUST_GAMMA", "0.15"))
# ADJUSTED v2 — still experimental, not validated research values.
# Rationale: reduced ATT&CK weight to avoid penalizing IOC-heavy MISP dataset.
# Increased cross-source support weight as multi-source corroboration is strongest 
# signal in this dataset. Requires proper ablation study for final values.
TRUST_DELTA = float(os.getenv("TRUST_DELTA", "0.25"))
# ADJUSTED v2 — still experimental, not validated research values.
# Rationale: reduced ATT&CK weight to avoid penalizing IOC-heavy MISP dataset.
# Increased cross-source support weight as multi-source corroboration is strongest 
# signal in this dataset. Requires proper ablation study for final values.
TRUST_EPSILON = float(os.getenv("TRUST_EPSILON", "0.15"))
# ADJUSTED v2 — still experimental, not validated research values.
# Rationale: reduced ATT&CK weight to avoid penalizing IOC-heavy MISP dataset.
# Increased cross-source support weight as multi-source corroboration is strongest 
# signal in this dataset. Requires proper ablation study for final values.
TRUST_LAMBDA = float(os.getenv("TRUST_LAMBDA", "0.05"))

# Trust threshold from professor's specification
TRUST_THRESHOLD = float(os.getenv("TRUST_THRESHOLD", "0.80"))

# Source reliability lookup table (PLACEHOLDER — requires real expert curation, defaults are illustrative)
SOURCE_RELIABILITY = {
    "CTI_REPORT": 0.80,   # narrative ReportEvent titles
    "MISP_IOC": 0.65,     # deterministic MISP IOC (reliable but lower context)
    "CVE": 0.90,          # CVE records (authoritative structured source)
    "UNKNOWN": 0.50       # fallback
}

# ATT&CK Excel Dataset path
ATTCK_XLSX_PATH = Path(os.getenv("ATTCK_XLSX_PATH", str(BASE_DIR.parent.parent / "DATASETS" / "attackmitre.xlsx")))

# ==============================================================================
# Phase 4: Entity Alignment & Canonicalization
# ==============================================================================
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-mpnet-base-v2")
EMBEDDING_DIM = int(os.getenv("EMBEDDING_DIM", "768"))
# Default 0.85 — higher than CTINexus's 0.6 because we want to avoid 
# false merges. Tunable — lower to 0.75 for more aggressive 
# alignment, raise to 0.90 for conservative. Requires manual review of 
# borderline cases.
ALIGNMENT_SIMILARITY_THRESHOLD = float(os.getenv("ALIGNMENT_SIMILARITY_THRESHOLD", "0.85"))

# Manually defined alias table (extend with domain knowledge)
ENTITY_ALIASES = {
    "fancy bear": "APT28",
    "sofacy": "APT28", 
    "cozy bear": "APT29",
    "lazarus group": "Lazarus",
    "ocean lotus": "OceanLotus",
    "oceanlotus": "OceanLotus",
}

ALIGNMENT_DATA_DIR = BASE_DIR / "data" / "alignment"
ALIGNMENT_DATA_DIR.mkdir(parents=True, exist_ok=True)

# ==============================================================================
# Phase 5: Temporal-Causal GraphRAG Reasoning
# ==============================================================================
TOP_K_RETRIEVAL = int(os.getenv("TOP_K_RETRIEVAL", "20"))
MAX_CONTEXT_TOKENS = int(os.getenv("MAX_CONTEXT_TOKENS", "4096"))
GRAPH_TRAVERSAL_DEPTH = int(os.getenv("GRAPH_TRAVERSAL_DEPTH", "4"))

FAISS_DIR = BASE_DIR / "data" / "faiss"
FAISS_DIR.mkdir(parents=True, exist_ok=True)
FAISS_INDEX_PATH = Path(os.getenv("FAISS_INDEX_PATH", str(FAISS_DIR / "entity_index.faiss")))
FAISS_METADATA_PATH = Path(os.getenv("FAISS_METADATA_PATH", str(FAISS_DIR / "entity_metadata.jsonl")))

