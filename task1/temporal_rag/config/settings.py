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

# PLACEHOLDER — requires calibration/experimentation. Default equal weighting only.
TRUST_ALPHA = float(os.getenv("TRUST_ALPHA", "0.20"))
# PLACEHOLDER — requires calibration/experimentation. Default equal weighting only.
TRUST_BETA = float(os.getenv("TRUST_BETA", "0.20"))
# PLACEHOLDER — requires calibration/experimentation. Default equal weighting only.
TRUST_GAMMA = float(os.getenv("TRUST_GAMMA", "0.20"))
# PLACEHOLDER — requires calibration/experimentation. Default equal weighting only.
TRUST_DELTA = float(os.getenv("TRUST_DELTA", "0.20"))
# PLACEHOLDER — requires calibration/experimentation. Default equal weighting only.
TRUST_EPSILON = float(os.getenv("TRUST_EPSILON", "0.20"))
# PLACEHOLDER — requires calibration/experimentation. Default equal weighting only.
TRUST_LAMBDA = float(os.getenv("TRUST_LAMBDA", "0.10"))

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

