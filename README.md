# CTI-TTP: Temporal Knowledge Graph & Threat Intelligence RAG System

A research-grade Cyber Threat Intelligence (CTI) platform implementing an end-to-end pipeline from heterogeneous threat reports and vulnerability feeds into a unified **Temporal Knowledge Graph** with **Trust Scoring** and **Temporal RAG Reasoning**.

---

## Architecture Overview

```
 ┌────────────────┐      ┌────────────────┐
 │ MISP XML Feeds │      │  CVE JSON Feeds│
 └────────┬───────┘      └────────┬───────┘
          │                       │
          ▼                       ▼
 ┌────────────────────────────────────────┐
 │   Ingestion & Composite Key Normalizer │
 └───────────────────┬────────────────────┘
                     │
                     ▼
 ┌────────────────────────────────────────┐
 │ Task 1: Unified Extraction Engine      │
 │  - Local LLM Narrative Extraction     │
 │  - Deterministic IOC Facts             │
 └───────────────────┬────────────────────┘
                     │
                     ▼
 ┌────────────────────────────────────────┐
 │ Task 2: Temporal Graph Builder (Neo4j) │
 │  - UNWIND High-Throughput Batch Ingest │
 │  - ISO-8601 Temporal (Tau) Normalizer  │
 └───────────────────┬────────────────────┘
                     │
                     ▼
 ┌────────────────────────────────────────┐
 │ Task 3: Trust & Temporal Verification  │
 │  - 6-Factor Trust Formula              │
 │  - MITRE ATT&CK Taxonomy Matching      │
 │  - Temporal Contradiction Detection    │
 └────────────────────────────────────────┘
```

---

## Project Structure

```
CTI-TTP/
├── DATASETS/
│   ├── attackmitre.xlsx           # MITRE ATT&CK reference taxonomy
│   └── model_evaluation_table.csv # Extraction model performance table
├── DOCS/                          # Specification and architectural docs
├── task1/
│   └── temporal_rag/
│       ├── common/                # LLM (Ollama) & Neo4j driver wrappers
│       ├── config/                # Environment and trust formula weights
│       ├── ingestion/             # MISP XML and CVE JSON parsers
│       ├── reference_data/        # ATT&CK loader & fuzzy matcher
│       ├── schemas/               # Pydantic data schemas
│       ├── tasks/                 # Task 1, Task 2, and Task 3 pipelines
│       └── tests/                 # Unit & integration test suites
├── task2/                         # Task 2 documentation and scripts
├── task3/                         # Task 3 documentation and scripts
├── task4/                         # Task 4 alignment and canonicalization
└── README.md
```

---

## Quickstart & Execution

### 1. Environment Setup
```powershell
# Install requirements
pip install -r requirements.txt

# Configure environment variables (.env)
cp task1/temporal_rag/.env.example task1/temporal_rag/.env
```

### 2. Run All Tests
```powershell
cd task1/temporal_rag
python -m unittest discover -s tests -p "test_*.py" -v
```

### 3. Pipeline Execution
```powershell
# Task 1: Extract entities and relations
python -m tasks.task1_extraction --all

# Task 2: Ingest into Neo4j Temporal Graph
python -m tasks.task2_temporal_graph --setup-schema
python -m tasks.task2_temporal_graph --all --batch-size 250
python -m tasks.task2_temporal_graph --verify

# Task 3: Trust Scoring & Temporal Verification
python -m tasks.task3_trust --all --batch-size 1000
python -m tasks.task3_trust --verify
```
