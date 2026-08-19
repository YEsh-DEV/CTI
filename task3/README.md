# Task 3: Trust Scoring & Temporal Verification

Phase 3 is fully implemented and operational under the `temporal_rag` package.

### Key Components:
- **Trust Scoring Engine & CLI**: `y:/Reserchintern/CTI-TTP/task1/temporal_rag/tasks/task3_trust.py`
- **ATT&CK Reference Loader**: `y:/Reserchintern/CTI-TTP/task1/temporal_rag/reference_data/attck_loader.py`
- **Unit & Integration Tests**: `y:/Reserchintern/CTI-TTP/task1/temporal_rag/tests/test_task3.py`
- **Configuration & Weights**: `y:/Reserchintern/CTI-TTP/task1/temporal_rag/config/settings.py`

### CLI Usage (Run from `task1/temporal_rag`):
```powershell
# 1. Run unit tests
python -m unittest tests/test_task3.py -v

# 2. Run sample test (100 relationships)
python -m tasks.task3_trust --sample 100

# 3. Score all relationships in the graph
python -m tasks.task3_trust --all --batch-size 1000

# 4. Verify graph trust distribution
python -m tasks.task3_trust --verify
```
