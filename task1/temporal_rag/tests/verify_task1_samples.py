import json
from pathlib import Path
from tasks.task1_extraction import process_cti_event, process_cve_record
from common.llm_client import OllamaClient

events_to_test = [
    (1976, "Chafer / Remexi (Target Event)"),
    (10, "Hash-only Negative Control"),
    (2022, "DarkHydrus Google Drive Trojan"),
    (1008, "URSNIF, EMOTET, DRIDEX Loader"),
    (1033, "VERMIN Quasar RAT Ukraine"),
    (1298, "Gh0st RAT Variant"),
]

client = OllamaClient()
all_confidences = []

print("=" * 80)
print("TASK 1 COMPREHENSIVE VERIFICATION & CONFIDENCE DISTRIBUTION")
print("=" * 80)

for eid, desc in events_to_test:
    print(f"\n--- Testing Event {eid} ({desc}) ---")
    res = process_cti_event(eid, llm_client=client)
    if res:
        out_file = Path(f"data/normalized/extracted/{eid}.json")
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        print(f"Entities Count: {len(data['entities'])}")
        print(f"Relations Count: {len(data['relations'])}")
        
        # Collect confidences
        for e in data["entities"]:
            all_confidences.append(("Entity", e["type"], e["text"][:30], e["confidence"]))
        for r in data["relations"]:
            all_confidences.append(("Relation", r["relation"], f"{r['head'][:20]}->{r['tail'][:20]}", r["confidence"]))
            
        print("Sample Entities:")
        for e in data["entities"][:4]:
            print(f"  [{e['type']}] {e['text'][:35]} | canonical: {e.get('canonical_name')} | conf: {e['confidence']}")
        print("Sample Relations:")
        for r in data["relations"][:4]:
            print(f"  ({r['head'][:25]}) -[{r['relation']}]-> ({r['tail'][:25]}) | time: {r.get('time')} | conf: {r['confidence']}")

print("\n--- Testing CVE-2026-74234 ---")
cve_res = process_cve_record("CVE-2026-74234")
if cve_res:
    with open("data/normalized/extracted/CVE-2026-74234.json", "r", encoding="utf-8") as f:
        cve_data = json.load(f)
    print("CVE Entities:")
    for e in cve_data["entities"]:
        print(f"  [{e['type']}] {e['text']} | conf: {e['confidence']}")
    print("CVE Relations:")
    for r in cve_data["relations"]:
        print(f"  ({r['head']}) -[{r['relation']}]-> ({r['tail']}) | time: {r['time']} | conf: {r['confidence']}")

print("\n" + "=" * 80)
print("OBSERVED CONFIDENCE DISTRIBUTION SUMMARY")
print("=" * 80)
conf_values = [c[3] for c in all_confidences]
print(f"Total Triples & Entities Inspected: {len(conf_values)}")
print(f"Deterministic (conf=1.0) count: {sum(1 for c in conf_values if c == 1.0)}")
llm_confs = [c for c in conf_values if c < 1.0]
print(f"LLM Varied Confidence count (< 1.0): {len(llm_confs)}")
if llm_confs:
    print(f"LLM Range: min={min(llm_confs):.2f}, max={max(llm_confs):.2f}, avg={sum(llm_confs)/len(llm_confs):.2f}")
    from collections import Counter
    rounded_confs = Counter(round(c, 2) for c in llm_confs)
    print("LLM Confidence Histogram:")
    for score, count in sorted(rounded_confs.items(), reverse=True):
        print(f"  Score {score:.2f}: {count} occurrences")
