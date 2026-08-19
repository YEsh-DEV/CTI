import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.llm_client import OllamaClient
from common.logging_utils import setup_logger

logger = setup_logger("test_prof_template", "test_prof_template.log")

PROMPT_TEMPLATE = """You are a cybersecurity threat intelligence analyst.
Extract CTI knowledge from the given report.
Return only valid JSON.

Extract:
1. Threat actors
2. Malware
3. Tools
4. Vulnerabilities
5. ATT&CK tactics
6. ATT&CK techniques
7. Targets
8. Temporal expressions
9. Entity-relation triples
10. Evidence sentence for each triple
11. Confidence score from 0 to 1

Input CTI text:
{cti_report_chunk}

Expected JSON output format:
{{
  "entities": [
    {{"text": "Patchwork", "type": "ThreatActor", "canonical_name": "Patchwork APT", "confidence": 0.94}},
    {{"text": "PowerShell", "type": "Tool", "canonical_name": "PowerShell", "confidence": 0.91}},
    {{"text": "CVE-2017-11882", "type": "Vulnerability", "canonical_name": "CVE-2017-11882", "confidence": 0.96}}
  ],
  "relations": [
    {{
      "head": "Patchwork",
      "relation": "uses",
      "tail": "PowerShell",
      "time": "unknown",
      "evidence": "PowerShell is a common tool for Patchwork.",
      "confidence": 0.89
    }},
    {{
      "head": "Patchwork",
      "relation": "exploits",
      "tail": "CVE-2017-11882",
      "time": "unknown",
      "evidence": "Patchwork typically uses CVE-2017-11882...",
      "confidence": 0.91
    }}
  ]
}}
"""

TEST_CASES = [
    {
        "name": "Patchwork Multi-Entity Report",
        "text": "In May 2018, Patchwork targeted government institutions in Southeast Asia. Patchwork used PowerShell scripts and exploited CVE-2017-11882 to deliver QuasarRAT malware.",
    },
    {
        "name": "Chafer Remexi Incident",
        "text": "In November 2018, Chafer used Remexi malware to spy on Iran-based foreign diplomatic entities.",
    },
    {
        "name": "DarkHydrus Google Drive Campaign",
        "text": "DarkHydrus delivered a new Trojan that utilized Google Drive for command and control (C2) communication in 2019.",
    },
    {
        "name": "Generic Hash (Negative Control)",
        "text": "cdce8791df7c971cb4e609b27a2b5f8f",
    }
]

def run_tests():
    client = OllamaClient()
    results = []

    print("=" * 70)
    print("TESTING PROFESSOR PROMPT TEMPLATE ON CTI DATASETS WITH OLLAMA (deepseek-r1:1.5b)")
    print("=" * 70)

    for i, tc in enumerate(TEST_CASES, 1):
        print(f"\n--- Test Case {i}: {tc['name']} ---")
        print(f"Input Text:\n  \"{tc['text']}\"")
        
        user_prompt = PROMPT_TEMPLATE.replace("{cti_report_chunk}", tc["text"])
        
        parsed_json, raw = client.extract_structured_json(
            system_prompt="You are an expert Cyber Threat Intelligence analyst. Extract structured entities and relations. Return ONLY valid JSON matching the requested schema.",
            user_prompt=user_prompt,
            context_id=f"test_{i}",
        )
        
        print("\nExtracted Output:")
        if parsed_json:
            print(json.dumps(parsed_json, indent=2))
        else:
            print(f"Failed to parse JSON. Raw output:\n{raw}")
            
        results.append({
            "test_case": tc["name"],
            "input": tc["text"],
            "parsed_output": parsed_json,
            "success": parsed_json is not None
        })

    return results

if __name__ == "__main__":
    run_tests()
