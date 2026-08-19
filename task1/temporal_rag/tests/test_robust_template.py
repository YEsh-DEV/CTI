import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.llm_client import OllamaClient
from common.logging_utils import setup_logger

ROBUST_PROMPT_TEMPLATE = """You are a cybersecurity threat intelligence analyst.
Extract CTI knowledge from the given report chunk.
Return ONLY valid JSON with root keys "entities" and "relations".

Instructions:
- Only extract entities and relations that are EXPLICITLY stated in the input text.
- If an entity or relation is not in the input text, DO NOT include it.
- If the input text is a hash, filename, or contains no actionable threat entities, return empty lists: {"entities": [], "relations": []}.
- Do NOT hallucinate or copy entities from instructions.

Entity types to recognize: ThreatActor, Malware, Tool, Vulnerability, AttackTactic, AttackTechnique, Target.

Expected JSON output format schema:
{
  "entities": [
    {"text": "Extracted text verbatim", "type": "ThreatActor | Malware | Tool | Vulnerability | AttackTactic | AttackTechnique | Target", "canonical_name": "Standard name", "confidence": 0.0 to 1.0}
  ],
  "relations": [
    {
      "head": "Head entity name",
      "relation": "uses | exploits | targets | drops | communicates_with",
      "tail": "Tail entity name",
      "time": "Date or time expression if mentioned, else null",
      "evidence": "Verbatim sentence from input",
      "confidence": 0.0 to 1.0
    }
  ]
}

Input CTI text:
{cti_report_chunk}
"""

TEST_CASES = [
    {
        "name": "Patchwork Report",
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

def run_robust_tests():
    client = OllamaClient()
    print("=" * 70)
    print("RUNNING REFINED PROFESSOR TEMPLATE (ANTI-LEAKING / STRICT SCHEMA)")
    print("=" * 70)

    for i, tc in enumerate(TEST_CASES, 1):
        print(f"\n--- Test Case {i}: {tc['name']} ---")
        print(f"Input Text: \"{tc['text']}\"")
        
        user_prompt = ROBUST_PROMPT_TEMPLATE.replace("{cti_report_chunk}", tc["text"])
        
        parsed_json, raw = client.extract_structured_json(
            system_prompt="You are a strict cybersecurity threat intelligence analyst. Output ONLY valid JSON matching the requested schema. Never invent entities.",
            user_prompt=user_prompt,
            context_id=f"robust_test_{i}",
        )
        
        print("Extracted Output:")
        if parsed_json:
            print(json.dumps(parsed_json, indent=2))
        else:
            print(f"Raw output:\n{raw}")

if __name__ == "__main__":
    run_robust_tests()
