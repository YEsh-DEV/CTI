import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.llm_client import OllamaClient, strip_think_tags
from schemas.normalized import NormalizedCTIEvent

PROMPT_WITHOUT_NUMERIC_ANCHORS = """You are a cybersecurity threat intelligence analyst.
Extract CTI knowledge from the given report text.
Return ONLY valid JSON with root keys "entities" and "relations".

Instructions:
- Only extract entities and relations explicitly present in the input text.
- If no entities or relations are present, return: {"entities": [], "relations": []}.
- For confidence, assign a realistic calibration score between 0.0 and 1.0 reflecting your genuine certainty (e.g. 0.95 for explicitly named actors/malware, 0.7-0.8 for inferred/generic terms, 0.5-0.6 for ambiguous terms). Do NOT default to 1.0.

Entity types: ThreatActor, Malware, Tool, Vulnerability, AttackTactic, AttackTechnique, Target.

Expected JSON output format schema:
{
  "entities": [
    {"text": "<verbatim text>", "type": "<entity type>", "canonical_name": "<standard name>", "confidence": <float between 0.0 and 1.0>}
  ],
  "relations": [
    {
      "head": "<head entity>",
      "relation": "<uses | exploits | targets | drops | communicates_with | delivers | spies_on>",
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

def inspect_raw_llm_outputs():
    client = OllamaClient()
    
    # 10 real events with narrative titles from 2018/2019 CTI reports
    sample_narrative_titles = [
        "Chafer used Remexi malware to spy on Iran-based foreign diplomatic entities.pdf",
        "DarkHydrus delivers new Trojan that can use Google Drive for C2 communications.pdf",
        "In May 2018, Patchwork targeted government institutions in Southeast Asia using PowerShell scripts and CVE-2017-11882.",
        "MuddyWater expands operations against Middle East government targets using POWERSTATS malware.",
        "Lazarus Group deployed BADCALL and HARDRAIN malware targeting aerospace sectors in South Korea.",
        "OceanLotus used customized Cobalt Strike beacons and Steganography in Southeast Asian attacks.",
        "APT28 targeted European military organizations exploiting CVE-2017-0199 with Sentry Trojan.",
        "Turla APT utilized Snake rootkit and Carbon framework for cyber espionage in 2018.",
        "Gamaredon Group targeted Ukrainian infrastructure using Pterodo backdoor scripts.",
        "Sandworm deployed Olympic Destroyer malware against winter games infrastructure.",
    ]

    print("=" * 80)
    print("INSPECTING RAW MODEL OUTPUTS ON 10 REAL NARRATIVE CTI TITLES")
    print("=" * 80)

    for i, title in enumerate(sample_narrative_titles, 1):
        print(f"\n[{i}/10] Input: \"{title}\"")
        prompt = PROMPT_WITHOUT_NUMERIC_ANCHORS.replace("{cti_report_chunk}", title)
        
        # Raw call to Ollama chat
        messages = [
            {"role": "system", "content": "You are an expert Cyber Threat Intelligence analyst. Return ONLY valid JSON."},
            {"role": "user", "content": prompt}
        ]
        
        raw_output = client.generate_chat_completion(messages)
        cleaned = strip_think_tags(raw_output)
        
        print("\n--- RAW MODEL OUTPUT (after think-tag strip) ---")
        print(cleaned)
        print("-" * 80)

if __name__ == "__main__":
    inspect_raw_llm_outputs()
