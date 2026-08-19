import json
import re
import time
from typing import Any, Dict, Optional, Tuple
import requests
from config.settings import OLLAMA_HOST, OLLAMA_MODEL
from common.logging_utils import setup_logger

logger = setup_logger("llm_client", "llm_client.log")


def strip_think_tags(text: str) -> str:
    """
    Strips everything enclosed in <think>...</think> tags.
    Handles multiline content and trailing/unclosed think blocks if present.
    """
    if not text:
        return ""
    # Remove closed <think>...</think> blocks (case-insensitive, dot matches newline)
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
    # If there's an unclosed <think> tag, strip everything from <think> to end
    cleaned = re.sub(r"<think>.*$", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
    return cleaned.strip()


def _clean_json_candidate(s: str) -> str:
    # Convert unquoted ranges like : 0.5-0.6 or : 0.7 - 0.8 into midpoint floats
    def _replace_range(m):
        try:
            low = float(m.group(1))
            high = float(m.group(2))
            mid = round((low + high) / 2.0, 2)
            return f": {mid}"
        except ValueError:
            return m.group(0)

    s = re.sub(r':\s*([0-9\.]+)\s*[-–]\s*([0-9\.]+)', _replace_range, s)
    # Fix ' " confidence: 0.85" ' -> ' "confidence": 0.85 '
    s = re.sub(r'\"\s*([a-zA-Z_]+)\s*:\s*([0-9\.]+)\s*\"', r'"\1": \2', s)
    # Fix missing commas between properties on adjacent lines
    s = re.sub(r'(\"|[0-9\.]+|null|true|false)\s*\n\s*(\"[a-zA-Z_]+\"\s*:)', r'\1,\n\2', s)
    # Remove trailing commas before } or ]
    s = re.sub(r",\s*([\}\]])", r"\1", s)
    return s.strip()


def extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    """
    Extracts and parses a JSON object from text that may contain markdown fences,
    surrounding noise, or minor JSON syntax imperfections (like trailing commas).
    """
    cleaned = strip_think_tags(text)
    if not cleaned:
        return None

    # Try direct parse
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Try extracting markdown json code block ```json ... ``` or ``` ... ```
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL | re.IGNORECASE)
    if match:
        raw_snippet = match.group(1)
        try:
            parsed = json.loads(raw_snippet)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            try:
                parsed = json.loads(_clean_json_candidate(raw_snippet))
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

    # Try finding the outermost balanced { ... }
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        json_candidate = cleaned[first_brace : last_brace + 1]
        try:
            parsed = json.loads(json_candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            try:
                parsed = json.loads(_clean_json_candidate(json_candidate))
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

    return None


class OllamaClient:
    """Client for interacting with local Ollama instance with retry and think-tag stripping."""

    def __init__(self, host: str = OLLAMA_HOST, model: str = OLLAMA_MODEL, timeout: int = 60):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout

    def generate_chat_completion(
        self,
        messages: list,
        temperature: float = 0.0,
    ) -> str:
        """Calls the /api/chat endpoint of Ollama."""
        url = f"{self.host}/api/chat"
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }
        response = requests.post(url, json=payload, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        return data.get("message", {}).get("content", "")

    def extract_structured_json(
        self,
        system_prompt: str,
        user_prompt: str,
        context_id: str = "unknown",
        max_attempts: int = 2,
    ) -> Tuple[Optional[Dict[str, Any]], str]:
        """
        Sends prompt to Ollama, strips think tags, and attempts to parse JSON.
        If initial parse fails, re-prompts once with a correction message.
        Logs latency, context_id, and success/failure.
        Returns (parsed_dict, raw_response_text).
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        attempt = 1
        raw_response = ""
        start_total_time = time.time()

        while attempt <= max_attempts:
            start_time = time.time()
            try:
                raw_response = self.generate_chat_completion(messages)
                latency = time.time() - start_time
                parsed_json = extract_json_object(raw_response)

                if parsed_json is not None:
                    total_latency = time.time() - start_total_time
                    logger.info(
                        f"Context: {context_id} | Attempt {attempt}/{max_attempts} | "
                        f"Success: True | Latency: {total_latency:.2f}s"
                    )
                    return parsed_json, raw_response

                logger.warning(
                    f"Context: {context_id} | Attempt {attempt}/{max_attempts} | "
                    f"JSON parse failed | Raw output: {raw_response[:150]}..."
                )

                if attempt < max_attempts:
                    # Retry with repair prompt
                    messages.append({"role": "assistant", "content": raw_response})
                    messages.append({
                        "role": "user",
                        "content": "Your previous output was not valid JSON. Return ONLY the JSON object, no other text.",
                    })

            except Exception as exc:
                latency = time.time() - start_time
                logger.error(
                    f"Context: {context_id} | Attempt {attempt}/{max_attempts} | "
                    f"Error: {exc} | Latency: {latency:.2f}s"
                )

            attempt += 1

        total_latency = time.time() - start_total_time
        logger.error(
            f"Context: {context_id} | Extraction failed after {max_attempts} attempts | Total Latency: {total_latency:.2f}s"
        )
        return None, raw_response
