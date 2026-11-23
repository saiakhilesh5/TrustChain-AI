"""Gemini API wrapper with multi-key rotation.

Hallucination control contract (unchanged from the agent layer):
- Agents receive findings as structured JSON with stable ids.
- Agents must respond with JSON keyed by those ids.
- The orchestrator discards any id or field not present in the input.

Key rotation: up to N keys are loaded from the environment (GEMINI_API_KEY_1
.. GEMINI_API_KEY_N, or a single GEMINI_API_KEY). Requests start from the
least-recently-failed key; on HTTP 429 the client rotates to the next key and
retries. If every key is rate limited in one call, the call fails so callers
can fall back to tools-only output.
"""

import json
import os
import re
import time
from typing import Protocol

import requests

DEFAULT_MODELS = ["gemini-3.8-flash", "gemini-3.5-flash", "gemini-2.5-flash"]
API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

RATE_LIMIT_STATUS = 429
UNAVAILABLE_STATUS = 503  # model overloaded — retry on another key
RETRYABLE_STATUSES = (RATE_LIMIT_STATUS, UNAVAILABLE_STATUS)
MODEL_UNAVAILABLE_STATUS = 404


class LlmClient(Protocol):
    def complete(self, system: str, user: str, max_tokens: int) -> str: ...


def _load_keys() -> list[str]:
    keys = []
    for index in range(1, 17):
        key = os.environ.get(f"GEMINI_API_KEY_{index}", "").strip()
        if key:
            keys.append(key)
    single = os.environ.get("GEMINI_API_KEY", "").strip()
    if single and single not in keys:
        keys.append(single)
    return [key for key in keys if not key.startswith("your-")]


class GeminiClient:
    """REST client for the Gemini API that rotates through multiple keys."""

    def __init__(self, keys: list[str] | None = None, model: str | None = None):
        self._keys = [key for key in (keys if keys is not None else _load_keys()) if key]
        if not self._keys:
            raise RuntimeError(
                "No Gemini API keys found. Fill in GEMINI_API_KEY_1..N in .env, or run "
                "with --no-ai to generate a tooling-only report."
            )
        self.model = model or os.environ.get("TRUSTCHAIN_MODEL", DEFAULT_MODELS[0])
        self._models = list(dict.fromkeys([self.model] + DEFAULT_MODELS))
        self._next_key = 0
        self.key_status = {index: "ok" for index in range(len(self._keys))}

    @property
    def key_count(self) -> int:
        return len(self._keys)

    def complete(self, system: str, user: str, max_tokens: int = 4096) -> str:
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.2},
        }
        last_error = None
        for model in self._models:
            for _ in range(len(self._keys)):
                index = self._next_key
                self._next_key = (self._next_key + 1) % len(self._keys)
                try:
                    text = self._request(model, self._keys[index], payload)
                    self.model = model
                    return text
                except _ModelUnavailable:
                    break  # this model is retired/hidden — try the next model
                except _RateLimited as error:
                    self.key_status[index] = "rate-limited"
                    last_error = error
                    time.sleep(1)
                except requests.RequestException as error:
                    # timeout / connection error — try the next key
                    self.key_status[index] = "network-error"
                    last_error = error
                    time.sleep(1)
        raise RuntimeError(
            f"all {len(self._keys)} Gemini API keys failed on models "
            f"{', '.join(self._models)}; retry later or run with --no-ai for a "
            "tools-only report"
        ) from last_error

    def _request(self, model: str, api_key: str, payload: dict) -> str:
        response = requests.post(
            f"{API_BASE}/{model}:generateContent",
            params={"key": api_key},
            json=payload,
            timeout=120,
        )
        if response.status_code in RETRYABLE_STATUSES:
            raise _RateLimited(response.text[:200])
        if response.status_code == MODEL_UNAVAILABLE_STATUS:
            raise _ModelUnavailable(response.text[:200])
        if response.status_code != 200:
            raise RuntimeError(f"Gemini API error {response.status_code}: {response.text[:200]}")
        body = response.json()
        parts = body.get("candidates", [{}])[0].get("content", {}).get("parts", [])
        text = "".join(part.get("text", "") for part in parts)
        if not text:
            raise RuntimeError("Gemini returned an empty response")
        return text


class _RateLimited(Exception):
    pass


class _ModelUnavailable(Exception):
    pass


class OfflineClient:
    """Deterministic stand-in used with --no-ai: no inference, only facts."""

    def complete(self, system: str, user: str, max_tokens: int = 4096) -> str:
        return "{}"


def extract_json(text: str) -> dict:
    """Extract the first JSON object from a model response."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match is None:
        raise ValueError("no JSON object found in model response")
    return json.loads(match.group(0))
