"""Anthropic API wrapper: one place where Claude is invoked.

Hallucination control contract:
- Agents receive findings as structured JSON with stable ids.
- Agents must respond with JSON keyed by those ids.
- The orchestrator discards any id or field not present in the input.
"""

import json
import os
import re
from typing import Protocol

DEFAULT_MODEL = "claude-sonnet-4-5"


class LlmClient(Protocol):
    def complete(self, system: str, user: str, max_tokens: int) -> str: ...


class AnthropicClient:
    def __init__(self, api_key: str | None = None, model: str | None = None):
        import anthropic

        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Set it in your environment, or run "
                "with --no-ai to generate a tooling-only report."
            )
        self.model = model or os.environ.get("TRUSTCHAIN_MODEL", DEFAULT_MODEL)
        self._client = anthropic.Anthropic(api_key=self.api_key)

    def complete(self, system: str, user: str, max_tokens: int = 4096) -> str:
        response = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(block.text for block in response.content if block.type == "text")


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
