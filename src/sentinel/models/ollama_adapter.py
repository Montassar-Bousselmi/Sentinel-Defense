"""Ollama model adapter for locally hosted chat models."""

from __future__ import annotations

import json
from typing import Any

import httpx

from sentinel.agent.base import AgentContext, Feedback
from sentinel.core.actions import CandidateAction
from sentinel.models.base import ModelAdapter, ModelError, TurnHints
from sentinel.models.hf_adapter import SYSTEM_PROMPT, parse_action, tool_card


class OllamaModelAdapter(ModelAdapter):
    """Run a model served by a local Ollama daemon."""

    name = "ollama"

    def __init__(
        self,
        model: str,
        base_url: str = "http://127.0.0.1:11434",
        timeout_s: float = 120.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not model:
            raise ModelError("Ollama model name must not be empty")
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self._client = client
        self._goal = ""
        self._tools: list[dict[str, Any]] = []

    def start_turn(self, goal: str, hints: TurnHints) -> None:
        self._goal = goal
        self._tools = hints.tools

    def _messages(self, context: AgentContext) -> list[dict[str, str]]:
        history = "\n".join(f"[{obs.kind}] {obs.text}" for obs in context.observations)
        tools = json.dumps([tool_card(tool) for tool in self._tools])
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"Tools: {tools}\nGoal: {self._goal}\nHistory:\n{history[-12_000:]}",
            },
        ]

    def propose(self, context: AgentContext) -> CandidateAction:
        payload = {
            "model": self._model,
            "messages": self._messages(context),
            "stream": False,
            "think": False,
            "options": {"temperature": 0},
        }
        owns_client = self._client is None
        client = self._client or httpx.Client(timeout=self._timeout_s)
        try:
            try:
                response = client.post(f"{self._base_url}/api/chat", json=payload)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                raise ModelError(f"Ollama request failed for {self._model!r}: {exc}") from exc
            try:
                body = response.json()
                content = body["message"]["content"]
            except (ValueError, KeyError, TypeError) as exc:
                raise ModelError("Ollama response did not contain message.content") from exc
            return parse_action(content)
        finally:
            if owns_client:
                client.close()

    def observe(self, feedback: Feedback) -> None:
        # The full conversation is rebuilt from AgentContext on every proposal.
        return None
