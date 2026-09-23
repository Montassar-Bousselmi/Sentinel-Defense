import json

import httpx
import pytest

from sentinel.agent.base import AgentContext
from sentinel.models.base import ModelError, TurnHints
from sentinel.models.ollama_adapter import OllamaModelAdapter


def _context() -> AgentContext:
    return AgentContext(goal="Read the ticket.", turn_index=0, step_id=0, observations=[], provenance={}, tools=[])


def test_ollama_adapter_posts_chat_request_and_parses_action() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"message": {"content": '{"type":"respond","content":"done","final":true}'}},
            request=request,
        )

    adapter = OllamaModelAdapter("qwen3:8b", client=httpx.Client(transport=httpx.MockTransport(handler)))
    adapter.start_turn("Read the ticket.", TurnHints())
    action = adapter.propose(_context())

    assert action.content == "done"
    assert requests[0].url.path == "/api/chat"
    assert json.loads(requests[0].content)["model"] == "qwen3:8b"


def test_ollama_adapter_reports_connection_errors() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(503, request=request))
    adapter = OllamaModelAdapter("qwen3:8b", client=httpx.Client(transport=transport))
    adapter.start_turn("Read the ticket.", TurnHints())

    with pytest.raises(ModelError, match="Ollama request failed"):
        adapter.propose(_context())
