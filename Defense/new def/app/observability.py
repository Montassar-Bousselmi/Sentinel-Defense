"""Bounded, privacy-preserving SENTINEL decision trace."""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.decision import action_digest
from app.models import DefenseDecision, DefenseRequest


@dataclass(frozen=True)
class TraceEvent:
    timestamp: float
    run_id: str
    step_id: int
    action_digest: str
    action_type: str
    tool: str | None
    decision: str
    risk_score: float
    confidence: float
    reason_codes: tuple[str, ...]
    explanation: str | None
    outcome: str
    metadata: dict[str, Any]


class TraceStore:
    def __init__(self, max_events: int = 2048, path: str | None = None, max_file_bytes: int = 50_000_000) -> None:
        self._events: deque[TraceEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self.path = Path(path) if path else None
        self.max_file_bytes = max_file_bytes
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self) -> None:
        # The append-only trace file previously had no retention policy and
        # would grow without bound for the life of the process. This keeps at
        # most one prior generation on disk (path.1) rather than implementing
        # full log management, which is enough to stop unbounded disk growth
        # without adding an external dependency.
        if not self.path or not self.path.exists():
            return
        if self.path.stat().st_size < self.max_file_bytes:
            return
        rotated = self.path.with_suffix(self.path.suffix + ".1")
        self.path.replace(rotated)

    def record(self, request: DefenseRequest, decision: DefenseDecision) -> TraceEvent:
        event = TraceEvent(
            timestamp=time.time(),
            run_id=request.run_id,
            step_id=request.step_id,
            action_digest=action_digest(request.candidate_action.confirmation_for or request.candidate_action),
            action_type=request.candidate_action.type,
            tool=(request.candidate_action.confirmation_for or request.candidate_action).tool,
            decision=decision.decision,
            risk_score=decision.risk_score,
            confidence=decision.confidence,
            reason_codes=tuple(decision.reason_codes),
            explanation=decision.explanation,
            outcome={
                "allow": "proceeds",
                "block": "stopped",
                "escalate": "human_confirmation_required",
                "rewrite": "safer_action_substituted",
            }[decision.decision],
            metadata=decision.metadata,
        )
        with self._lock:
            self._events.append(event)
            if self.path:
                self._rotate_if_needed()
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(asdict(event), separators=(",", ":")) + "\n")
        return event

    def recent(self, run_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self._events)
        if run_id is not None:
            events = [event for event in events if event.run_id == run_id]
        return [asdict(event) for event in events]


trace_store = TraceStore(
    max_events=int(os.getenv("SENTINEL_TRACE_MAX_EVENTS", "2048")),
    path=os.getenv("SENTINEL_TRACE_PATH"),
    max_file_bytes=int(os.getenv("SENTINEL_TRACE_MAX_FILE_BYTES", str(50_000_000))),
)
