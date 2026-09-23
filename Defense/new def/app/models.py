"""API schemas and data models."""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_METADATA_BYTES = 4_096
REASON_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{1,63}$"
MAX_CONTENT_CHARS = 50_000
MAX_LIST_ITEMS = 500
MAX_CONFIRMATION_DEPTH = 6


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class CandidateAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["respond", "tool_call", "memory_write", "request_confirmation"]
    tool: str | None = None
    arguments: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    content: str | None = Field(default=None, max_length=MAX_CONTENT_CHARS)
    final: bool = False
    confirmation_for: CandidateAction | None = None

    @model_validator(mode="after")
    def _bounded_confirmation_depth(self) -> CandidateAction:
        depth = 0
        node = self.confirmation_for
        while node is not None:
            depth += 1
            if depth > MAX_CONFIRMATION_DEPTH:
                raise ValueError(f"confirmation_for nesting exceeds {MAX_CONFIRMATION_DEPTH} levels")
            node = node.confirmation_for
        return self


class Provenance(_Lenient):
    source_type: str
    source_id: str
    trust_level: Literal[
        "system_policy",
        "authenticated_user",
        "trusted_internal",
        "untrusted_internal",
        "untrusted_external",
        "adversary_controlled",
    ]
    origin_actor: str
    retrieved_via: str
    sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"


class ProvenanceRecord(_Lenient):
    id: str
    provenance: Provenance


class ConversationItem(_Lenient):
    role: str
    kind: str
    content: str = Field(max_length=MAX_CONTENT_CHARS)
    provenance_ids: list[str] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)


class ObservationView(_Lenient):
    kind: str
    content: str = Field(max_length=MAX_CONTENT_CHARS)
    provenance_ids: list[str] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)


class HistoryDigest(_Lenient):
    steps_taken: int = 0
    turn_index: int = 0
    tool_calls: list[dict[str, Any]] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    confirmations_granted: list[str] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    blocked_count: int = 0
    escalated_count: int = 0
    least_trusted_seen: str | None = None
    most_sensitive_seen: str | None = None


class DefenseRequest(_Lenient):
    run_id: str
    step_id: int
    user_goal: str = Field(max_length=MAX_CONTENT_CHARS)
    conversation: list[ConversationItem] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    observation: ObservationView | None = None
    candidate_action: CandidateAction
    policy_context: dict[str, Any] = Field(default_factory=dict)
    provenance: list[ProvenanceRecord] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    history_digest: HistoryDigest = Field(default_factory=HistoryDigest)


class DefenseDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["allow", "block", "escalate", "rewrite"]
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list, max_length=16)
    explanation: str | None = Field(default=None, max_length=500)
    rewritten_action: CandidateAction | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("reason_codes")
    @classmethod
    def _valid_codes(cls, codes: list[str]) -> list[str]:
        for code in codes:
            if not re.fullmatch(REASON_CODE_PATTERN, code):
                raise ValueError(f"invalid reason code {code!r}; use UPPER_SNAKE_CASE")
        return codes

    @field_validator("metadata")
    @classmethod
    def _bounded_metadata(cls, metadata: dict[str, Any]) -> dict[str, Any]:
        try:
            size = len(json.dumps(metadata, separators=(",", ":")))
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON-serializable") from exc
        if size > MAX_METADATA_BYTES:
            raise ValueError(f"metadata exceeds {MAX_METADATA_BYTES} bytes")
        return metadata

    @model_validator(mode="after")
    def _rewrite_needs_action(self) -> DefenseDecision:
        if (self.decision == "rewrite") != (self.rewritten_action is not None):
            raise ValueError("rewritten_action is required for, and only for, decision 'rewrite'")
        return self
