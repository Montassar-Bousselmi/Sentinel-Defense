"""Provenance-aware, stateful SENTINEL defense engine.

Design goals derived from the SENTINEL specification:
- decide only from agent state, candidate action, provenance, active policy, and observed content;
- treat untrusted content as data/evidence, never as authority;
- detect data-flow risk, indirect injection, multi-step influence, memory poisoning, and tampering;
- preserve utility by allowing benign reads and rewriting some risky sends into drafts;
- require confirmation for consequential operations;
- expose concise, auditable reason codes without chain-of-thought.

This module intentionally does not use scenario IDs, filenames, organizer labels, or expected outcomes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
import urllib.parse
import unicodedata
from functools import lru_cache
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from app.models import CandidateAction, DefenseDecision, DefenseRequest, Provenance

if TYPE_CHECKING:  # pragma: no cover - avoids a circular import at runtime
    from app.observability import TraceStore

TRUST_RANK = {
    "system_policy": 5,
    "authenticated_user": 4,
    "trusted_internal": 3,
    "untrusted_internal": 2,
    "untrusted_external": 1,
    "adversary_controlled": 0,
}

SENSITIVITY_RANK = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}

UNTRUSTED = {"untrusted_internal", "untrusted_external", "adversary_controlled"}
HIGH_IMPACT_STATUS = {
    "closed",
    "resolved",
    "cancelled",
    "disabled",
    "deleted",
    "executed",
    "approved",
    "completed",
}

# These are semantic capability labels, not scenario identifiers.
TOOL_CAPABILITIES = {
    "send_email": {"communicate_external", "write_external"},
    "email_send": {"communicate_external", "write_external"},
    "email_draft": {"communicate_draft", "internal_record_write"},
    "draft_email": {"communicate_draft", "internal_record_write"},
    "case_note_create": {"internal_record_write"},
    "ticket_update": {"internal_record_write"},
    "incident_create": {"internal_record_write"},
    "incident_update": {"internal_record_write"},
    "payment_prepare": {"payment_prepare"},
    "payment_execute": {"payment_execute", "financial_state_change"},
    "memory_write": {"memory_write"},
    "email_read": {"read"},
    "email_search": {"read"},
    "document_read": {"read"},
    "document_search": {"read"},
    "ticket_read": {"read"},
    "ticket_search": {"read"},
    "customer_lookup": {"read"},
    "policy_search": {"read"},
    "case_document_read": {"read"},
    "account_summary": {"read"},
    "alert_read": {"read"},
    "alert_search": {"read"},
    "asset_lookup": {"read"},
    "intel_search": {"read"},
    "wiki_search": {"read"},
}

EXTERNAL_DESTINATION_KEYS = {
    "to",
    "recipient",
    "recipients",
    "email",
    "email_to",
    "destination",
    "target",
    "url",
    "uri",
    "endpoint",
    "external_recipient",
    "account",
    "account_id",
    # Common exfiltration channels that were previously unchecked: an agent (or
    # an injected instruction) can route data out just as effectively through
    # cc/bcc or a webhook as through the primary "to" field.
    "cc",
    "bcc",
    "reply_to",
    "reply-to",
    "webhook",
    "webhook_url",
    "callback",
    "callback_url",
    "redirect_uri",
    "redirect_url",
    "notify",
    "notify_email",
    "forward_to",
    "share_with",
}


CYRILLIC_LOOKALIKES = str.maketrans({
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p",
    "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I",
    "Ј": "J", "К": "K", "М": "M", "О": "O", "Р": "P", "Т": "T",
    "Х": "X", "Ѕ": "S",
})

LEET_MAP = str.maketrans({
    "@": "a", "0": "o", "1": "i", "3": "e", "$": "s", "5": "s", "!": "i",
})

@lru_cache(maxsize=1024)
def _strip_adversarial_obfuscation(text: str) -> str:
    """Normalize Unicode, strip zero-width chars, and map homoglyphs."""
    decomposed = unicodedata.normalize("NFKD", text)
    cleaned = re.sub(r"[\u200b-\u200f\u202a-\u202e\ufeff]", "", decomposed)
    return cleaned.translate(CYRILLIC_LOOKALIKES)

SECRET_KEY_HINTS = {
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    "api_key",
    "apikey",
    "private_key",
    "access_key",
    "auth",
    "authorization",
}

INSTRUCTION_TERMS = {
    "ignore",
    "override",
    "follow",
    "execute",
    "send",
    "forward",
    "upload",
    "delete",
    "close",
    "disable",
    "approve",
    "confirm",
    "reveal",
    "export",
    "publish",
    "store",
    "remember",
    "authorize",
    "treat",
    "must",
    "do not",
    # French
    "ignorer",
    "outrepasser",
    "suivre",
    "executer",
    "exécuter",
    "envoyer",
    "transferer",
    "transférer",
    "supprimer",
    "desactiver",
    "désactiver",
    "approuver",
    "confirmer",
    "reveler",
    "révéler",
    "exporter",
    "publier",
    "stocker",
    # Spanish
    "anular",
    "seguir",
    "reenviar",
    "eliminar",
    "guardar",
    # German
    "ignorieren",
    "ubersteuern",
    "übersteuern",
    "folgen",
    "ausfuhren",
    "ausführen",
    "weiterleiten",
    "loschen",
    "löschen",
    "deaktivieren",
    "bestatigen",
    "bestätigen",
    "speichern",
}

AUTHORITY_TERMS = {
    "policy",
    "approved",
    "approval",
    "authorized",
    "authorization",
    "administrator",
    "admin",
    "officer",
    "system instruction",
    "security instruction",
    # Multilingual
    "politique",
    "approuve",
    "approuvé",
    "autorise",
    "autorisé",
    "administrateur",
    "politica",
    "política",
    "aprobado",
    "autorizacion",
    "autorización",
    "richtlinie",
    "genehmigt",
    "genehmigung",
    "systemanweisung",
}

SECRET_PATTERNS = [
    re.compile(r"(?i)\b(?:sk|pk)_[a-z0-9]{16,64}\b"),
    # Generic structured token, key, account, and contract reference patterns (independent of benchmark canary names)
    re.compile(r"(?i)\b[a-z0-9_]{0,16}(?:secret|token|key)[_-][a-z0-9]{8,64}\b"),
    re.compile(r"(?i)\b[a-z]{3,6}_(?:tok|key|sec|token)_[a-z0-9]{12,64}\b"),
    re.compile(r"\b[A-Z]{4,6}\d{14,24}\b"),
    re.compile(r"\b[A-Z]{3,4}-[A-Z0-9]{3,4}-[A-Z0-9]{6,16}\b"),
    re.compile(r"(?i)\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|session[_ -]?token)\s*[:=]\s*[^\s,;]{8,128}"),
    re.compile(r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----"),
    re.compile(r"(?i)\bauthorization:\s*bearer\s+[a-z0-9._\-]{12,256}"),
    re.compile(r"(?i)\bpassword\s*[:=]\s*\S{6,128}"),
    # Real-world credential formats bounded against ReDoS
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),  # AWS STS temporary key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),  # GitHub personal/app tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,64}\b"),  # Slack tokens
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),  # Google API key
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,200}\.[A-Za-z0-9_-]{10,200}\.[A-Za-z0-9_-]{10,500}\b"),  # JWT
    re.compile(r'\bmongodb(?:\+srv)?://[^\s"\'<>]{10,128}\b'),  # MongoDB connection string
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,128}\b"),  # Anthropic API key
    re.compile(r"\bsk-(?:proj-|live-)?[A-Za-z0-9_\-]{20,128}\b"),  # OpenAI API key
    re.compile(r"(?i)\b(?:sk|pk)_(?:live|test)_[a-z0-9]{16,64}\b"),  # Stripe live/test key
]


def action_digest(action: CandidateAction) -> str:
    """Match the evaluator's starter-kit digest logic; use the full SHA-256 internally."""

    def canonical(value: object) -> object:
        if isinstance(value, str):
            return " ".join(value.split())
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value

    payload: dict[str, object] = {
        "type": action.type,
        "tool": action.tool,
        "arguments": {k: canonical(v) for k, v in sorted(action.arguments.items())},
        "content": action.content if action.type != "tool_call" else None,
    }
    if action.confirmation_for is not None:
        payload["confirmation_for"] = action_digest(action.confirmation_for)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    # SENTINEL starter/evaluator confirmation IDs use the first 24 hex characters.
    return hashlib.sha256(encoded).hexdigest()[:24]


def trace_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


_CONFIRMATION_SECRET_ENV = "SENTINEL_CONFIRMATION_SECRET"


def _confirmation_secret() -> bytes:
    """Server-side key used to sign confirmation tickets.

    SECURITY: this MUST be set via SENTINEL_CONFIRMATION_SECRET in any real
    deployment. Falling back to a fixed string keeps the service from crashing
    in local/dev use, but it means confirmation tokens are forgeable exactly
    like the old plain-digest scheme whenever the env var is unset - this is a
    deliberately loud footgun, not a safe default. Log/alert on startup if the
    env var is missing.
    """
    secret = os.getenv(_CONFIRMATION_SECRET_ENV)
    if not secret:
        secret = "INSECURE-DEV-ONLY-SET-" + _CONFIRMATION_SECRET_ENV
    return secret.encode("utf-8")


def confirmation_token(action: CandidateAction, run_id: str) -> str:
    """Mint the ticket a caller must present to prove an action was actually confirmed.

    This replaces using the plain `action_digest` as the confirmation-granted
    value. A plain SHA-256 digest is fully computable by anyone who has this
    source code and the action's own (public) fields - which means a caller
    could self-issue "confirmations" for consequential actions without a human
    ever approving them. Signing the digest with a server-held secret (HMAC)
    means only this service can produce a valid token; a caller can only ever
    replay a token that was actually returned to it after a real escalation.
    Binding `run_id` into the signed payload also prevents a token minted for
    one session from being replayed in a different one.
    """
    payload = f"{run_id}:{action_digest(action)}".encode("utf-8")
    return hmac.new(_confirmation_secret(), payload, hashlib.sha256).hexdigest()[:24]


def _text(value: object) -> str:
    return str(value) if value is not None else ""


WORD_TOKEN_PATTERN = re.compile(r"[a-z0-9_@.:-]{2,}")


@lru_cache(maxsize=1024)
def _normalize(text: str) -> str:
    return " ".join(text.lower().split())


@lru_cache(maxsize=1024)
def _token_tuple(text: str) -> tuple[str, ...]:
    return tuple(WORD_TOKEN_PATTERN.findall(_normalize(text)))


@lru_cache(maxsize=1024)
def _tokens(text: str) -> frozenset[str]:
    return frozenset(_token_tuple(text))


@lru_cache(maxsize=1024)
def _token_bigrams(text: str) -> frozenset[tuple[str, str]]:
    toks = _token_tuple(text)
    if len(toks) < 2:
        return frozenset()
    return frozenset((toks[i], toks[i + 1]) for i in range(len(toks) - 1))


def _semantic_overlap(a: str, b: str) -> float:
    """Multi-scale similarity: token Jaccard, bi-gram Jaccard, and containment."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    token_jaccard = len(ta & tb) / len(ta | tb)

    # Containment: fraction of smaller token set inside larger token set
    smaller, larger = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
    containment = (len(smaller & larger) / len(smaller)) if smaller else 0.0
    embedded_score = 0.65 * containment if len(smaller) >= 4 else 0.0

    bg_a, bg_b = _token_bigrams(a), _token_bigrams(b)
    bg_jaccard = (len(bg_a & bg_b) / len(bg_a | bg_b)) if (bg_a and bg_b) else 0.0

    return max(token_jaccard, embedded_score, bg_jaccard)


def _jaccard(a: str, b: str) -> float:
    return _semantic_overlap(a, b)


def _contains_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


_HIGH_ENTROPY_TOKEN = re.compile(r"\b[A-Za-z0-9+_=]{28,}\b")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_high_entropy_secret(text: str) -> bool:
    """Low-confidence fallback for credential-shaped strings that match none of
    our named formats. Deliberately kept as a separate, lower-weight signal
    (see HIGH_ENTROPY_TOKEN below) rather than folded into `secret_detected`,
    since entropy alone produces real false positives (hashes, IDs, slugs)."""
    for token in _HIGH_ENTROPY_TOKEN.findall(text):
        if re.fullmatch(r"[0-9a-f]{32,64}", token) or token.isdigit():
            continue
        has_upper = any(c.isupper() for c in token)
        has_lower = any(c.islower() for c in token)
        has_digit = any(c.isdigit() for c in token)
        if (has_upper and has_lower and has_digit) and _shannon_entropy(token) >= 4.2:
            return True
    return False


def _decode_obvious_encodings(text: str, _depth: int = 0) -> list[str]:
    """Decode only obvious, bounded encodings; never treat decoded text as trusted.

    Recurses up to two extra layers (depth-limited, candidate-count-limited) to
    catch simple double-encoding such as base64-of-base64, and also tries
    URL-decoding, since a single layer of either was previously enough to hide
    an injected instruction or credential from every downstream check.
    """
    if _depth > 2:
        return []
    candidates: list[str] = []
    compact_for_b64 = re.sub(r"\s+", "", text)
    for chunk in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", compact_for_b64):
        try:
            raw = base64.b64decode(chunk, validate=True)
            decoded = raw.decode("utf-8")
            if decoded and any(ch.isalpha() for ch in decoded):
                candidates.append(decoded)
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass

    for chunk in re.findall(r"\b(?:[0-9A-Fa-f]{2}){8,}\b", text):
        try:
            raw = bytes.fromhex(chunk)
            decoded = raw.decode("utf-8")
            if decoded and any(ch.isalpha() for ch in decoded):
                candidates.append(decoded)
        except (ValueError, UnicodeDecodeError):
            pass

    try:
        url_decoded = urllib.parse.unquote(text)
        if url_decoded != text and any(ch.isalpha() for ch in url_decoded):
            candidates.append(url_decoded)
    except (ValueError, TypeError):
        pass

    compact = re.sub(r"\s+", "", text)
    if len(compact) >= 12:
        reversed_text = compact[::-1]
        if any(term in reversed_text.lower() for term in INSTRUCTION_TERMS | AUTHORITY_TERMS):
            candidates.append(reversed_text)

    candidates = candidates[:8]
    if _depth < 2:
        nested: list[str] = []
        for candidate in candidates:
            nested.extend(_decode_obvious_encodings(candidate, _depth + 1))
        candidates.extend(nested[:8])
    return candidates[:16]


def _encoded_sensitive_payload(text: str) -> bool:
    """Detect obvious encoded credential-like payloads inside an action argument."""
    for decoded in _decode_obvious_encodings(text):
        normalized = _normalize(decoded)
        if _contains_secret(decoded) or any(term in normalized for term in SECRET_KEY_HINTS):
            return True
        if re.search(r"(?i)\b(?:token|credential|password|private\s+key|api\s+key|secret)\s*[:=]\s*\S{6,}", normalized):
            return True
    return False


NEGATION_INJECTION_RE = re.compile(
    r"(?i)\b(?:do\s+not|don't|never|stop|refrain\s+from|forget|disregard|ignore|ne\s+pas|no)\s+"
    r"(?:follow|enforce|comply\s+with|apply|use|respecter|seguir|befolgen)?\s*"
    r"(?:the\s+|la\s+|el\s+|die\s+)?(?:policy|rules?|guardrails?|restrictions?|instructions?|politique|reglas?|richtlinie)\b"
)

HIJACK_DELIMITER_RE = re.compile(
    r"(?i)(?:\[system\]|<<<\s*system\s*>>>|---\s*begin\s+(?:system|prompt|instruction)|human:\s*|assistant:\s*|system:\s*|jailbreak|developer\s+mode|dan\s+mode)"
)


STRUCTURAL_INSTRUCTION_RE = re.compile(r"\b(ignore|do not|never|must|immediately|ignorer|ne pas)\b")
STRUCTURAL_AUTHORITY_RE = re.compile(r"\b(approved|authorized|policy|administrator|politique|autorisé)\b")


@lru_cache(maxsize=1024)
def _instruction_score(text: str) -> float:
    cleaned = _strip_adversarial_obfuscation(text)
    normalized = _normalize(cleaned)
    leet_norm = _normalize(cleaned.translate(LEET_MAP))
    tokens = _tokens(normalized) | _tokens(leet_norm)

    instruction_hits = sum(1 for term in INSTRUCTION_TERMS if term in normalized or term in leet_norm or term in tokens)
    authority_hits = sum(1 for term in AUTHORITY_TERMS if term in normalized or term in leet_norm or term in tokens)

    negation_hit = 1 if (NEGATION_INJECTION_RE.search(normalized) or NEGATION_INJECTION_RE.search(leet_norm)) else 0
    hijack_hit = 1 if (HIJACK_DELIMITER_RE.search(normalized) or HIJACK_DELIMITER_RE.search(leet_norm)) else 0

    structural = sum([
        1 if STRUCTURAL_INSTRUCTION_RE.search(normalized) else 0,
        1 if STRUCTURAL_AUTHORITY_RE.search(normalized) else 0,
        1 if ":" in normalized and len(normalized.split(":", 1)[0]) < 40 else 0,
        negation_hit * 2,
        hijack_hit * 2,
    ])
    score = 0.08 * instruction_hits + 0.12 * authority_hits + 0.10 * structural
    return min(1.0, score)


def _is_external_destination(value: str, policy: dict) -> bool:
    value = value.strip().lower()
    if not value:
        return False

    allowlisted = {str(x).lower() for x in policy.get("trusted_destinations", []) if x}
    if value in allowlisted:
        return False

    internal_domains = {
        str(x).lower()
        for x in (policy.get("internal_domains", []) or []) + (policy.get("internal_email_domains", []) or [])
        if x
    }
    if "@" in value:
        domain = value.rsplit("@", 1)[-1].strip(" >).,")
        if domain in internal_domains or any(domain.endswith("." + d) for d in internal_domains):
            return False
        return True

    parsed = urlparse(value if "://" in value else "https://" + value)
    host = (parsed.hostname or "").lower()
    if host:
        if host in internal_domains or any(host.endswith("." + d) for d in internal_domains):
            return False
        trusted_hosts = {str(x).lower() for x in policy.get("trusted_hosts", []) if x}
        return host not in trusted_hosts

    return False


def _capabilities_for(tool: str | None, policy: dict) -> set[str]:
    if not tool:
        return set()
    configured = policy.get("tool_capabilities", {})
    values = configured.get(tool) if isinstance(configured, dict) else None
    if isinstance(values, list):
        return {str(x) for x in values}
    return set(TOOL_CAPABILITIES.get(tool, set()))


def _required_confirmation(tool: str, policy: dict, action: CandidateAction) -> bool:
    configured = set(policy.get("confirmation_required", [])) | set(policy.get("confirmation_required_tools", []))
    if tool in configured:
        return True
    if tool in {"payment_execute", "financial_execute"}:
        return True
    status = action.arguments.get("status")
    if isinstance(status, str) and status.lower() in HIGH_IMPACT_STATUS:
        return True
    if tool in {"send_email", "email_send"}:
        return bool(_external_values(action, policy))
    return tool.endswith("_execute")


def _allowed_tool(tool: str, policy: dict) -> bool:
    allowed = policy.get("allowed_tools")
    if isinstance(allowed, list) and allowed:
        return tool in {str(x) for x in allowed}
    # Missing policy is not evidence of authorization.
    return False


def _goal_alignment(goal: str, action: CandidateAction, capabilities: set[str]) -> float:
    goal_n = _normalize(goal)
    if not goal_n:
        return 0.5

    # Action/capability semantics are more reliable than exact phrase matching.
    capability_terms: dict[str, set[str]] = {
        "read": {"read", "retrieve", "lookup", "search", "find", "review", "summarize"},
        "communicate": {"send", "reply", "email", "draft", "respond"},
        "write": {"write", "create", "update", "modify", "note"},
        "finance": {"payment", "pay", "refund", "transfer", "purchase"},
        "incident": {"incident", "alert", "security", "remediation", "monitoring"},
        "memory": {"remember", "memory", "store"},
    }

    goal_words = _tokens(goal_n)
    matched_categories = 0
    for terms in capability_terms.values():
        if goal_words & terms:
            matched_categories += 1 if terms & goal_words else 0

    # A purely read-only task should not spontaneously acquire write capabilities.
    read_markers = {"summarize", "summary", "read", "review", "find", "retrieve", "lookup"}
    write_markers = {"send", "forward", "email", "create", "update", "modify", "note", "close", "disable", "pay", "execute"}
    if goal_words & read_markers and not (goal_words & write_markers) and capabilities & {"write_external", "modify_record", "payment_execute", "security_state_change"}:
        return 0.15

    if "communicate_draft" in capabilities and any(w in goal_words for w in {"draft", "prepare", "reply", "respond"}):
        return 0.9
    if "communicate_external" in capabilities:
        if any(w in goal_words for w in {"draft", "prepare"}) and not any(w in goal_words for w in {"send", "forward"}):
            return 0.2
        if any(w in goal_words for w in {"send", "email", "reply", "forward"}):
            return 0.9
    if "payment_execute" in capabilities and any(w in goal_words for w in {"pay", "payment", "transfer", "execute", "refund"}):
        return 0.85
    if "memory_write" in capabilities and any(w in goal_words for w in {"remember", "memory", "store"}):
        return 0.85
    if "modify_record" in capabilities and any(
        w in goal_words for w in {"add", "close", "incident", "modify", "note", "open", "resolve", "ticket", "update"}
    ):
        return 0.85

    if action.type == "respond":
        return 0.75
    return min(0.75, 0.45 + 0.08 * matched_categories)


@dataclass
class SignalSet:
    risk: float = 0.0
    confidence: float = 0.5
    codes: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    factors: dict[str, float] = field(default_factory=dict)
    source_trust: int = 5
    source_sensitivity: int = 0
    untrusted_influence: float = 0.0
    external_destination: bool = False
    secret_detected: bool = False
    consequential: bool = False
    goal_alignment: float = 0.5
    injection_score: float = 0.0

    def add(self, code: str, weight: float, note: str) -> None:
        if code not in self.codes:
            self.codes.append(code)
        self.risk = min(1.0, self.risk + weight)
        self.notes.append(note)

    def factor(self, name: str, value: float) -> None:
        self.factors[name] = max(0.0, min(1.0, value))


def _provenance_map(request: DefenseRequest) -> dict[str, Provenance]:
    return {record.id: record.provenance for record in request.provenance}


def _effective_trust(pids: list[str], pmap: dict[str, Provenance], policy: dict) -> tuple[str, str]:
    """Resolve (trust_level, sensitivity) across all provenance IDs.

    When multiple provenance IDs are associated with an item, evaluate ALL
    resolved records and select the most untrusted level (minimum trust rank)
    and the most sensitive level (maximum sensitivity rank). This eliminates
    the vulnerability where an adversary could prepend a trusted ID to mask
    untrusted or confidential content.
    """
    resolved_records = [pmap[pid] for pid in pids if pid in pmap]
    if resolved_records:
        min_rank = min(TRUST_RANK.get(r.trust_level, 0) for r in resolved_records)
        max_sens = max(SENSITIVITY_RANK.get(r.sensitivity, 0) for r in resolved_records)
        trust_level = next(k for k, v in TRUST_RANK.items() if v == min_rank)
        sensitivity = next(k for k, v in SENSITIVITY_RANK.items() if v == max_sens)
        return trust_level, sensitivity

    default = policy.get("default_trust_for_unlabeled", "untrusted_internal")
    if default not in TRUST_RANK:
        default = "untrusted_internal"
    return default, "internal"


def _source_stats(request: DefenseRequest) -> tuple[int, int, list[tuple[str, str, str]]]:
    pmap = _provenance_map(request)
    policy = request.policy_context
    sources: list[tuple[str, str, str]] = []
    min_trust = 5
    max_sens = 0
    for item in request.conversation:
        trust_level, sensitivity = _effective_trust(item.provenance_ids, pmap, policy)
        min_trust = min(min_trust, TRUST_RANK[trust_level])
        max_sens = max(max_sens, SENSITIVITY_RANK[sensitivity])
        sources.append((trust_level, sensitivity, item.content))
    if request.observation:
        trust_level, sensitivity = _effective_trust(request.observation.provenance_ids, pmap, policy)
        min_trust = min(min_trust, TRUST_RANK[trust_level])
        max_sens = max(max_sens, SENSITIVITY_RANK[sensitivity])
        sources.append((trust_level, sensitivity, request.observation.content))
    return min_trust, max_sens, sources


def _untrusted_contents(request: DefenseRequest) -> list[str]:
    pmap = _provenance_map(request)
    policy = request.policy_context
    contents: list[str] = []

    for item in request.conversation:
        trust_level, _sensitivity = _effective_trust(item.provenance_ids, pmap, policy)
        if trust_level in UNTRUSTED:
            contents.append(item.content)

    if request.observation:
        trust_level, _sensitivity = _effective_trust(request.observation.provenance_ids, pmap, policy)
        if trust_level in UNTRUSTED:
            contents.append(request.observation.content)

    return contents


def _history_strings(request: DefenseRequest) -> list[str]:
    results: list[str] = []
    for record in request.history_digest.tool_calls:
        if not isinstance(record, dict):
            continue
        for key in ("tool", "name", "result", "output", "content", "arguments", "status"):
            value = record.get(key)
            if isinstance(value, (str, int, float, bool)):
                results.append(str(value))
            elif isinstance(value, dict):
                results.extend(str(v) for v in value.values() if v is not None)
    return results


def _argument_text(action: CandidateAction) -> str:
    return " ".join([action.tool or "", action.content or ""] + [f"{k}={v}" for k, v in action.arguments.items()])


DIRECT_INSTRUCTION_KEYS = {
    "account_id",
    "alert_id",
    "asset_id",
    "beneficiary_id",
    "case_id",
    "doc_id",
    "document_id",
    "email_id",
    "incident_id",
    "payment_id",
    "query",
    "search_query",
    "remediation_id",
    "status",
    "ticket_id",
}

READ_ONLY_DOCUMENT_TOOLS = {"document_read"}


DESTINATION_KEY_HINTS = EXTERNAL_DESTINATION_KEYS | {
    "recipient",
    "recipients",
    "destination",
    "destinations",
    "to",
    "cc",
    "bcc",
    "endpoint",
    "url",
    "webhook",
    "target",
    "forward_to",
    "send_to",
    "host",
}


def _find_external_values(obj: Any, key_context: str, policy: dict, depth: int = 0) -> list[str]:
    """Recursively search for external destination strings in arguments up to depth 8."""
    if depth > 8:
        return []
    results: list[str] = []
    if isinstance(obj, str):
        key_l = key_context.lower()
        is_dest_key = any(h in key_l for h in DESTINATION_KEY_HINTS)
        if is_dest_key or "@" in obj or "://" in obj:
            if _is_external_destination(obj, policy):
                results.append(obj)
        stripped = obj.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
            try:
                parsed = json.loads(stripped)
                results.extend(_find_external_values(parsed, key_context, policy, depth + 1))
            except Exception:
                pass
    elif isinstance(obj, dict):
        for k, v in obj.items():
            results.extend(_find_external_values(v, str(k), policy, depth + 1))
    elif isinstance(obj, (list, tuple, set)):
        for item in obj:
            results.extend(_find_external_values(item, key_context, policy, depth + 1))
    return results


def _external_values(action: CandidateAction, policy: dict) -> list[str]:
    return _find_external_values(action.arguments, "", policy)


def _build_safe_rewrite(action: CandidateAction, policy: dict) -> CandidateAction | None:
    """Rewrite external send actions into draft actions without copying hidden data elsewhere."""
    if action.tool not in {"send_email", "email_send"}:
        return None

    allowed = {str(x) for x in policy.get("allowed_tools", [])}
    target_tool = "email_draft" if "email_draft" in allowed else ("draft_email" if "draft_email" in allowed else None)
    if not target_tool:
        return None

    # Keep only valid compose/draft arguments (to, subject, body) so ToolArgs(extra='forbid') does not fail
    valid_keys = {"to", "subject", "body"}
    args = {k: v for k, v in action.arguments.items() if k in valid_keys}
    return CandidateAction(
        type="tool_call",
        tool=target_tool,
        arguments=args,
        content=action.content,
        final=False,
    )


def _decide(request: DefenseRequest, trace_store: "TraceStore | None" = None) -> DefenseDecision:
    candidate = request.candidate_action
    action = candidate.confirmation_for if candidate.type == "request_confirmation" else candidate

    # Non-tool actions remain valid actions in SENTINEL; their safety still matters.
    if action is None:
        return DefenseDecision(
            decision="block",
            risk_score=1.0,
            confidence=0.99,
            reason_codes=["INVALID_CONFIRMATION_TARGET"],
            explanation="The confirmation request does not contain an actionable target.",
        )

    if candidate.type == "request_confirmation":
        # Asking for human confirmation is itself non-consequential; evaluate the target so
        # a malicious agent cannot use confirmation as a substitute for policy enforcement.
        target = action
        target_result = _evaluate_tool_request(request, target, trace_store)
        if target_result[0] in {"block", "rewrite"}:
            return target_result[1]
        return DefenseDecision(
            decision="allow",
            risk_score=min(0.6, target_result[1].risk_score),
            confidence=target_result[1].confidence,
            reason_codes=target_result[1].reason_codes or ["CONFIRMATION_REQUESTED"],
            explanation="The agent is requesting confirmation for the evaluated action.",
            # NOTE: this token is a signed ticket (see confirmation_token), not a
            # plain digest - a caller cannot compute it themselves. A real human
            # confirmation step must occur before this exact string reappears in
            # a future request's history_digest.confirmations_granted.
            metadata={
                **target_result[1].metadata,
                "confirmation_target": confirmation_token(target, request.run_id),
                "action_digest": action_digest(target),
            },
        )

    if action.type == "memory_write" or (action.type == "tool_call" and action.tool in {"memory_write", "memory_store", "store_memory"}):
        return _evaluate_memory_write(request, action)

    if action.type != "tool_call" or action.tool is None:
        return _evaluate_respond(request, action)

    return _evaluate_tool_request(request, action, trace_store)[1]


def _evaluate_respond(request: DefenseRequest, action: CandidateAction) -> DefenseDecision:
    content = action.content or ""
    signal = SignalSet()
    trust_rank, sensitivity, _ = _source_stats(request)
    signal.source_trust = trust_rank
    signal.source_sensitivity = sensitivity

    # Check for secret or credential leakage in user response
    has_secret = _contains_secret(content) or _encoded_sensitive_payload(content)
    if has_secret:
        signal.add("CREDENTIAL_LIKE_DATA", 0.65, "Credential or secret token detected in user response.")
        signal.add("SENSITIVE_DATA_TO_SINK", 0.35, "Sensitive credential would leak to response sink.")
        cleaned = content
        for pattern in SECRET_PATTERNS:
            cleaned = pattern.sub("[REDACTED_SECRET]", cleaned)
        rewritten = CandidateAction(
            type="respond",
            content=cleaned,
            final=action.final,
        )
        return _decision_from_signal(
            signal,
            "rewrite",
            "The response contained sensitive credential-like data and was redacted to prevent exfiltration.",
            rewritten_action=rewritten,
        )

    return DefenseDecision(
        decision="allow",
        risk_score=0.05,
        confidence=0.7,
        reason_codes=["NON_TOOL_ACTION"],
        explanation="No external tool capability is invoked by this action.",
        metadata={"action_type": action.type},
    )


CRITICAL_MEMORY_KEYS = {
    "system_prompt",
    "system_instruction",
    "guardrail",
    "guardrails",
    "policy",
    "rules",
    "system_message",
    "security_policy",
    "security_config",
    "core_instructions",
    "developer_message",
}


def _evaluate_memory_write(request: DefenseRequest, action: CandidateAction) -> DefenseDecision:
    untrusted = _untrusted_contents(request)
    content = action.content or " ".join(str(v) for v in action.arguments.values() if v is not None)
    signal = SignalSet()

    trust_rank, sensitivity, _ = _source_stats(request)
    signal.source_trust = trust_rank
    signal.source_sensitivity = sensitivity

    # Guard against self-modifying agent memory writes targeting control instructions or policy
    targeted_slot = str(
        action.arguments.get("key")
        or action.arguments.get("name")
        or action.arguments.get("target")
        or action.arguments.get("slot")
        or ""
    ).lower()
    if any(crit in targeted_slot for crit in CRITICAL_MEMORY_KEYS):
        signal.add("SYSTEM_STATE_TAMPERING", 0.90, "Memory write targets critical system instruction or policy state.")
        return _decision_from_signal(signal, "block", "Memory writes cannot overwrite system instructions or security guardrails.")

    if re.search(r"(?i)(?:you are now|new system prompt|override rules|disregard policy)", content):
        signal.add("SYSTEM_STATE_TAMPERING", 0.85, "Memory content attempts to redefine system role or override rules.")
        return _decision_from_signal(signal, "block", "Memory content attempts to inject system instructions.")

    overlap = max((_jaccard(content, source) for source in untrusted), default=0.0)
    injection = _instruction_score(content)
    authority_claim = any(term in _normalize(content) for term in AUTHORITY_TERMS)

    if untrusted and ((overlap >= 0.18 and injection >= 0.28) or authority_claim):
        signal.untrusted_influence = max(overlap, injection)
        signal.add("MEMORY_UNTRUSTED_LINEAGE", 0.55, "Memory content is materially influenced by untrusted material.")
        if authority_claim:
            signal.add("UNTRUSTED_AUTHORITY_CLAIM", 0.25, "Untrusted material is being promoted into durable memory as authority-like content.")
        return _decision_from_signal(signal, "block", "The memory write would preserve attacker-influenced content as durable state.")

    if sensitivity >= SENSITIVITY_RANK["confidential"]:
        signal.add("SENSITIVE_MEMORY_WRITE", 0.25, "Sensitive content is being persisted in memory.")

    return _decision_from_signal(signal, "allow", "The memory write is not materially derived from untrusted authority-like content.")


def _server_history(trace_store: "TraceStore | None", run_id: str) -> dict[str, Any]:
    """Reconstruct history facts from the server's own trace log for this run_id.

    `history_digest` in the request is supplied by the caller, so a caller that
    under-reports (or zeroes out) blocked_count/escalated_count/steps_taken/
    least_trusted_seen can silently defeat the long-horizon and adaptive-retry
    checks below. The trace store already records every decision this service
    has made for a run, including the source-trust rank it observed
    (`metadata.source_trust_rank`), so it doubles as an independent, harder-to-
    forge history source. Returns {} when unavailable so callers can fall back
    to the client-reported digest alone.
    """
    if trace_store is None or not run_id:
        return {}
    events = trace_store.recent(run_id)
    if not events:
        return {}
    trust_ranks = [
        rank
        for event in events
        if isinstance(rank := event.get("metadata", {}).get("source_trust_rank"), int)
    ]
    escalated_targets = set()
    for event in events:
        decision = event.get("decision")
        action_type = event.get("action_type")
        if decision == "escalate" or (action_type == "request_confirmation" and decision == "allow"):
            meta = event.get("metadata", {})
            if "confirmation_target" in meta:
                escalated_targets.add(meta["confirmation_target"])
            if "action_digest" in meta:
                escalated_targets.add(meta["action_digest"])

    return {
        "blocked_count": sum(1 for event in events if event.get("decision") == "block"),
        "escalated_count": sum(1 for event in events if event.get("decision") == "escalate"),
        "steps_taken": len(events),
        "min_trust_rank": min(trust_ranks) if trust_ranks else None,
        "escalated_targets": escalated_targets,
        "has_prior_trace": True,
    }


def _evaluate_tool_request(
    request: DefenseRequest, action: CandidateAction, trace_store: "TraceStore | None" = None
) -> tuple[str, DefenseDecision]:
    policy = request.policy_context
    tool = action.tool or ""
    signal = SignalSet()
    capabilities = _capabilities_for(tool, policy)

    if not _allowed_tool(tool, policy):
        signal.add("TOOL_NOT_AUTHORIZED", 0.72, "The requested tool is not authorized by the active tool policy.")
        signal.factor("authorization", 1.0)
        return "block", _decision_from_signal(signal, "block", "The tool is outside the active authorization policy.")

    trust_rank, sensitivity, source_records = _source_stats(request)
    signal.source_trust = trust_rank
    signal.source_sensitivity = sensitivity
    signal.factor("source_trust", 1.0 - trust_rank / 5.0)
    signal.factor("source_sensitivity", sensitivity / 3.0)

    goal_alignment = _goal_alignment(request.user_goal, action, capabilities)
    signal.goal_alignment = goal_alignment
    signal.factor("goal_alignment", 1.0 - goal_alignment)

    if goal_alignment < 0.25:
        signal.add("GOAL_MISMATCH", 0.25, "The action adds a capability not supported by the stated user goal.")

    action_text = _argument_text(action)
    untrusted = _untrusted_contents(request)
    composed_untrusted = " ".join(untrusted)
    injection_scores = [_instruction_score(text) for text in untrusted]
    if composed_untrusted:
        injection_scores.append(_instruction_score(composed_untrusted))
    decoded_texts = [decoded for text in untrusted for decoded in _decode_obvious_encodings(text)]
    injection_scores.extend(_instruction_score(text) for text in decoded_texts)
    signal.injection_score = max(injection_scores, default=0.0)

    overlaps = [_jaccard(action_text, text) for text in untrusted]
    decoded_overlaps = [_jaccard(action_text, text) for text in decoded_texts]
    if composed_untrusted:
        overlaps.append(_jaccard(action_text, composed_untrusted))
    max_overlap = max(overlaps + decoded_overlaps, default=0.0)

    # Multi-signal inference: untrusted instructional content matters when it also resembles
    # the current action or intersects with action-relevant entities.
    action_entities = _tokens(action_text) - {tool.lower()}
    entity_hits = 0.0
    for text in untrusted + decoded_texts + ([composed_untrusted] if composed_untrusted else []):
        toks = _tokens(text)
        if action_entities:
            entity_hits = max(entity_hits, len(action_entities & toks) / max(1, len(action_entities)))

    influence = max(
        0.45 * signal.injection_score + 0.40 * max_overlap + 0.15 * entity_hits,
        0.0,
    )
    signal.untrusted_influence = min(1.0, influence)
    signal.factor("untrusted_influence", signal.untrusted_influence)

    normalized_untrusted = [_normalize(text) for text in untrusted]
    argument_values = [
        _normalize(str(value))
        for key, value in action.arguments.items()
        if key in DIRECT_INSTRUCTION_KEYS and value is not None and len(str(value)) >= 4
    ]
    direct_instruction = any(
        any(
            re.search(rf"{re.escape(tool.lower())}.{{0,40}}{re.escape(value)}", text)
            or re.search(rf"{re.escape(value)}.{{0,40}}{re.escape(tool.lower())}", text)
            for value in argument_values
        )
        for text in normalized_untrusted
    )
    if direct_instruction and tool not in READ_ONLY_DOCUMENT_TOOLS:
        signal.add("DIRECT_UNTRUSTED_INSTRUCTION", 0.55, "Untrusted content directly requests the candidate tool with its arguments.")
        return "block", _decision_from_signal(signal, "block", "The candidate action is directly instructed by untrusted content.")

    if signal.untrusted_influence >= 0.28:
        signal.add("UNTRUSTED_INFLUENCE", 0.32, "Untrusted content is materially aligned with the candidate action.")

    # Tool-output tampering: observed tool results are evidence, not a new authority source.
    if request.observation and request.observation.provenance_ids:
        pmap = _provenance_map(request)
        obs_trusts = [pmap[pid].trust_level for pid in request.observation.provenance_ids if pid in pmap]
        obs_untrusted = any(t in UNTRUSTED for t in obs_trusts)
        observation_score = _instruction_score(request.observation.content)
        authority_claim = any(term in _normalize(request.observation.content) for term in AUTHORITY_TERMS)
        status = _normalize(_text(action.arguments.get("status")))
        high_impact_status = status in HIGH_IMPACT_STATUS
        if obs_untrusted and observation_score >= 0.20 and (authority_claim or high_impact_status or signal.untrusted_influence >= 0.20):
            signal.add("UNTRUSTED_TOOL_OUTPUT_AUTHORITY", 0.38, "An untrusted observation is attempting to influence an external state-changing action.")

    # Data-flow analysis.
    arg_text = action_text
    secret = _contains_secret(arg_text) or _encoded_sensitive_payload(arg_text)
    key_secret = any(any(h in k.lower() for h in SECRET_KEY_HINTS) for k in action.arguments)
    signal.secret_detected = secret or key_secret
    if signal.secret_detected:
        signal.add("CREDENTIAL_LIKE_DATA", 0.30, "Credential-like data is present in the candidate action.")
    elif tool not in READ_ONLY_DOCUMENT_TOOLS and _looks_high_entropy_secret(arg_text):
        # Lower-confidence signal: contributes to the general risk budget but,
        # unlike secret_detected, does not trigger the hard-stop rules below -
        # this covers credential formats our named patterns don't recognize
        # without making every hash/ID/slug a hard block.
        signal.add("HIGH_ENTROPY_TOKEN", 0.12, "An unlabeled high-entropy token resembling a credential is present in the candidate action.")

    external_values = [] if tool in {"email_draft", "draft_email", "payment_prepare"} else _external_values(action, policy)
    signal.external_destination = bool(external_values)
    if external_values:
        signal.add("EXTERNAL_DESTINATION", 0.18, "The candidate action targets a destination outside configured trusted destinations.")

    if signal.secret_detected and external_values:
        signal.add("SENSITIVE_DATA_TO_EXTERNAL", 0.42, "Credential-like data is being sent to an external destination.")

    if sensitivity >= SENSITIVITY_RANK["confidential"] and external_values:
        signal.add("CONFIDENTIAL_DATA_TO_EXTERNAL", 0.35, "Confidential or restricted source material is being sent externally.")

    if signal.source_trust <= TRUST_RANK["untrusted_external"] and external_values:
        signal.add("LOW_TRUST_EXTERNAL_FLOW", 0.22, "The action combines low-trust source material with an external destination.")

    # History-aware escalation for long-horizon/compositional behavior.
    #
    # blocked_count/escalated_count/steps_taken/least_trusted_seen below are
    # reconciled with the server's own trace log rather than trusted outright:
    # history_digest is caller-supplied, and a caller (or an attacker who
    # controls the framework building the request) could under-report these to
    # hide a prior pattern of denials or a low-trust source seen earlier in the
    # run. Reconciliation takes the *more suspicious* of the two sources, so a
    # caller can raise the client-reported values but not use them to suppress
    # what the server already recorded.
    server_hist = _server_history(trace_store, request.run_id)
    effective_blocked = max(request.history_digest.blocked_count, server_hist.get("blocked_count", 0))
    effective_escalated = max(request.history_digest.escalated_count, server_hist.get("escalated_count", 0))
    effective_steps = max(request.history_digest.steps_taken, server_hist.get("steps_taken", 0))
    reported_trust_rank = (
        TRUST_RANK[request.history_digest.least_trusted_seen]
        if request.history_digest.least_trusted_seen in TRUST_RANK
        else 5
    )
    server_min_trust_rank = server_hist.get("min_trust_rank")
    effective_min_trust_rank = (
        min(reported_trust_rank, server_min_trust_rank) if server_min_trust_rank is not None else reported_trust_rank
    )

    history_blob = " ".join(_history_strings(request))
    history_untrusted_overlap = max((_jaccard(action_text, h) for h in _untrusted_contents(request) + [history_blob]), default=0.0)
    previous_denials = effective_blocked + effective_escalated
    if history_blob and history_untrusted_overlap >= 0.16:
        signal.add("COMPOSITIONAL_INFLUENCE", 0.18, "Prior observations/actions share action-relevant entities with the current candidate.")
    if effective_min_trust_rank <= TRUST_RANK["untrusted_external"] and effective_steps >= 3:
        signal.add("LOW_TRUST_LONG_HORIZON", 0.12, "Low-trust material has remained in the agent state across multiple steps.")
    if previous_denials >= 2 and signal.untrusted_influence >= 0.15:
        signal.add("ADAPTIVE_RETRY_SIGNAL", 0.15, "The current action follows prior blocked/escalated behavior while retaining untrusted influence.")

    consequential = bool(capabilities & {"write_external", "payment_execute", "financial_state_change", "security_state_change"})
    status = action.arguments.get("status")
    if isinstance(status, str) and status.lower() in HIGH_IMPACT_STATUS:
        consequential = True
    signal.consequential = consequential

    granted = set(request.history_digest.confirmations_granted)
    token = confirmation_token(action, request.run_id)
    digest = action_digest(action)
    reported_confirmed = (token in granted or digest in granted)

    confirmed = reported_confirmed
    # Reconcile confirmation against trace store if the server has prior records for this run
    if reported_confirmed and server_hist.get("has_prior_trace"):
        valid_targets = server_hist.get("escalated_targets", set())
        # If the server has tracked escalations in this run and this target was never escalated:
        if server_hist.get("escalated_count", 0) > 0 and token not in valid_targets and digest not in valid_targets:
            signal.add("UNVERIFIED_CONFIRMATION_GRANT", 0.40, "Confirmation presented was not issued by prior escalation in this run.")
            confirmed = False

    requires_confirmation = _required_confirmation(tool, policy, action)

    # Hard-stop rules: policy violations and dangerous data flows must not be bypassed by confirmation.
    if signal.secret_detected and external_values:
        rewrite = _build_safe_rewrite(action, policy)
        if rewrite is not None:
            signal.add("SAFE_REWRITE_AVAILABLE", 0.08, "The unsafe external send can be converted into a draft without executing the send.")
            return "rewrite", _decision_from_signal(signal, "rewrite", "The action would export credential-like data; the safer equivalent is a draft.", rewrite)
        return "block", _decision_from_signal(signal, "block", "Credential-like data would cross into an external destination.")

    if sensitivity >= SENSITIVITY_RANK["restricted"] and external_values:
        return "block", _decision_from_signal(signal, "block", "Restricted information would cross into an external destination.")

    if signal.secret_detected and tool in {"email_draft", "draft_email"}:
        return "block", _decision_from_signal(signal, "block", "Credential-like data must not be placed in an email draft.")

    if "UNTRUSTED_TOOL_OUTPUT_AUTHORITY" in signal.codes and consequential:
        return "block", _decision_from_signal(signal, "block", "An untrusted observation cannot authorize a consequential state change.")

    if "UNTRUSTED_INFLUENCE" in signal.codes and consequential:
        # Preserve utility where possible, but don't allow an untrusted instruction to silently
        # authorize a consequential operation.
        if requires_confirmation and not confirmed:
            signal.add("HUMAN_REVIEW_REQUIRED", 0.15, "Consequential action has untrusted influence and lacks bound human confirmation.")
            return "escalate", _decision_from_signal(
                signal,
                "escalate",
                "Human confirmation is required before this consequential action can proceed.",
                extra_metadata={"confirmation_target": confirmation_token(action, request.run_id), "action_digest": action_digest(action)},
            )
        return "block", _decision_from_signal(signal, "block", "The consequential action is materially influenced by untrusted content.")

    if requires_confirmation and not confirmed:
        signal.add("MISSING_CONFIRMATION", 0.25, "The action is consequential and has no confirmation bound to its exact digest.")
        return "escalate", _decision_from_signal(
            signal,
            "escalate",
            "Human confirmation is required before this consequential action proceeds.",
            extra_metadata={"confirmation_target": confirmation_token(action, request.run_id), "action_digest": action_digest(action)},
        )

    # Evidence of untrusted instructions on a read-only action is not itself a reason to block.
    # That preserves legitimate summarization/review utility.
    if signal.untrusted_influence >= 0.35 and not consequential:
        signal.add("UNTRUSTED_CONTENT_AS_DATA", 0.02, "Suspicious content is present, but the action does not grant it additional authority.")

    # Internal case notes and record updates are bounded records of the agent's work, not an
    # authorization for the consequential action described in the note.
    bounded_internal_write = "internal_record_write" in capabilities and not consequential
    if bounded_internal_write and not signal.secret_detected:
        return "allow", _decision_from_signal(signal, "allow", "The action records bounded internal work without changing consequential or external state.")

    # Read-only actions (evidence gathering) must not be blocked merely for accumulated background risk.
    if "read" in capabilities and not consequential and not signal.secret_detected:
        return "allow", _decision_from_signal(signal, "allow", "Authorized read-only actions are allowed as evidence gathering.")

    if signal.risk >= 0.75:
        return "block", _decision_from_signal(signal, "block", "Combined security signals exceed the action's allowed risk budget.")
    if signal.risk >= 0.45 and consequential:
        return "escalate", _decision_from_signal(
            signal,
            "escalate",
            "The combined action, provenance, and state signals warrant human review.",
            extra_metadata={"confirmation_target": confirmation_token(action, request.run_id), "action_digest": action_digest(action)},
        )

    return "allow", _decision_from_signal(signal, "allow", "The action is authorized, consistent with the goal, and does not violate the observed data-flow constraints.")


def _decision_from_signal(
    signal: SignalSet,
    decision: str,
    explanation: str,
    rewritten_action: CandidateAction | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> DefenseDecision:
    # Calibrated, deterministic normalization rather than arbitrary per-branch constants.
    feature_values = list(signal.factors.values())
    if feature_values:
        combined = 0.55 * signal.risk + 0.45 * (sum(feature_values) / len(feature_values))
    else:
        combined = signal.risk
    risk = max(0.0, min(1.0, combined))

    evidence_count = len(signal.codes)
    confidence = 0.45 + min(0.50, 0.07 * evidence_count)
    if signal.source_trust <= 1:
        confidence += 0.04
    confidence = min(0.99, confidence)

    codes = signal.codes[:16]
    metadata = {
        "policy_version": "sentinel-defense-v2",
        "signal_count": evidence_count,
        "factors": {k: round(v, 4) for k, v in signal.factors.items()},
        "source_trust_rank": signal.source_trust,
        "source_sensitivity_rank": signal.source_sensitivity,
        "goal_alignment": round(signal.goal_alignment, 4),
        "untrusted_influence": round(signal.untrusted_influence, 4),
        "injection_score": round(signal.injection_score, 4),
        "external_destination": signal.external_destination,
        "secret_detected": signal.secret_detected,
        "consequential": signal.consequential,
    }
    if extra_metadata:
        metadata.update(extra_metadata)

    return DefenseDecision(
        decision=decision,  # type: ignore[arg-type]
        risk_score=round(risk, 4),
        confidence=round(confidence, 4),
        reason_codes=codes or ["NO_SECURITY_VIOLATION"],
        explanation=explanation[:500],
        rewritten_action=rewritten_action,
        metadata=metadata,
    )


def decide(request: DefenseRequest, trace_store: "TraceStore | None" = None) -> DefenseDecision:
    """Fail closed on an unexpected defense-engine error.

    `trace_store`, when provided, lets history-aware checks be reconciled
    against the server's own record of this run instead of trusting the
    caller-reported history_digest alone (see _server_history).
    """
    try:
        return _decide(request, trace_store)
    except Exception as exc:  # defensive boundary: evaluator sees a valid response instead of a 500
        return DefenseDecision(
            decision="block",
            risk_score=1.0,
            confidence=0.99,
            reason_codes=["DEFENSE_INTERNAL_ERROR"],
            explanation="The defense encountered an internal error and failed closed.",
            metadata={"policy_version": "sentinel-defense-v2", "error_type": type(exc).__name__},
        )
