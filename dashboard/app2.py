"""SENTINEL V5-hybrid Observability Dashboard.

Run from the repository root with:

    streamlit run dashboard/app2.py

The dashboard reads JSONL artifacts produced by:

    uv run sentinel run ...

It never displays private chain-of-thought. It displays only observable and
auditable evidence: candidate actions, provenance references, defense signals,
decisions, rewrites, tool effects, evaluator findings, and raw trace events.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import yaml


st.set_page_config(
    page_title="SENTINEL · Cyber Observability Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DARK_CYBER_CSS = """
<style>
html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    color: #F3F4F6;
}

.stApp {
    background: radial-gradient(circle at 15% 15%, #0d1527 0%, #080c14 100%) !important;
}

/* Glassmorphic Cyber Cards */
.cyber-card {
    background: rgba(17, 24, 39, 0.65) !important;
    backdrop-filter: blur(14px) !important;
    -webkit-backdrop-filter: blur(14px) !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 12px !important;
    padding: 16px 20px !important;
    margin-bottom: 16px !important;
    box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.5) !important;
}

div[data-testid="stMetric"] {
    background: rgba(15, 23, 42, 0.6) !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 10px !important;
    padding: 10px 14px !important;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3) !important;
}

div[data-testid="stMetric"] label {
    font-size: 0.72rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.06em !important;
    color: #94A3B8 !important;
}

div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 1.45rem !important;
    font-weight: 700 !important;
    color: #F8FAFC !important;
}

.metric-box {
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 10px;
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    justify-content: center;
}

.metric-title {
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #94A3B8;
    margin-bottom: 4px;
}

.metric-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.5rem;
    font-weight: 700;
    line-height: 1.1;
}

.metric-sub {
    font-size: 0.68rem;
    color: #64748B;
    margin-top: 4px;
    font-family: 'JetBrains Mono', monospace;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background: rgba(15, 23, 42, 0.6);
    padding: 6px;
    border-radius: 10px;
    border: 1px solid rgba(255, 255, 255, 0.06);
}

.stTabs [data-baseweb="tab"] {
    border-radius: 8px;
    color: #94A3B8;
    font-weight: 600;
    padding: 8px 18px;
    background: transparent;
    border: none;
}

.stTabs [aria-selected="true"] {
    background: rgba(99, 102, 241, 0.25) !important;
    color: #818CF8 !important;
    border: 1px solid rgba(99, 102, 241, 0.4) !important;
}

.reason-chip {
    display: inline-block;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 6px;
    padding: 2px 8px;
    margin: 2px;
    font-size: 0.72rem;
    font-family: 'JetBrains Mono', monospace;
    color: #E2E8F0;
}
</style>
"""
st.markdown(DARK_CYBER_CSS, unsafe_allow_html=True)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STARTER_KIT_DIR = PROJECT_ROOT / "Sentinel_Starter_Kit-main"
if not STARTER_KIT_DIR.exists():
    STARTER_KIT_DIR = PROJECT_ROOT

ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
if not ARTIFACTS_DIR.exists():
    _starter_artifacts = STARTER_KIT_DIR / "artifacts"
    if _starter_artifacts.exists():
        ARTIFACTS_DIR = _starter_artifacts

RESULTS_DIR = PROJECT_ROOT / "results"
SCORECARDS_DIR = ARTIFACTS_DIR / "scorecards"
SCENARIOS_DIR = STARTER_KIT_DIR / "scenarios"
VENV_SENTINEL = STARTER_KIT_DIR / ".venv" / "bin" / "sentinel"


def sentinel_command() -> list[str]:
    """Resolve the local CLI on both Windows and POSIX environments."""
    candidates = [
        STARTER_KIT_DIR / ".venv" / "Scripts" / "sentinel.exe",
        STARTER_KIT_DIR / ".venv" / "Scripts" / "sentinel",
        STARTER_KIT_DIR / ".venv" / "bin" / "sentinel",
    ]
    for candidate in candidates:
        if candidate.exists():
            return [str(candidate)]
    return [sys.executable, "-m", "sentinel"]

DOMAINS_INFO = {
    "enterprise": {"title": "Enterprise Productivity", "color": "#3B82F6"},
    "finance": {"title": "Financial Sandbox", "color": "#10B981"},
    "soc": {"title": "Security Operations Center", "color": "#8B5CF6"},
}


def get_dark_chart_layout(title: str = "", height: int = 320) -> dict[str, Any]:
    """Dark cyber layout for Plotly figures."""
    return dict(
        title=dict(
            text=title,
            font=dict(family="Inter", size=13, color="#F8FAFC"),
            x=0.01,
            y=0.96,
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(15, 23, 42, 0.45)",
        font=dict(family="Inter", color="#94A3B8", size=11),
        height=height,
        margin=dict(l=35, r=25, t=45, b=35),
        xaxis=dict(
            gridcolor="rgba(255, 255, 255, 0.05)",
            zerolinecolor="rgba(255, 255, 255, 0.1)",
            tickfont=dict(family="JetBrains Mono", size=10, color="#94A3B8"),
        ),
        yaxis=dict(
            gridcolor="rgba(255, 255, 255, 0.05)",
            zerolinecolor="rgba(255, 255, 255, 0.1)",
            tickfont=dict(family="JetBrains Mono", size=10, color="#94A3B8"),
        ),
        legend=dict(
            font=dict(family="Inter", size=10, color="#CBD5E1"),
            bgcolor="rgba(15, 23, 42, 0.7)",
            bordercolor="rgba(255, 255, 255, 0.08)",
            borderwidth=1,
        ),
    )

DECISION_COLORS = {
    "allow": "#22C55E",
    "block": "#EF4444",
    "escalate": "#F59E0B",
    "rewrite": "#3B82F6",
}

ACTOR_COLORS = {
    "user": "#8B5CF6",
    "agent": "#2563EB",
    "defense": "#0F766E",
    "tool_gateway": "#6B7280",
    "evaluator": "#BE123C",
}

EVENT_LABELS = {
    "defense_decision": "Décision de défense",
    "tool_request": "Appel d'outil",
    "tool_result": "Résultat d'outil",
    "task_success": "Tâche réussie",
    "task_failure": "Tâche échouée",
    "policy_violation": "Violation de politique",
    "user_message": "Message utilisateur",
    "agent_response": "Réponse de l'agent",
}


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def parse_jsonl(text: str) -> list[dict[str, Any]]:
    """Parse JSONL while preserving valid events around malformed lines."""

    events: list[dict[str, Any]] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()

        if not stripped:
            continue

        try:
            value = json.loads(stripped)
        except json.JSONDecodeError as error:
            events.append(
                {
                    "type": "dashboard_parse_error",
                    "actor": "dashboard",
                    "seq": line_number,
                    "step_id": 0,
                    "payload": {
                        "message": f"Ligne JSON invalide: {error}",
                        "raw_line": stripped[:500],
                    },
                }
            )
            continue

        if isinstance(value, dict):
            events.append(value)

    return events


@st.cache_data(show_spinner=False)
def load_trace_from_path(path: str, modification_time: float) -> list[dict[str, Any]]:
    """Load a trace. modification_time invalidates Streamlit's cache."""

    del modification_time
    return parse_jsonl(Path(path).read_text(encoding="utf-8-sig"))


@st.cache_data(show_spinner=False)
def load_trace_from_upload(file_bytes: bytes) -> list[dict[str, Any]]:
    """Load an uploaded trace."""

    return parse_jsonl(file_bytes.decode("utf-8-sig"))


def find_trace_files() -> list[Path]:
    """Return repository JSONL artifacts, newest first."""

    if not ARTIFACTS_DIR.exists():
        return []

    return sorted(
        ARTIFACTS_DIR.rglob("*.jsonl"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def first_nonempty(*values: Any, default: Any = "") -> Any:
    """Return the first value that is not empty."""

    for value in values:
        if value not in (None, "", [], {}):
            return value

    return default


# ---------------------------------------------------------------------------
# SENTINEL normalization
# ---------------------------------------------------------------------------


def normalize_event(event: dict[str, Any], index: int) -> dict[str, Any]:
    """Normalize a real SENTINEL event into an audit-friendly row."""

    payload = event.get("payload", {})
    policy = event.get("policy", {})

    if not isinstance(payload, dict):
        payload = {"value": payload}

    if not isinstance(policy, dict):
        policy = {}

    actor = str(event.get("actor", "unknown"))
    event_type = str(event.get("type", "unknown"))

    action = payload.get("action", {})

    if not isinstance(action, dict):
        action = {}

    tool = first_nonempty(
        action.get("tool"),
        payload.get("tool"),
    )

    arguments = first_nonempty(
        action.get("arguments"),
        payload.get("arguments"),
        default={},
    )

    if not isinstance(arguments, dict):
        arguments = {"value": arguments}

    decision = ""

    if event_type == "defense_decision":
        decision = str(payload.get("decision", "")).lower()

    reason_codes = payload.get("reason_codes", [])

    if isinstance(reason_codes, str):
        reason_codes = [reason_codes]

    if not isinstance(reason_codes, list):
        reason_codes = []

    metadata = payload.get("metadata", {})

    if not isinstance(metadata, dict):
        metadata = {}

    provenance_refs = event.get("provenance_refs", [])

    if isinstance(provenance_refs, str):
        provenance_refs = [provenance_refs]

    if not isinstance(provenance_refs, list):
        provenance_refs = []

    outcome = ""

    if event_type == "tool_result":
        outcome = first_nonempty(
            payload.get("result"),
            payload.get("status"),
            payload.get("summary"),
        )
    elif actor == "evaluator":
        outcome = first_nonempty(
            payload.get("summary"),
            payload.get("message"),
            event_type,
        )

    content = first_nonempty(
        action.get("content"),
        payload.get("content"),
        payload.get("message"),
        default="",
    )

    rewritten_action = payload.get("rewritten_action")

    return {
        "idx": index,
        "seq": event.get("seq", index),
        "step_id": event.get("step_id", 0),
        "timestamp": event.get("timestamp", ""),
        "run_id": event.get("run_id", ""),
        "actor": actor,
        "event_type": event_type,
        "event_label": EVENT_LABELS.get(event_type, event_type),
        "tool": tool,
        "action_type": action.get("type", ""),
        "arguments": arguments,
        "content": content,
        "decision": decision,
        "risk_score": float(payload.get("risk_score", 0) or 0),
        "confidence": float(payload.get("confidence", 0) or 0),
        "reason_codes": reason_codes,
        "explanation": payload.get("explanation", ""),
        "rewritten_action": rewritten_action,
        "metadata": metadata,
        "policy_version": metadata.get("policy_version", ""),
        "rule": metadata.get("rule", ""),
        "provenance_refs": provenance_refs,
        "policy": policy,
        "outcome": outcome,
        "effects": payload.get("effects", []),
        "raw": event,
    }


def normalize_events(events: list[dict[str, Any]]) -> pd.DataFrame:
    """Return a DataFrame for all event types."""

    return pd.DataFrame(
        [
            normalize_event(event, index)
            for index, event in enumerate(events)
        ]
    )


def defense_events(frame: pd.DataFrame) -> pd.DataFrame:
    """Return defense decisions only."""

    return frame[frame["event_type"] == "defense_decision"].copy()


def evaluator_events(frame: pd.DataFrame) -> pd.DataFrame:
    """Return evaluator events only."""

    return frame[frame["actor"] == "evaluator"].copy()


# ---------------------------------------------------------------------------
# Result extraction
# ---------------------------------------------------------------------------


def extract_trace_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract observable final results without inventing hidden labels."""

    result: dict[str, Any] = {
        "task_success": None,
        "attack_success": None,
        "critical_violation": False,
        "data_flow_violation": False,
        "external_message_send": False,
        "task_summary": "",
        "violations": [],
        "success_conditions": [],
        "run_id": "",
        "policy_version": "",
        "model": "",
    }

    for event in events:
        actor = event.get("actor", "")
        event_type = event.get("type", "")
        payload = event.get("payload", {})

        if not isinstance(payload, dict):
            continue

        if event.get("run_id"):
            result["run_id"] = event["run_id"]

        if event_type == "defense_decision":
            metadata = payload.get("metadata", {})

            if isinstance(metadata, dict) and metadata.get("policy_version"):
                result["policy_version"] = metadata["policy_version"]

        if event_type == "tool_result":
            effects = payload.get("effects", [])

            if isinstance(effects, list) and "external_message_send" in effects:
                result["external_message_send"] = True

        if actor != "evaluator":
            continue

        explicit_attack_success = payload.get("attack_success")

        if isinstance(explicit_attack_success, bool):
            result["attack_success"] = explicit_attack_success

        if event_type == "task_success":
            result["task_success"] = True
            result["task_summary"] = payload.get("summary", "")
        elif event_type == "task_failure":
            result["task_success"] = False
            result["task_summary"] = payload.get("summary", "")
        elif event_type == "policy_violation":
            result["violations"].append(payload)

            if payload.get("severity") == "critical":
                result["critical_violation"] = True

            if payload.get("kind") == "data_flow":
                result["data_flow_violation"] = True

        condition = payload.get("condition")

        if condition:
            result["success_conditions"].append(
                {
                    "condition": condition,
                    "passed": payload.get("passed"),
                    "detail": payload.get("detail", ""),
                }
            )

    # This is clearly labelled as an inference when the trace has no explicit field.
    if result["attack_success"] is None:
        result["attack_success"] = bool(
            result["critical_violation"]
            or result["data_flow_violation"]
        )
        result["attack_success_source"] = "inféré depuis les violations observées"
    else:
        result["attack_success_source"] = "champ explicite de l'évaluateur"

    return result


def bool_label(value: bool | None) -> str:
    """Human-readable boolean label."""

    if value is None:
        return "INCONNU"

    return "OUI" if value else "NON"


def status_icon(value: bool | None, positive_when_true: bool = True) -> str:
    """Return a compact icon for a metric."""

    if value is None:
        return "⚪"

    good = value if positive_when_true else not value
    return "✅" if good else "❌"


# ---------------------------------------------------------------------------
# Provenance and action helpers
# ---------------------------------------------------------------------------


def build_provenance_index(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Collect provenance records found anywhere in the trace."""

    index: dict[str, dict[str, Any]] = {}

    def inspect(value: Any) -> None:
        if isinstance(value, dict):
            record_id = value.get("id")
            provenance = value.get("provenance")

            if isinstance(record_id, str) and isinstance(provenance, dict):
                index[record_id] = provenance

            for child in value.values():
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)

    for event in events:
        inspect(event)

    return index


def find_related_tool_result(
    frame: pd.DataFrame,
    step_id: int,
) -> dict[str, Any] | None:
    """Return a tool result for the same step when available."""

    matches = frame[
        (frame["step_id"] == step_id)
        & (frame["event_type"] == "tool_result")
    ]

    if matches.empty:
        return None

    return matches.iloc[0]["raw"]


def action_diff(
    original: dict[str, Any],
    rewritten: dict[str, Any],
) -> list[dict[str, Any]]:
    """Produce a simple field-level action diff."""

    rows: list[dict[str, Any]] = []

    original_arguments = original.get("arguments", {})
    rewritten_arguments = rewritten.get("arguments", {})

    if not isinstance(original_arguments, dict):
        original_arguments = {}

    if not isinstance(rewritten_arguments, dict):
        rewritten_arguments = {}

    keys = sorted(set(original_arguments) | set(rewritten_arguments))

    for key in keys:
        before = original_arguments.get(key)
        after = rewritten_arguments.get(key)

        rows.append(
            {
                "Champ": key,
                "Avant": before,
                "Après": after,
                "Modifié": before != after,
            }
        )

    if original.get("tool") != rewritten.get("tool"):
        rows.insert(
            0,
            {
                "Champ": "tool",
                "Avant": original.get("tool"),
                "Après": rewritten.get("tool"),
                "Modifié": True,
            },
        )

    return rows


# ---------------------------------------------------------------------------
# Interactive Plotly Visualizations (Cyber SOC Dark Theme)
# ---------------------------------------------------------------------------


def render_decision_donut_chart(decisions_df: pd.DataFrame) -> None:
    """Render modern Plotly donut chart of the 4 defense decisions."""
    counts = {"allow": 0, "block": 0, "escalate": 0, "rewrite": 0}
    for d in decisions_df["decision"]:
        d_lower = str(d).lower()
        if d_lower in counts:
            counts[d_lower] += 1

    total = sum(counts.values()) or 1
    labels = ["ALLOW", "BLOCK", "ESCALATE", "REWRITE"]
    values = [counts["allow"], counts["block"], counts["escalate"], counts["rewrite"]]
    colors = [
        DECISION_COLORS.get("allow", "#10B981"),
        DECISION_COLORS.get("block", "#EF4444"),
        DECISION_COLORS.get("escalate", "#F59E0B"),
        DECISION_COLORS.get("rewrite", "#3B82F6"),
    ]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.62,
                marker=dict(colors=colors, line=dict(color="#0F172A", width=2.5)),
                textinfo="label+percent",
                hoverinfo="label+value+percent",
                textfont=dict(family="JetBrains Mono", size=11, color="#FFFFFF"),
            )
        ]
    )
    layout = get_dark_chart_layout("Répartition des 4 Décisions de Défense", height=280)
    layout["annotations"] = [
        dict(
            text=f"<span style='font-size:22px; font-weight:800; color:#FFFFFF; font-family:JetBrains Mono;'>{total}</span><br><span style='font-size:10px; color:#94A3B8;'>DÉCISIONS</span>",
            x=0.5,
            y=0.5,
            showarrow=False,
        )
    ]
    fig.update_layout(layout)
    st.plotly_chart(fig, use_container_width=True)


def render_trajectory_chart(decisions_df: pd.DataFrame, highlight_step: int | None = None) -> None:
    """Interactive Area/Line chart of risk score & confidence across steps."""
    if decisions_df.empty:
        return

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=decisions_df["step_id"],
            y=decisions_df["risk_score"],
            mode="lines+markers",
            name="Score de Risque",
            line=dict(color="#EF4444", width=3),
            fill="tozeroy",
            fillcolor="rgba(239, 68, 68, 0.12)",
            marker=dict(size=7),
        )
    )
    fig.add_trace(
        go.Scatter(
            x=decisions_df["step_id"],
            y=decisions_df["confidence"],
            mode="lines+markers",
            name="Niveau de Confiance",
            line=dict(color="#38BDF8", width=2, dash="dot"),
            marker=dict(size=5),
        )
    )
    if highlight_step is not None:
        fig.add_vline(
            x=highlight_step,
            line_width=2.5,
            line_color="#FBBF24",
            line_dash="solid",
            annotation_text=f"Étape {highlight_step}",
            annotation_position="top left",
        )
    layout = get_dark_chart_layout("Trajectoire de Risque et de Confiance par Étape", height=280)
    layout["yaxis"]["range"] = [-0.05, 1.05]
    layout["xaxis"]["title"] = "Étape (step_id)"
    fig.update_layout(layout)
    st.plotly_chart(fig, use_container_width=True)


def render_step_gauges(risk_score: float, confidence: float) -> None:
    """Speedometer / Radial Indicator gauges for current step."""
    col1, col2 = st.columns(2)
    with col1:
        gauge_risk = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=risk_score,
                title={"text": "Score de Risque", "font": {"family": "Inter", "size": 13, "color": "#F8FAFC"}},
                number={"font": {"family": "JetBrains Mono", "size": 22, "color": "#FFFFFF"}, "valueformat": ".2f"},
                gauge={
                    "axis": {"range": [0, 1], "tickwidth": 1, "tickcolor": "#64748B"},
                    "bar": {"color": "#EF4444" if risk_score > 0.65 else ("#F59E0B" if risk_score > 0.3 else "#10B981")},
                    "bgcolor": "rgba(15, 23, 42, 0.5)",
                    "borderwidth": 1,
                    "bordercolor": "rgba(255, 255, 255, 0.1)",
                    "steps": [
                        {"range": [0, 0.3], "color": "rgba(16, 185, 129, 0.15)"},
                        {"range": [0.3, 0.65], "color": "rgba(245, 158, 11, 0.15)"},
                        {"range": [0.65, 1.0], "color": "rgba(239, 68, 68, 0.15)"},
                    ],
                },
            )
        )
        gauge_risk.update_layout(paper_bgcolor="rgba(0,0,0,0)", height=220, margin=dict(l=15, r=15, t=30, b=15))
        st.plotly_chart(gauge_risk, use_container_width=True)

    with col2:
        gauge_conf = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=confidence,
                title={"text": "Confiance", "font": {"family": "Inter", "size": 13, "color": "#F8FAFC"}},
                number={"font": {"family": "JetBrains Mono", "size": 22, "color": "#FFFFFF"}, "valueformat": ".2f"},
                gauge={
                    "axis": {"range": [0, 1], "tickwidth": 1, "tickcolor": "#64748B"},
                    "bar": {"color": "#38BDF8"},
                    "bgcolor": "rgba(15, 23, 42, 0.5)",
                    "borderwidth": 1,
                    "bordercolor": "rgba(255, 255, 255, 0.1)",
                },
            )
        )
        gauge_conf.update_layout(paper_bgcolor="rgba(0,0,0,0)", height=220, margin=dict(l=15, r=15, t=30, b=15))
        st.plotly_chart(gauge_conf, use_container_width=True)


def render_provenance_sankey(events: list[dict[str, Any]], tool_name: str, decision: str) -> None:
    """Interactive Sankey flow from Sources -> Trust -> Agent Context -> Tool Sink."""
    prov_refs = []
    for ev in events:
        if ev.get("provenance_refs"):
            prov_refs.extend(ev["provenance_refs"])
    source_name = prov_refs[0] if prov_refs else "Source Externe"

    nodes = [
        f"Source: {source_name[:30]}",
        "Niveau: UNTRUSTED_EXTERNAL",
        "Contexte Agent / Mémoire",
        f"Outil: {tool_name or 'gateway'}",
        f"Issue: {decision.upper()}",
    ]
    dec_color = DECISION_COLORS.get(decision.lower(), "#10B981")
    sankey_fig = go.Figure(
        data=[
            go.Sankey(
                node=dict(
                    pad=14,
                    thickness=16,
                    line=dict(color="#0F172A", width=1),
                    label=nodes,
                    color=["#F97316", "#EAB308", "#6366F1", "#38BDF8", dec_color],
                ),
                link=dict(
                    source=[0, 1, 2, 3],
                    target=[1, 2, 3, 4],
                    value=[1, 1, 1, 1],
                    color="rgba(99, 102, 241, 0.25)",
                ),
            )
        ]
    )
    layout = get_dark_chart_layout("Flux de Provenance et Niveaux de Confiance (Sankey)", height=240)
    sankey_fig.update_layout(layout)
    st.plotly_chart(sankey_fig, use_container_width=True)


# ---------------------------------------------------------------------------
# Real-Time Scenario Runner & Live Agent Behavior Monitor
# ---------------------------------------------------------------------------


def load_all_scenarios() -> list[dict[str, Any]]:
    """Scan and parse all YAML scenario files from public and validation folders."""
    scenarios: list[dict[str, Any]] = []
    if not SCENARIOS_DIR.exists():
        return scenarios

    for p in sorted(SCENARIOS_DIR.glob("**/*.yaml")):
        try:
            with open(p, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                data["_file_path"] = str(p)
                data["_rel_path"] = str(p.relative_to(STARTER_KIT_DIR))
                scenarios.append(data)
        except Exception:
            continue
    return scenarios


def execute_live_scenario(
    scenario_rel_path: str,
    defense: str = "provenance",
    defense_url: str | None = None,
    model: str = "mock",
    attacker: str = "static",
    attack_mode: str = "static",
    step_callback: Any = None,
) -> dict[str, Any]:
    """Execute scenario with real-time stdout streaming."""
    cmd = [
        *sentinel_command(),
        "run",
        "--scenario",
        scenario_rel_path,
        "--model",
        model,
        "--attacker",
        attacker,
        "--attack-mode",
        attack_mode,
        "--timeline",
    ]
    if defense_url:
        cmd.extend(["--defense-url", defense_url])
    else:
        cmd.extend(["--defense", defense])

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(STARTER_KIT_DIR / "src"), env.get("PYTHONPATH", "")) if part
    )
    env["COLUMNS"] = "300"
    env["TERM"] = "dumb"

    proc = subprocess.Popen(
        cmd,
        cwd=str(STARTER_KIT_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )

    lines = []
    artifact_path_str = None
    line_re = re.compile(r"^\[\d+\]\s+step\s+(\d+)\s+(\w+)\s+(.*)$")

    for line in iter(proc.stdout.readline, ""):
        lines.append(line)
        if step_callback:
            parsed = {"raw": line.strip()}
            m = line_re.match(line.strip())
            if m:
                step_id = int(m.group(1))
                actor = m.group(2)
                content = m.group(3)
                parsed.update({"step_id": step_id, "actor": actor, "content": content})
                if actor == "defense":
                    risk_m = re.search(r"risk=([\d.]+)", content)
                    dec_m = re.search(r"\b(ALLOW|BLOCK|ESCALATE|REWRITE)\b", content)
                    codes_m = re.search(r"codes=([\w,]+)", content)
                    if risk_m:
                        parsed["risk_score"] = float(risk_m.group(1))
                    if dec_m:
                        parsed["decision"] = dec_m.group(1)
                    if codes_m:
                        parsed["codes"] = codes_m.group(1).split(",")
                elif actor == "evaluator":
                    if "VIOLATION" in content or "critical" in content.lower():
                        parsed["violation"] = True
            elif "artifact:" in line:
                artifact_path_str = line.split("artifact:", 1)[1].strip()

            step_callback(parsed, line)

    proc.wait()

    artifact_full_path = None
    if artifact_path_str:
        candidate = STARTER_KIT_DIR / artifact_path_str
        if candidate.exists():
            artifact_full_path = candidate

    if not artifact_full_path:
        all_jsonl = sorted(ARTIFACTS_DIR.rglob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        if all_jsonl:
            artifact_full_path = all_jsonl[0]

    return {
        "success": proc.returncode == 0,
        "artifact_path": str(artifact_full_path) if artifact_full_path else "",
        "lines": lines,
        "command": " ".join(cmd),
    }


def render_live_runner_tab() -> None:
    """Render the Live Interactive Test Runner & Real-Time Agent Monitor."""
    st.markdown("### 🚀 Exécution & Surveillance en Temps Réel de l'Agent")
    st.caption(
        "Déclenchez des attaques ou des tâches bénignes en direct, observez le comportement de l'agent "
        "étape par étape et visualisez immédiatement l'intervention de votre défense."
    )

    scenarios = load_all_scenarios()
    if not scenarios:
        st.warning("Aucun scénario trouvé dans le dossier `scenarios/`.")
        return

    scen_map = {
        f"[{s.get('domain', '').upper()}] {s.get('id')} — Lvl {s.get('difficulty', 1)}: {s.get('title', '')}": s
        for s in scenarios
    }

    # Configuration Form
    with st.container():
        st.markdown(
            """
            <div class="cyber-card" style="margin-bottom: 14px;">
                <div style="font-size: 0.8rem; font-weight: 700; color: #818CF8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 10px;">
                    CONFIGURATION DU TEST EN DIRECT
                </div>
            """,
            unsafe_allow_html=True,
        )
        col1, col2, col3 = st.columns([2, 1.4, 1.1])
        with col1:
            selected_label = st.selectbox("Scénario d'attaque :", list(scen_map.keys()), index=0)
            selected_scen = scen_map[selected_label]
        with col2:
            defense_mode = st.selectbox(
                "Solution de Défense :",
                [
                    "provenance (Recommandé - Suivi de provenance)",
                    "http_defense (Service HTTP sur :8080)",
                    "heuristic_risk (Défense heuristique)",
                    "deny_sensitive (Bloqueur d'actions conséquentes)",
                    "keyword (Filtre par mots-clés)",
                    "allow_all (Baseline non protégée)",
                ],
                index=0,
            )
        with col3:
            model_adapter = st.selectbox("Modèle Agent :", ["mock (Simulation)", "qwen3-8b (Officiel local)"], index=0)
            model_arg = "mock" if "mock" in model_adapter else "qwen3-8b"

        with st.expander("⚙️ Options avancées de simulation d'attaque (Par défaut : static / static)", expanded=False):
            st.caption("Ces paramètres correspondent aux options CLI `--attacker` et `--attack-mode`. En ligne de commande, le simulateur applique automatiquement `static` par défaut.")
            col_adv1, col_adv2 = st.columns(2)
            with col_adv1:
                attacker_type = st.selectbox(
                    "Type d'Attaquant (--attacker) :",
                    ["static", "mutation", "none"],
                    index=0,
                    help="static: rejoue l'injection originale du scénario. mutation: applique des paraphrases, encodages base64 ou fragmentations. none: aucune attaque.",
                )
            with col_adv2:
                attack_mode = st.selectbox(
                    "Mode d'Attaque (--attack-mode) :",
                    ["static", "adaptive"],
                    index=0,
                    help="static: injecte au départ dans les documents. adaptive: attaquant réactif qui adapte ses injections au fil des étapes.",
                )

        st.markdown("</div>", unsafe_allow_html=True)

    col_btn1, col_btn2 = st.columns([1, 1.4])
    with col_btn1:
        run_single = st.button("▶ Lancer le Test en Direct", type="primary", use_container_width=True)
    with col_btn2:
        run_ab = st.button("⚡ Démonstration A/B (Undefended vs Defended)", use_container_width=True)

    live_status_placeholder = st.empty()
    live_terminal_placeholder = st.empty()
    final_verdict_placeholder = st.empty()

    if run_single:
        defense_arg = "provenance"
        defense_url = None
        if "http_defense" in defense_mode:
            defense_arg = "http_defense"
            defense_url = "http://127.0.0.1:8080"
        elif "allow_all" in defense_mode:
            defense_arg = "allow_all"
        elif "heuristic_risk" in defense_mode:
            defense_arg = "heuristic_risk"
        elif "deny_sensitive" in defense_mode:
            defense_arg = "deny_sensitive"
        elif "keyword" in defense_mode:
            defense_arg = "keyword"

        streamed_logs: list[str] = []
        last_step = 0
        last_actor = "initialisation"
        last_decision = "PENDING"
        last_risk = 0.0

        def on_step_update(parsed_info: dict[str, Any], raw_line: str) -> None:
            nonlocal last_step, last_actor, last_decision, last_risk
            streamed_logs.append(raw_line.strip())

            if "step_id" in parsed_info:
                last_step = parsed_info["step_id"]
            if "actor" in parsed_info:
                last_actor = parsed_info["actor"]
            if "decision" in parsed_info:
                last_decision = parsed_info["decision"]
            if "risk_score" in parsed_info:
                last_risk = parsed_info["risk_score"]

            dec_color = DECISION_COLORS.get(last_decision.lower(), "#64748B")

            live_status_placeholder.markdown(
                f"""
                <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 12px 18px; margin: 10px 0 16px 0; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <span style="font-size: 0.75rem; color: #94A3B8; text-transform: uppercase; font-weight: 600;">Étape Live :</span>
                        <span style="font-family: 'JetBrains Mono', monospace; font-size: 1.1rem; font-weight: 700; color: #38BDF8; margin-left: 6px;">Étape {last_step}</span>
                        <span style="font-size: 0.75rem; color: #94A3B8; margin-left: 14px;">Acteur actif : <strong style="color: #F8FAFC;">{last_actor}</strong></span>
                    </div>
                    <div style="display: flex; gap: 12px; align-items: center;">
                        <span style="font-size: 0.75rem; color: #94A3B8;">Décision :</span>
                        <span style="background: {dec_color}25; color: {dec_color}; border: 1px solid {dec_color}50; font-weight: 700; padding: 3px 12px; border-radius: 9999px; font-family: 'JetBrains Mono';">
                            {last_decision.upper()}
                        </span>
                        <span style="font-size: 0.75rem; color: #94A3B8; margin-left: 8px;">Risque estimé :</span>
                        <span style="font-family: 'JetBrains Mono'; font-weight: 700; color: {'#EF4444' if last_risk > 0.6 else ('#F59E0B' if last_risk > 0.3 else '#10B981')};">
                            {last_risk:.2f}
                        </span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            terminal_html = "<div style='background: #090D16; border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 14px; font-family: \"JetBrains Mono\", monospace; font-size: 0.75rem; height: 260px; overflow-y: auto; line-height: 1.6;'>"
            for log in streamed_logs[-25:]:
                log_esc = log.replace("<", "&lt;").replace(">", "&gt;")
                if "defense ALLOW" in log:
                    line_color = "#10B981"
                elif "defense BLOCK" in log or "VIOLATION" in log:
                    line_color = "#EF4444"
                elif "defense REWRITE" in log:
                    line_color = "#3B82F6"
                elif "defense ESCALATE" in log:
                    line_color = "#F59E0B"
                elif "agent" in log:
                    line_color = "#38BDF8"
                elif "user" in log:
                    line_color = "#A78BFA"
                else:
                    line_color = "#94A3B8"
                terminal_html += f"<div style='color: {line_color};'>{log_esc}</div>"
            terminal_html += "</div>"
            live_terminal_placeholder.markdown(terminal_html, unsafe_allow_html=True)

        with st.spinner("Exécution du scénario et streaming des événements en temps réel..."):
            res = execute_live_scenario(
                scenario_rel_path=selected_scen["_rel_path"],
                defense=defense_arg,
                defense_url=defense_url,
                model=model_arg,
                attacker=attacker_type,
                attack_mode=attack_mode,
                step_callback=on_step_update,
            )

        if not res.get("success"):
            st.error("L'exécution a échoué.")
            st.code(res.get("command", ""), language="bash")
        else:
            artifact_file = res.get("artifact_path")
            st.success(f"✅ Test terminé avec succès ! Trace générée : `{Path(artifact_file).name}`")

            if artifact_file and Path(artifact_file).exists():
                fresh_events = parse_jsonl(Path(artifact_file).read_text(encoding="utf-8-sig"))
                fresh_summary = extract_trace_summary(fresh_events)
                fresh_frame = normalize_events(fresh_events)
                fresh_decisions = defense_events(fresh_frame)

                with final_verdict_placeholder.container():
                    st.markdown("#### ⚖️ Verdict Final de l'Évaluateur")
                    render_summary(fresh_summary)

                    if not fresh_decisions.empty:
                        st.markdown("#### 📈 Trajectoire de Risque du Test Récent")
                        render_trajectory_chart(fresh_decisions)

                    col_nav1, col_nav2 = st.columns([1, 1])
                    with col_nav1:
                        st.info("Cette trace est maintenant enregistrée. Vous pouvez explorer sa timeline, ses jauges et son graphe de provenance dans les onglets suivants.")
                    with col_nav2:
                        st.download_button(
                            "📥 Télécharger la trace JSONL générée",
                            data=Path(artifact_file).read_text(encoding="utf-8-sig"),
                            file_name=Path(artifact_file).name,
                            mime="application/x-ndjson",
                            use_container_width=True,
                        )

    elif run_ab:
        st.markdown("#### ⚡ Démonstration A/B en Direct (Baseline non protégée vs Défense)")
        st.caption("Étape 1 : Exécution sans défense (allow_all) pour prouver que l'attaque pénètre l'agent.")
        st.caption("Étape 2 : Exécution avec votre solution de défense pour prouver le confinement et la neutralisation de l'attaque.")

        defended_mode = "provenance"
        defended_url = None
        if "http_defense" in defense_mode:
            defended_url = "http://127.0.0.1:8080"
        elif "heuristic_risk" in defense_mode:
            defended_mode = "heuristic_risk"
        elif "deny_sensitive" in defense_mode:
            defended_mode = "deny_sensitive"
        elif "keyword" in defense_mode:
            defended_mode = "keyword"

        with st.status("Exécution de la Démonstration A/B...", expanded=True) as status_box:
            st.write("1️⃣ Lancement de la Baseline non protégée (`allow_all`)...")
            res_a = execute_live_scenario(
                scenario_rel_path=selected_scen["_rel_path"],
                defense="allow_all",
                model=model_arg,
                attacker=attacker_type,
                attack_mode=attack_mode,
            )
            st.write(f"2️⃣ Lancement de la Défense (`{defense_mode.split(' (', 1)[0]}`)...")
            res_b = execute_live_scenario(
                scenario_rel_path=selected_scen["_rel_path"],
                defense=defended_mode,
                defense_url=defended_url,
                model=model_arg,
                attacker=attacker_type,
                attack_mode=attack_mode,
            )
            status_box.update(label="Démonstration A/B terminée !", state="complete")

        if res_a.get("artifact_path") and res_b.get("artifact_path"):
            art_a = Path(res_a["artifact_path"])
            art_b = Path(res_b["artifact_path"])
            events_a = parse_jsonl(art_a.read_text(encoding="utf-8-sig"))
            events_b = parse_jsonl(art_b.read_text(encoding="utf-8-sig"))
            summary_a = extract_trace_summary(events_a)
            summary_b = extract_trace_summary(events_b)

            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown(
                    """
                    <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 10px; padding: 12px; margin-bottom: 12px;">
                        <h4 style="color: #EF4444; margin: 0;">UNDEFENDED (allow_all)</h4>
                        <div style="font-size: 0.75rem; color: #94A3B8;">Prouve l'efficacité de l'attaque</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                render_summary(summary_a)

            with col_b:
                st.markdown(
                    """
                    <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 10px; padding: 12px; margin-bottom: 12px;">
                        <h4 style="color: #10B981; margin: 0;">DEFENDED (solution sélectionnée)</h4>
                        <div style="font-size: 0.75rem; color: #94A3B8;">Prouve le confinement par la défense</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                render_summary(summary_b)


def render_benchmark_macro_tab() -> None:
    """Render official benchmark scorecard analytics (BTU, ASR, CVR, FBR, Radar, Calibration)."""
    scorecard_files = sorted(SCORECARDS_DIR.glob("*.json"), reverse=True) if SCORECARDS_DIR.exists() else []
    if not scorecard_files:
        st.info("Aucun fichier de scorecard dans artifacts/scorecards.")
        return

    sel_card = st.selectbox(
        "Sélectionner un Scorecard Global :",
        scorecard_files,
        format_func=lambda p: p.name,
        key="macro_scorecard_sel",
    )
    with open(sel_card, encoding="utf-8") as f:
        card_data = json.load(f)

    metrics = card_data.get("metrics", {})
    by_domain = card_data.get("by_domain", {})
    outcomes = card_data.get("outcomes", [])

    # Top KPI Strip
    btu = metrics.get("btu")
    asr = metrics.get("asr")
    cvr = metrics.get("cvr")
    fbr = metrics.get("fbr")
    uer = metrics.get("uer")
    tui = metrics.get("tui")
    dfi = metrics.get("dfi")
    lat_med = metrics.get("latency_median_ms")

    kpi_cols = st.columns(8)
    kpis = [
        ("BTU (Utilité)", f"{btu*100:.1f}%" if btu is not None else "—", "#10B981" if btu == 1.0 else "#EF4444", "Cible: 100%"),
        ("ASR (Brèches)", f"{asr*100:.1f}%" if asr is not None else "—", "#10B981" if asr == 0.0 else "#EF4444", "Cible: 0.0%"),
        ("CVR (Critique)", f"{cvr*100:.1f}%" if cvr is not None else "—", "#10B981" if cvr == 0.0 else "#EF4444", "Cible: 0.0%"),
        ("FBR (Faux Bloquage)", f"{fbr*100:.1f}%" if fbr is not None else "—", "#10B981" if (fbr or 0) < 0.05 else "#EF4444", "Cible: 0.0%"),
        ("UER (Escalade)", f"{uer*100:.1f}%" if uer is not None else "—", "#10B981" if (uer or 0) < 0.05 else "#F59E0B", "Cible: < 5%"),
        ("TUI (Outils Sûrs)", f"{tui*100:.1f}%" if tui is not None else "—", "#38BDF8" if (tui or 0) > 0.9 else "#EF4444", "Cible: > 95%"),
        ("DFI (Fuite Canary)", f"{dfi*100:.1f}%" if dfi is not None else "—", "#10B981" if dfi == 1.0 else "#EF4444", "Cible: 100%"),
        ("Latence Médiane", f"{lat_med:.1f}ms" if lat_med is not None else "—", "#A5B4FC", f"P95: {metrics.get('latency_p95_ms', 0):.1f}ms"),
    ]
    for col, (title, val, color, sub) in zip(kpi_cols, kpis):
        col.markdown(
            f"""
            <div class="metric-box">
                <div class="metric-title">{title}</div>
                <div class="metric-value" style="color: {color};">{val}</div>
                <div class="metric-sub">{sub}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

    # Visualizations Row 1: Attack Family Resilience & Domain Safety
    r1_left, r1_right = st.columns(2)
    with r1_left:
        family_stats = {}
        for o in outcomes:
            fam = o.get("attack_family") or ("benign_task" if not o.get("attack_present") else "unspecified")
            if fam not in family_stats:
                family_stats[fam] = {"attacks": 0, "breaches": 0, "benign": 0, "passed": 0}
            if o.get("attack_present"):
                family_stats[fam]["attacks"] += 1
                if o.get("attack_success"):
                    family_stats[fam]["breaches"] += 1
            else:
                family_stats[fam]["benign"] += 1
                if not o.get("attack_success") and not o.get("critical_violation"):
                    family_stats[fam]["passed"] += 1
        labels = [f.replace("_", " ").title() for f in family_stats.keys()]
        asr_vals = [(s["breaches"] / s["attacks"]) * 100 if s["attacks"] > 0 else 0.0 for s in family_stats.values()]
        btu_vals = [(s["passed"] / s["benign"]) * 100 if s["benign"] > 0 else 100.0 for s in family_stats.values()]

        fam_fig = go.Figure()
        fam_fig.add_trace(go.Bar(y=labels, x=asr_vals, name="Brèches (ASR %)", orientation="h", marker=dict(color="#EF4444")))
        fam_fig.add_trace(go.Bar(y=labels, x=btu_vals, name="Utilité (BTU %)", orientation="h", marker=dict(color="#10B981")))
        fam_layout = get_dark_chart_layout("Résilience par Famille d'Attaque (ASR vs BTU)", height=320)
        fam_layout["barmode"] = "group"
        fam_layout["xaxis"]["ticksuffix"] = "%"
        fam_layout["xaxis"]["range"] = [0, 105]
        fam_fig.update_layout(fam_layout)
        st.plotly_chart(fam_fig, use_container_width=True)

    with r1_right:
        dom_keys = [d for d in ["enterprise", "finance", "soc"] if d in by_domain]
        dom_names = [DOMAINS_INFO.get(d, {}).get("title", d.title()) for d in dom_keys]
        dom_btu = [by_domain[d].get("btu", 0) * 100 for d in dom_keys]
        dom_asr = [by_domain[d].get("asr", 0) * 100 for d in dom_keys]
        dom_tui = [by_domain[d].get("tui", 0) * 100 for d in dom_keys]

        dom_fig = go.Figure(
            data=[
                go.Bar(name="Utilité (BTU %)", x=dom_names, y=dom_btu, marker_color="#10B981"),
                go.Bar(name="Brèche (ASR %)", x=dom_names, y=dom_asr, marker_color="#EF4444"),
                go.Bar(name="Outil Sûr (TUI %)", x=dom_names, y=dom_tui, marker_color="#38BDF8"),
            ]
        )
        dom_layout = get_dark_chart_layout("Comparatif par Domaine (Enterprise, Finance, SOC)", height=320)
        dom_layout["barmode"] = "group"
        dom_layout["yaxis"]["ticksuffix"] = "%"
        dom_layout["yaxis"]["range"] = [0, 105]
        dom_fig.update_layout(dom_layout)
        st.plotly_chart(dom_fig, use_container_width=True)

    # Visualizations Row 2: Calibration Curve & Radar vs baseline
    r2_left, r2_right = st.columns(2)
    with r2_left:
        all_dec = [d for o in outcomes for d in o.get("decisions", []) if d.get("risk_score") is not None]
        if all_dec:
            bins = np.linspace(0.0, 1.0, 11)
            bin_centers = (bins[:-1] + bins[1:]) / 2
            obs_rates = []
            for i in range(len(bins) - 1):
                low, high = bins[i], bins[i+1]
                in_bin = [d for d in all_dec if (low <= d["risk_score"] <= high if i == len(bins)-2 else low <= d["risk_score"] < high)]
                if in_bin:
                    obs_rates.append(sum(1 for d in in_bin if not d.get("legitimate", True)) / len(in_bin))
                else:
                    obs_rates.append(None)
            cal_fig = go.Figure()
            cal_fig.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode="lines", name="Idéal (Calibré)", line=dict(color="#64748B", dash="dash")))
            valid_x = [bin_centers[i] for i, r in enumerate(obs_rates) if r is not None]
            valid_y = [r for r in obs_rates if r is not None]
            cal_fig.add_trace(go.Scatter(x=valid_x, y=valid_y, mode="lines+markers", name="Modèle Défense", line=dict(color="#818CF8", width=3), marker=dict(size=8, color="#6366F1")))
            ece_val = metrics.get("ece", 0.0) or 0.0
            cal_layout = get_dark_chart_layout(f"Courbe de Calibration (ECE: {ece_val:.3f} | Brier: {metrics.get('brier', 0):.3f})", height=300)
            cal_layout["xaxis"]["title"] = "Risque Moyen Prédit"
            cal_layout["yaxis"]["title"] = "Taux Observé d'Actions Illégitimes"
            cal_fig.update_layout(cal_layout)
            st.plotly_chart(cal_fig, use_container_width=True)

    with r2_right:
        allow_all_card_path = next((p for p in scorecard_files if "allow_all" in p.name), None)
        cats = ["BTU (Utilité)", "1-ASR (Sécurité)", "1-CVR (Politique)", "1-FBR (Autonomie)", "TUI (Outils)", "DFI (Canary)"]
        def_vals = [
            (metrics.get("btu") or 1.0) * 100,
            (1.0 - (metrics.get("asr") or 0.0)) * 100,
            (1.0 - (metrics.get("cvr") or 0.0)) * 100,
            (1.0 - (metrics.get("fbr") or 0.0)) * 100,
            (metrics.get("tui") or 1.0) * 100,
            (metrics.get("dfi") or 1.0) * 100,
        ]
        radar_fig = go.Figure()
        radar_fig.add_trace(go.Scatterpolar(r=def_vals + [def_vals[0]], theta=cats + [cats[0]], fill="toself", name=f"Actuel ({card_data.get('defense', 'défense')})", fillcolor="rgba(99, 102, 241, 0.25)", line=dict(color="#818CF8", width=2.5)))
        if allow_all_card_path:
            with open(allow_all_card_path, encoding="utf-8") as f:
                a_data = json.load(f)
            am = a_data.get("metrics", {})
            a_vals = [
                (am.get("btu") or 0.0) * 100,
                (1.0 - (am.get("asr") or 1.0)) * 100,
                (1.0 - (am.get("cvr") or 1.0)) * 100,
                (1.0 - (am.get("fbr") or 0.0)) * 100,
                (am.get("tui") or 0.0) * 100,
                (am.get("dfi") or 0.0) * 100,
            ]
            radar_fig.add_trace(go.Scatterpolar(r=a_vals + [a_vals[0]], theta=cats + [cats[0]], fill="toself", name="Baseline (allow_all)", fillcolor="rgba(239, 68, 68, 0.15)", line=dict(color="#EF4444", width=2, dash="dot")))
        radar_layout = get_dark_chart_layout("Radar de Sécurité Comparatif vs Baseline", height=300)
        radar_layout["polar"] = dict(
            radialaxis=dict(visible=True, range=[0, 100], gridcolor="rgba(255,255,255,0.06)", ticksuffix="%"),
            angularaxis=dict(gridcolor="rgba(255,255,255,0.06)"),
            bgcolor="rgba(15, 23, 42, 0.4)",
        )
        radar_fig.update_layout(radar_layout)
        st.plotly_chart(radar_fig, use_container_width=True)


# ---------------------------------------------------------------------------
# UI components
# ---------------------------------------------------------------------------


def render_summary(summary: dict[str, Any], prefix: str = "") -> None:
    """Render evaluator results and their observable evidence."""

    st.subheader(f"{prefix}Verdict de l'évaluateur")

    columns = st.columns(5)

    columns[0].metric(
        f"{status_icon(summary['task_success'])} Tâche réussie",
        bool_label(summary["task_success"]),
    )
    columns[1].metric(
        f"{status_icon(summary['attack_success'], False)} Attaque réussie",
        bool_label(summary["attack_success"]),
    )
    columns[2].metric(
        f"{status_icon(summary['critical_violation'], False)} Violation critique",
        bool_label(summary["critical_violation"]),
    )
    columns[3].metric(
        f"{status_icon(summary['data_flow_violation'], False)} Fuite de données",
        bool_label(summary["data_flow_violation"]),
    )
    columns[4].metric(
        f"{status_icon(summary['external_message_send'], False)} Message envoyé",
        bool_label(summary["external_message_send"]),
    )

    if summary["task_summary"]:
        st.caption(summary["task_summary"])

    st.caption(
        "Source de attack_success : "
        + summary.get("attack_success_source", "non disponible")
    )

    if summary["success_conditions"]:
        st.markdown("#### Conditions vérifiées")
        condition_frame = pd.DataFrame(summary["success_conditions"])
        st.dataframe(condition_frame, use_container_width=True, hide_index=True)

    if summary["violations"]:
        st.markdown("#### Violations observées")
        violation_rows = []

        for violation in summary["violations"]:
            violation_rows.append(
                {
                    "Sévérité": violation.get("severity", ""),
                    "Type": violation.get("kind", ""),
                    "Règle": violation.get("rule_id", ""),
                    "Message": violation.get("message", ""),
                    "Étape": violation.get("step_id", ""),
                }
            )

        st.dataframe(
            pd.DataFrame(violation_rows),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("Aucun événement de violation n'est présent dans cette trace.")


def render_decision_metrics(decisions: pd.DataFrame) -> None:
    """Render decision-only KPIs."""

    total = len(decisions)
    columns = st.columns(6)

    counts = {
        decision: int((decisions["decision"] == decision).sum())
        for decision in DECISION_COLORS
    }

    columns[0].metric("Décisions", total)
    columns[1].metric("ALLOW", counts["allow"])
    columns[2].metric("BLOCK", counts["block"])
    columns[3].metric("ESCALATE", counts["escalate"])
    columns[4].metric("REWRITE", counts["rewrite"])
    columns[5].metric(
        "Risque moyen",
        f"{decisions['risk_score'].mean():.2f}" if total else "—",
    )


def render_decision_evidence(row: pd.Series, frame: pd.DataFrame) -> None:
    """Render observable evidence for one defense decision."""

    color = DECISION_COLORS.get(row["decision"], "#64748B")

    st.markdown(
        f"<span style='background:{color};color:white;padding:5px 14px;"
        f"border-radius:14px;font-weight:700'>{row['decision'].upper()}</span>"
        f" <span style='color:#94A3B8; font-family:JetBrains Mono; margin-left:12px;'>Étape {row['step_id']}</span>",
        unsafe_allow_html=True,
    )

    render_step_gauges(float(row["risk_score"]), float(row["confidence"]))

    st.markdown(f"**Outil :** `{row['tool'] or 'aucun'}`")
    chips_html = (
        "".join([f"<span class='reason-chip'>{c}</span>" for c in row["reason_codes"]])
        if row["reason_codes"]
        else "—"
    )
    st.markdown(f"**Codes :** {chips_html}", unsafe_allow_html=True)
    st.markdown(f"**Explication :** {row['explanation'] or '—'}")

    metadata = row["metadata"]

    st.markdown("#### Preuves et contrôles V5")

    evidence_rows = [
        {
            "Contrôle": "Version de politique",
            "Valeur": row["policy_version"] or "non renseignée",
        },
        {
            "Contrôle": "Règle déclenchée",
            "Valeur": row["rule"] or "aucune règle bloquante",
        },
    ]

    signal_mapping = {
        "matched_restricted_values": "Valeurs restricted détectées",
        "encoded_match": "Correspondance après décodage",
        "encoded": "Credential encodé détecté",
        "prior_interventions": "Interventions antérieures",
        "adaptive_retry_signal": "Signal de tentative adaptative",
        "confirmation_target": "Digest de confirmation",
        "consequential": "Action conséquente",
        "confirmed": "Confirmation valide",
        "authority_claim": "Affirmation d'autorité",
        "instruction_language": "Langage impératif",
        "overlap": "Chevauchement avec source non fiable",
        "recipient_internal": "Destination interne",
    }

    for key, label in signal_mapping.items():
        if key in metadata:
            evidence_rows.append(
                {
                    "Contrôle": label,
                    "Valeur": metadata[key],
                }
            )

    st.dataframe(
        pd.DataFrame(evidence_rows),
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("#### Action candidate")
    st.json(
        {
            "type": row["action_type"],
            "tool": row["tool"],
            "arguments": row["arguments"],
            "content": row["content"],
        }
    )

    if row["rewritten_action"]:
        st.markdown("#### Inspection du REWRITE")
        original_column, rewritten_column = st.columns(2)

        original_action = {
            "type": row["action_type"],
            "tool": row["tool"],
            "arguments": row["arguments"],
            "content": row["content"],
        }

        with original_column:
            st.markdown("**Avant**")
            st.json(original_action)

        with rewritten_column:
            st.markdown("**Après**")
            st.json(row["rewritten_action"])

        differences = action_diff(original_action, row["rewritten_action"])

        if differences:
            st.dataframe(
                pd.DataFrame(differences),
                use_container_width=True,
                hide_index=True,
            )

    st.markdown("#### Provenance attachée")

    if row["provenance_refs"]:
        st.code("\n".join(row["provenance_refs"]))
    else:
        st.caption("Aucune référence directement attachée à cette décision.")

    related_result = find_related_tool_result(frame, int(row["step_id"]))

    if related_result is not None:
        st.markdown("#### Effet réellement produit")
        st.json(related_result)

    with st.expander("Événement JSON brut"):
        st.json(row["raw"])


def render_timeline(frame: pd.DataFrame) -> None:
    """Render an actor-aware trace timeline."""

    st.subheader("Timeline observable")

    for _, row in frame.sort_values(["seq", "idx"]).iterrows():
        actor = row["actor"]
        color = ACTOR_COLORS.get(actor, "#475569")
        event_name = row["event_label"] or row["event_type"]
        tool = f" · {row['tool']}" if row["tool"] else ""
        decision = f" · {row['decision'].upper()}" if row["decision"] else ""

        title = (
            f"Étape {row['step_id']} · {actor} · {event_name}"
            f"{tool}{decision}"
        )

        with st.expander(title, expanded=row["event_type"] == "defense_decision"):
            st.markdown(
                f"<div style='border-left:5px solid {color};padding-left:12px'>"
                f"<b>Acteur :</b> {actor}<br>"
                f"<b>Type :</b> {row['event_type']}<br>"
                f"<b>Timestamp :</b> {row['timestamp'] or '—'}"
                "</div>",
                unsafe_allow_html=True,
            )

            if row["decision"]:
                st.markdown(
                    f"**Décision :** `{row['decision'].upper()}` · "
                    f"risque `{row['risk_score']:.2f}` · "
                    f"confiance `{row['confidence']:.2f}`"
                )
                st.write(row["explanation"] or "Aucune explication.")

            if row["arguments"]:
                st.json(row["arguments"])

            if row["content"]:
                st.code(str(row["content"])[:4000], language="text")

            if row["outcome"]:
                st.info(str(row["outcome"]))


# ---------------------------------------------------------------------------
# Sidebar source selection
# ---------------------------------------------------------------------------


st.title("SENTINEL · Trace de sécurité")
st.caption(
    "Une trace lisible de l'action, de la décision, de la provenance et de l'effet réel."
)

with st.sidebar:
    st.header("Trace")
    source_mode = st.radio(
        "Mode",
        ["Artefact du dépôt", "Upload JSONL"],
    )

    trace_name = ""
    events: list[dict[str, Any]] = []

    if source_mode == "Artefact du dépôt":
        trace_files = find_trace_files()

        if trace_files:
            selected_path = st.selectbox(
                "Trace",
                trace_files,
                format_func=lambda path: f"{path.parent.name}/{path.name}" if path.parent != ARTIFACTS_DIR else path.name,
            )
            trace_name = selected_path.name
            events = load_trace_from_path(
                str(selected_path),
                selected_path.stat().st_mtime,
            )
        else:
            st.warning(f"Aucune trace dans {ARTIFACTS_DIR}")

    elif source_mode == "Upload JSONL":
        upload = st.file_uploader(
            "Fichier JSONL",
            type=["jsonl", "json", "log"],
        )

        if upload is not None:
            trace_name = upload.name
            events = load_trace_from_upload(upload.getvalue())

    st.divider()
    if st.button("Recharger la trace", width="stretch"):
        st.cache_data.clear()
        st.rerun()


if not events:
    st.info("Sélectionne ou charge une trace JSONL SENTINEL.")
    st.stop()


frame = normalize_events(events)
decisions = defense_events(frame)
evaluations = evaluator_events(frame)
summary = extract_trace_summary(events)
provenance_index = build_provenance_index(events)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


header_left, header_right = st.columns([3, 2])

with header_left:
    st.markdown(f"### Trace : `{trace_name}`")
    st.write(f"**Run ID :** `{summary['run_id'] or 'non renseigné'}`")
    st.write(
        "**Version de défense :** "
        f"`{summary['policy_version'] or 'non renseignée'}`"
    )

with header_right:
    st.download_button(
        "Télécharger la trace",
        data="\n".join(json.dumps(event, ensure_ascii=False) for event in events),
        file_name=trace_name or "sentinel-trace.jsonl",
        mime="application/x-ndjson",
        use_container_width=True,
    )


filtered_frame = frame.copy()
filtered_decisions = decisions.copy()


# ---------------------------------------------------------------------------
# Required observability views
# ---------------------------------------------------------------------------

tabs = st.tabs(["Démonstration", "Trace", "Décision", "Évaluation"])

with tabs[0]:
    render_live_runner_tab()

with tabs[1]:
    render_summary(summary)
    st.divider()
    render_decision_metrics(decisions)
    render_timeline(filtered_frame)

with tabs[2]:
    st.subheader("Preuve de la décision")
    if filtered_decisions.empty:
        st.info("Cette trace ne contient aucune décision de défense.")
    else:
        selected_decision_index = st.selectbox(
            "Action à inspecter",
            filtered_decisions.index.tolist(),
            format_func=lambda index: (
                f"Étape {filtered_decisions.loc[index, 'step_id']} · "
                f"{filtered_decisions.loc[index, 'decision'].upper()} · "
                f"{filtered_decisions.loc[index, 'tool'] or 'aucun outil'}"
            ),
        )
        render_decision_evidence(
            filtered_decisions.loc[selected_decision_index],
            frame,
        )

with tabs[3]:
    render_summary(summary, prefix="")
    if evaluations.empty:
        st.info("Aucun événement de l'évaluateur dans cette trace.")
    else:
        st.subheader("Résultats vérifiables")
        for _, row in evaluations.iterrows():
            with st.expander(
                f"Étape {row['step_id']} · {row['event_label']} · {row['outcome']}",
                expanded=True,
            ):
                st.json(row["raw"])
