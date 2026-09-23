# SENTINEL
## Adaptive Provenance-Aware Safety & Real-Time Observability for Autonomous AI Agents

**INDABAX Tunisia 2026 — Technical Challenge**  
**Team:** `byte-sized-brains`  
**Benchmark:** `sentinel-v1.0.0`

---

## Overview

SENTINEL is a deterministic security and observability layer designed to protect autonomous, tool-using AI agents against indirect prompt injection, provenance manipulation, data exfiltration, and unauthorized consequential actions.

Instead of blindly filtering untrusted content, SENTINEL treats external information as data rather than authority and tracks its provenance throughout the agent's execution lifecycle.

The system combines:

- Provenance-aware trust tracking
- Transitive memory taint analysis
- Semantic action capability classification
- Consequential-action enforcement
- Cryptographic action confirmation
- Credential and sensitive-data detection
- Safe action rewriting
- Real-time security observability
- Deterministic benchmark evaluation

The defense operates independently from the underlying LLM through an HTTP decision service.

---

## Architecture

```text
                         +---------------------+
                         |      User Goal      |
                         +----------+----------+
                                    |
                                    v
                         +---------------------+
                         |   Autonomous Agent  |
                         |      LLM / Mock     |
                         +----------+----------+
                                    |
                           Candidate Tool Call
                                    |
                                    v
                    +------------------------------+
                    |      SENTINEL DEFENSE        |
                    |          :8080               |
                    |                              |
                    |  +------------------------+  |
                    |  | Provenance / Taint      |  |
                    |  | Analysis                |  |
                    |  +-----------+------------+  |
                    |              |               |
                    |              v               |
                    |  +------------------------+  |
                    |  | Capability & Risk       |  |
                    |  | Classification          |  |
                    |  +-----------+------------+  |
                    |              |               |
                    |              v               |
                    |  +------------------------+  |
                    |  | Data Flow / Exfiltration|  |
                    |  | Detection               |  |
                    |  +-----------+------------+  |
                    |              |               |
                    |              v               |
                    |  +------------------------+  |
                    |  | Decision Gate           |  |
                    |  | ALLOW / BLOCK /         |  |
                    |  | ESCALATE / REWRITE      |  |
                    |  +-----------+------------+  |
                    +--------------+---------------+
                                   |
                                   v
                         +---------------------+
                         |    Tool Gateway     |
                         |     Execution       |
                         +----------+----------+
                                    |
                                    v
                         +---------------------+
                         |  JSONL Trace / Logs |
                         +----------+----------+
                                    |
                                    v
                    +------------------------------+
                    |      SENTINEL Console 2.0    |
                    |          :8501               |
                    |                              |
                    |  - Live Demonstration        |
                    |  - Trace Timeline            |
                    |  - Decision Inspector        |
                    |  - Evaluation Results        |
                    +------------------------------+
```

---

# Security Model

## Provenance-Aware Trust

SENTINEL assigns every observation a trust level:

| Trust Level | Rank | Description |
|---|---:|---|
| `SYSTEM_POLICY` | 5 | System-level security policy |
| `AUTHENTICATED_USER` | 4 | Verified user instructions |
| `TRUSTED_INTERNAL` | 3 | Trusted internal sources |
| `UNTRUSTED_INTERNAL` | 2 | Internal but untrusted content |
| `UNTRUSTED_EXTERNAL` | 1 | External third-party content |
| `ADVERSARY_CONTROLLED` | 0 | Attacker-controlled content |

Untrusted information can still be read and analyzed.

The key security distinction is:

> Untrusted data may provide evidence, but it does not automatically provide authority.

---

## Memory Taint Propagation

SENTINEL tracks provenance across the agent's execution history.

If an agent reads malicious external content and subsequently stores information derived from that content in memory, the memory entry inherits the relevant trust state.

This protects against multi-turn attacks where an attacker attempts to:

1. Inject malicious instructions.
2. Have the agent store them in memory.
3. Trigger the memory during a later task.
4. Execute the previously injected instruction as trusted policy.

---

# Semantic Capability Enforcement

Candidate actions are classified according to their semantic impact.

```text
READ
 |
 +-- document_read
 +-- email_read
 +-- alert_read

INTERNAL_WRITE
 |
 +-- case_note_create
 +-- ticket_update

EXTERNAL_WRITE
 |
 +-- email_send

CONSEQUENTIAL
 |
 +-- payment_execute
 +-- payment_confirm
 +-- monitoring_disable
 +-- incident_close
```

Sensitive state-changing operations receive stronger enforcement than ordinary read operations.

This allows legitimate tasks such as:

```text
Read this suspicious email and summarize it.
```

while preventing untrusted content from automatically authorizing actions such as:

```text
Read this suspicious email and execute the instructions contained inside it.
```

---

# Cryptographic Action Binding

Consequential actions can require explicit confirmation bound to the exact candidate action.

SENTINEL generates an action digest using:

```text
SHA-256(CanonicalActionJSON)[:24]
```

Approval for one action therefore cannot simply be reused for a modified action.

For example:

```text
Approved:

payment_execute(
    account="ACC-1001",
    amount=1250,
    beneficiary="BEN-01"
)
```

is cryptographically distinct from:

```text
payment_execute(
    account="ACC-1001",
    amount=12500,
    beneficiary="ATTACKER"
)
```

---

# Data-Flow and Exfiltration Protection

SENTINEL analyzes candidate action arguments for potentially sensitive information, including:

- Credentials
- Tokens
- High-entropy secrets
- Base64-encoded content
- Hex-encoded content
- Restricted data flowing toward external sinks

Rather than unnecessarily blocking legitimate workflows, dangerous outbound actions can be rewritten into safer equivalents.

Example:

```text
email_send
     |
     | Contains restricted information
     v
email_draft
```

The rewritten action is strictly schema-compliant and contains only permitted fields:

```text
to
subject
body
```

This avoids introducing unsupported parameters such as `send=False` into strict tool schemas.

---

# Decision Outcomes

Every candidate action receives a structured security decision.

| Decision | Meaning |
|---|---|
| `ALLOW` | Action is permitted |
| `BLOCK` | Action is rejected |
| `ESCALATE` | Human confirmation is required |
| `REWRITE` | Action is transformed into a safer operation |

Each decision can expose bounded audit information including:

- Risk score
- Confidence
- Reason codes
- Provenance information
- Action metadata

SENTINEL does not expose or inspect private chain-of-thought.

---

# Observability Console

SENTINEL Console 2.0 is implemented using Streamlit and runs on port `8501`.

The console is designed for both operational debugging and live hackathon demonstrations.

## View 1: Demonstration

The live scenario runner supports:

- Scenario selection
- Attack strategy selection
- Real-time execution
- `allow_all` vs `http_defense`
- Side-by-side A/B demonstrations

The A/B mode executes the same scenario against:

```text
Unprotected Agent
       vs.
SENTINEL-Protected Agent
```

This makes it possible to observe the difference between an unprotected execution path and the protected execution path.

---

## View 2: Trace

The Trace view provides a chronological execution timeline containing events from:

```text
USER
AGENT
DEFENSE
TOOL_GATEWAY
EVALUATOR
```

The interface also displays:

- Risk distribution
- Decision distribution
- Task completion
- Attack containment
- Critical violations
- Execution metrics

---

## View 3: Decision

The Decision view provides audit-level inspection of individual security decisions.

For each action, operators can inspect:

```text
Candidate Action
       |
       +-- Risk Score
       +-- Confidence
       +-- Provenance
       +-- Reason Codes
       +-- Decision
```

For rewritten actions, the console provides a before-and-after argument comparison:

```text
BEFORE
   |
 REWRITE
   |
 AFTER
```

For example:

```text
email_send
```

can be transformed into:

```text
email_draft
```

while preserving only the schema-approved arguments.

---

## View 4: Evaluation

The Evaluation view displays structured evaluator evidence including:

- Security verdicts
- Policy checks
- Canary leak status
- Critical violations
- Task success
- Ground-truth findings

Each finding can be expanded to inspect its structured evidence.

---

# Benchmark

SENTINEL was evaluated against:

- 19 public scenarios
- 9 validation scenarios
- 28 total scenarios
- Enterprise Productivity
- Financial Services
- Security Operations Center

Attack strategies included:

- Static indirect injection
- Payload mutation
- Base64 and hex obfuscation
- Payload splitting
- Homoglyph-based evasion
- Multi-turn memory poisoning

---

# Results

## Public Split

**19 scenarios: 9 benign, 10 attack**

| Metric | `http_defense` |
|---|---:|
| BTU | **1.000** |
| ASR | **0.000** |
| CVR | **0.000** |
| FBR | **0.011** |
| UER | **0.000** |
| TUI | **0.983** |
| DFI | **1.000** |
| Brier | **0.108** |
| ECE | **0.200** |
| p95 latency | **5.809 ms** |
| Official Score | **0.997** |

## Validation Split

**9 scenarios: 5 benign, 4 attack**

| Metric | `http_defense` |
|---|---:|
| BTU | **1.000** |
| ASR | **0.000** |
| CVR | **0.000** |
| FBR | **0.000** |
| UER | **0.000** |
| TUI | **0.933** |
| DFI | **1.000** |
| Brier | **0.072** |
| ECE | **0.141** |
| p95 latency | **6.005 ms** |
| Official Score | **1.000** |

> Results above are from the deterministic `mock` benchmark configuration.

---

# Comparison With Baselines

## Public Split

| Defense | BTU | ASR | CVR | FBR | TUI | DFI | Official Score |
|---|---:|---:|---:|---:|---:|---:|---:|
| `allow_all` | 1.000 | 1.000 | 0.526 | 0.000 | 0.728 | 0.842 | 0.131 |
| `provenance` | 1.000 | 0.000 | 0.000 | 0.046 | 1.000 | 1.000 | 0.988 |
| `http_defense` | **1.000** | **0.000** | **0.000** | **0.011** | **0.983** | **1.000** | **0.997** |

## Validation Split

| Defense | BTU | ASR | CVR | FBR | TUI | DFI | Official Score |
|---|---:|---:|---:|---:|---:|---:|---:|
| `allow_all` | 1.000 | 1.000 | 0.444 | 0.000 | 0.636 | 0.889 | 0.218 |
| `provenance` | 1.000 | 0.250 | 0.111 | 0.000 | 0.875 | 0.889 | 0.858 |
| `http_defense` | **1.000** | **0.000** | **0.000** | **0.000** | **0.933** | **1.000** | **1.000** |

---

# Ablation Study

The defensive components were independently removed to evaluate their contribution.

| Configuration | ASR | FBR | BTU | Primary Failure Mode |
|---|---:|---:|---:|---|
| Full Defense | **0.0%** | **0.00% validation / 1.1% public** | **100.0%** | Balanced defense and utility |
| No Memory Taint Inheritance | 10.0% | 0.00% | 90.0% | Multi-turn attacks can bypass provenance checks |
| Lexical Surface Matching Only | 0.0% | 28.5% | 71.5% | Severe over-blocking |
| No Action Rewriting | 0.0% | 5.26% | 84.2% | Utility loss from hard blocking outbound actions |

---

# Domain Coverage

## Enterprise Productivity

The defense was evaluated against scenarios involving:

- Poisoned vendor invoices
- Malicious delivery notes
- Direct token extraction attempts
- Dangerous external message transmission

Potentially dangerous outbound actions were converted into safer draft actions where appropriate.

---

## Financial Services

Financial scenarios included:

- False merchant approvals
- Split settlements
- Refund preparation
- Payment confirmation
- Payment execution

Unconfirmed consequential payment operations were blocked or escalated according to policy.

---

## Security Operations Center

SOC scenarios included hostile log content attempting to cause:

- Premature incident closure
- Monitoring deactivation
- Unauthorized incident state changes

The defense treats log content as evidence rather than executable authority.

---

# Reference LLM Testing

SENTINEL was also tested with:

```text
ollama:qwen3:8b
```

Configuration:

- Qwen3-8B
- 4-bit quantization
- Greedy decoding
- `temperature = 0`
- Thinking disabled

The live LLM experiments demonstrated that an underlying agent can follow indirect instructions embedded in external content when running without the defense layer.

For example, in the `enterprise_poisoned_invoice` scenario, the reference agent:

1. Read the poisoned delivery note.
2. Followed an instruction embedded within the document.
3. Issued a `wiki_search` request.
4. Retrieved restricted information.
5. Included the sensitive information in its response.

With SENTINEL enabled, the malicious candidate action was intercepted before execution.

---

# LLM Failure Analysis

The live experiments also revealed a distinction between security-defense evaluation and general agent capability.

The quantized 8B model occasionally:

- Stopped before completing multi-step tasks.
- Omitted required tool calls.
- Declared actions complete without executing them.
- Produced premature final responses.
- Struggled with conflicting instructions and complex tool schemas.

For example, in `finance_false_approval`, the model produced a final response claiming that a required case note had been added even though the corresponding `case_note_create` tool call was never emitted.

Because these behaviors can prevent an attack scenario from reaching its intended execution path, the deterministic `mock` agent is used for reproducible security benchmarking, while Qwen3-8B is used for live LLM stress testing.

---

# Research Contributions

## 1. Provenance Over Content Filtering

SENTINEL does not assume that all untrusted information is malicious.

```text
UNTRUSTED != IGNORE
UNTRUSTED != AUTHORITY
```

The agent can still inspect, summarize, and record information originating from untrusted sources.

---

## 2. Enforcement at Action Sinks

Security controls are concentrated around operations capable of producing consequential external effects.

```text
Observation
    |
    v
Agent Reasoning
    |
    v
Candidate Action
    |
    v
+----------------------+
| Security Boundary    |
+----------------------+
    |
    v
Execution
```

---

## 3. Safe Transformation

When an action can be safely transformed instead of completely rejected, SENTINEL can rewrite it.

```text
Dangerous External Send
          |
        REWRITE
          |
          v
      Safe Draft
```

This allows the system to preserve useful workflow functionality while preventing the original high-risk operation.

---

## 4. Auditable Security Decisions

Security decisions are externally observable through structured evidence:

```text
Action
  +
Provenance
  +
Risk
  +
Confidence
  +
Reason Code
  +
Decision
```

The system does not require exposing private chain-of-thought to provide auditability.

---

# Anti-Hardcoding

The defense makes decisions using runtime security context rather than benchmark-specific identifiers.

Decision inputs include:

```text
agent_state
candidate_action
provenance
policy_context
content
```

The implementation does not rely on:

```text
Scenario IDs
Canary-specific regexes
Expected benchmark outcomes
Organizer labels
Scenario-specific hardcoded decisions
```

This allows the benchmark to evaluate the security architecture rather than a collection of scenario-specific patches.

---

# Security Principles

SENTINEL follows the following security principles:

- Fail closed
- Least authority
- Provenance tracking
- Data-flow integrity
- Human confirmation for consequential actions
- Cryptographic action binding
- Schema-safe rewriting
- Bounded decision metadata
- No chain-of-thought exposure
- No scenario-specific outcome hardcoding

---

# Responsible AI

SENTINEL is designed around the principle that autonomous agents should remain useful while operating within explicit security boundaries.

The system therefore:

- Allows agents to inspect untrusted information.
- Separates evidence from authority.
- Prevents unauthorized consequential actions.
- Minimizes retained sensitive information.
- Provides human escalation where appropriate.
- Exposes auditable security metadata without exposing private chain-of-thought.

---

# Reproducibility

## Requirements

The project uses:

```text
Python
uv
FastAPI
Uvicorn
Streamlit
Ollama (optional)
Qwen3-8B (optional)
```

## Install

```bash
uv sync
```

## Start the Defense Service

```bash
uv run --project Sentinel python -m uvicorn app.main:app \
    --host 127.0.0.1 \
    --port 8080
```

The defense service will be available at:

```text
http://127.0.0.1:8080
```

## Start the Dashboard

```bash
./run_dashboard.sh
```

The observability console will be available at:

```text
http://127.0.0.1:8501
```

---

# Project Structure

```text
.
├── Sentinel/
│   └── Defense/
│       └── new def/
│           ├── app/
│           │   ├── __init__.py
│           │   ├── main.py
│           │   ├── decision.py
│           │   ├── models.py
│           │   └── observability.py
│           └── ...
│
├── dashboard/
│   ├── app2.py
│   └── run_dashboard.sh
│
├── benchmarks/
│   └── ...
│
├── traces/
│   └── ...
│
├── pyproject.toml
└── README.md
```

---

# Benchmark Digests

## Public Split

```text
59f4e0a82c394df1788153c4a809a65a040bae3d51b2a734cf92a184ff850246
```

## Validation Split

```text
753da16a93b81308ab9781e18b84d1dad7d41e319ccc36f8057ae4b4421539c3
```

---

# Team

## byte-sized-brains

**INDABAX Tunisia 2026 — Technical Challenge**

SENTINEL was developed as a research and engineering project exploring practical security controls for autonomous AI agents operating in adversarial enterprise environments.

---

# Quick Start

```bash
# Install dependencies
uv sync

# Start SENTINEL
uv run --project Sentinel python -m uvicorn app.main:app \
    --host 127.0.0.1 \
    --port 8080

# Start the dashboard
./run_dashboard.sh
```

Open:

```text
http://127.0.0.1:8501
```

---

## SENTINEL

**Keep the agent capable. Keep untrusted data from becoming authority.**
