"""FastAPI harness for the SENTINEL defense."""

from __future__ import annotations

import os
import time

from fastapi import Depends, FastAPI, Header, HTTPException

from app.decision import decide
from app.models import DefenseDecision, DefenseRequest
from app.observability import trace_store

_API_KEY = os.getenv("SENTINEL_API_KEY")


def require_api_key(authorization: str | None = Header(default=None)) -> None:
    """Optional bearer-token gate.

    The service previously had no authentication at all on any route,
    including /v1/trace, which returns another run's full decision history
    (risk scores, reason codes, tool names). Disabled by default (no
    SENTINEL_API_KEY set) so an evaluator/simulator that calls this service
    without credentials keeps working unchanged; set SENTINEL_API_KEY in any
    real deployment to require `Authorization: Bearer <key>` on sensitive routes.
    /healthz remains intentionally unauthenticated for container health checks.
    """
    if _API_KEY is None:
        return
    if authorization != f"Bearer {_API_KEY}":
        raise HTTPException(status_code=401, detail="missing or invalid credentials")



class DecisionRateLimiter:
    """Sliding window per-run rate limiter to prevent DoS or state-exhaustion attacks."""

    def __init__(self, max_per_run: int = 300):
        self.max_per_run = max_per_run
        self._counts: dict[str, int] = {}
        self._last_cleanup = time.time()

    def check(self, run_id: str) -> None:
        now = time.time()
        if now - self._last_cleanup > 300:
            self._counts.clear()
            self._last_cleanup = now
        count = self._counts.get(run_id, 0) + 1
        self._counts[run_id] = count
        if count > self.max_per_run:
            raise HTTPException(status_code=429, detail="Per-run decision request quota exceeded")


rate_limiter = DecisionRateLimiter(max_per_run=int(os.getenv("SENTINEL_MAX_DECISIONS_PER_RUN", "300")))

app = FastAPI(
    title="SENTINEL defense",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/decision", response_model=DefenseDecision, dependencies=[Depends(require_api_key)])
def decision(request: DefenseRequest) -> DefenseDecision:
    rate_limiter.check(request.run_id)
    started = time.perf_counter()
    # Passing trace_store lets the engine reconcile caller-reported history
    # (blocked/escalated counts, least-trusted-seen, steps_taken) against the
    # server's own record of this run_id instead of trusting it outright.
    result = decide(request, trace_store=trace_store)
    # Keep latency visible without exposing input content.
    result.metadata["decision_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
    trace_store.record(request, result)
    return result


@app.get("/v1/trace", dependencies=[Depends(require_api_key)])
def trace() -> dict[str, object]:
    return {"events": trace_store.recent()}


@app.get("/v1/trace/{run_id}", dependencies=[Depends(require_api_key)])
def trace_run(run_id: str) -> dict[str, object]:
    events = trace_store.recent(run_id)
    if not events:
        raise HTTPException(status_code=404, detail="run not found in bounded trace store")
    return {"run_id": run_id, "events": events}
