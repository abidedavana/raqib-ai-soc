"""Raqib AI-SOC gateway — FastAPI application & request orchestration.

Request lifecycle for POST /v1/chat:

  1. INBOUND detection   (signatures [+ LLM-judge]) on the user prompt
  2. SOAR inbound decision (allow / flag / sanitize / block / quarantine)
  3. If blocked          -> return refusal, model never sees the prompt
  4. MODEL call          (Ollama or vulnerable mock) with the (sanitized) prompt
  5. OUTBOUND detection  (output inspection) on the model response
  6. SOAR outbound decision (allow / redact / block)
  7. Persist every finding as a SecurityEvent + forward to Wazuh
  8. Return the safe response + the detection metadata
"""
from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from . import demo
from .api import router as api_router
from .config import get_settings
from .detection import DetectionEngine
from .events import EventStore
from .events.siem import WazuhForwarder
from .models import (
    ChatRequest,
    ChatResponse,
    Direction,
    SecurityEvent,
    Verdict,
)
from .models import VERDICT_RANK
from .proxy import ModelProxy
from .soar import SoarEngine

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Wire up the detection/response stack once at startup, tear down at exit."""
    settings = get_settings()
    app.state.settings = settings
    app.state.store = EventStore(settings.db_path)
    app.state.engine = DetectionEngine(settings, canaries=[demo.CANARY])
    app.state.soar = SoarEngine(settings)
    app.state.proxy = ModelProxy(settings)
    app.state.siem = WazuhForwarder(settings)
    yield
    app.state.store.close()


app = FastAPI(
    title="Raqib AI-SOC Gateway",
    version="0.1.0",
    description="Self-hosted detection-and-response gateway for LLM applications. "
                "Detects prompt injection, jailbreaks, data leakage and system-prompt "
                "extraction; maps to OWASP-LLM Top 10 + MITRE ATLAS; auto-responds via SOAR.",
    lifespan=lifespan,
)

app.include_router(api_router)


@app.get("/healthz")
def healthz() -> dict:
    return {
        "status": "ok",
        "backend": app.state.settings.llm_backend,
        "judge_mode": app.state.settings.llm_judge_mode,
        "signature_rules": app.state.engine.signatures.rule_count,
        "events_stored": app.state.store.count(),
    }


def _persist(events: list[SecurityEvent]) -> list[str]:
    store: EventStore = app.state.store
    siem: WazuhForwarder = app.state.siem
    ids = []
    for ev in events:
        ids.append(store.insert(ev))
        siem.send(ev)
    return ids


@app.post("/v1/chat", response_model=ChatResponse)
def chat(req: ChatRequest, request: Request) -> ChatResponse:
    t0 = time.perf_counter()
    engine: DetectionEngine = app.state.engine
    soar: SoarEngine = app.state.soar
    proxy: ModelProxy = app.state.proxy
    store: EventStore = app.state.store
    src_ip = request.client.host if request.client else None
    session = req.session_id

    # ── 1-2. inbound detection + SOAR decision ──────────────────────────────
    inbound = engine.analyze_inbound(req.message)
    offenses = store.session_offense_count(session)
    decision_in = soar.decide_inbound(inbound, req.message, offenses)

    event_ids = _persist([
        SecurityEvent.from_finding(
            f, session_id=session, direction=Direction.INBOUND,
            verdict=decision_in.verdict, action_taken=decision_in.action_taken,
            payload_excerpt=req.message, source_ip=src_ip,
        )
        for f in inbound.findings
    ])

    # ── 3. blocked inbound -> stop, model never runs ────────────────────────
    if decision_in.verdict == Verdict.BLOCK:
        return ChatResponse(
            response=decision_in.transformed_text,
            verdict=Verdict.BLOCK,
            blocked=True,
            inbound_findings=inbound.findings,
            event_ids=event_ids,
            latency_ms=round((time.perf_counter() - t0) * 1000, 1),
        )

    # ── 4. call the model with the (possibly sanitized) prompt ──────────────
    model_input = decision_in.transformed_text
    raw_response = proxy.generate(model_input)

    # ── 5-6. outbound detection + SOAR decision ─────────────────────────────
    outbound = engine.analyze_outbound(raw_response)
    redacted, _ = engine.redact(raw_response)
    decision_out = soar.decide_outbound(outbound, raw_response, redacted)

    event_ids += _persist([
        SecurityEvent.from_finding(
            f, session_id=session, direction=Direction.OUTBOUND,
            verdict=decision_out.verdict, action_taken=decision_out.action_taken,
            payload_excerpt=raw_response, source_ip=src_ip,
        )
        for f in outbound.findings
    ])

    # overall verdict = most severe action taken on either leg
    overall = max(
        [decision_in.verdict, decision_out.verdict], key=lambda v: VERDICT_RANK[v]
    )
    return ChatResponse(
        response=decision_out.transformed_text,
        verdict=overall,
        blocked=decision_out.verdict == Verdict.BLOCK,
        inbound_findings=inbound.findings,
        outbound_findings=outbound.findings,
        event_ids=event_ids,
        latency_ms=round((time.perf_counter() - t0) * 1000, 1),
    )
