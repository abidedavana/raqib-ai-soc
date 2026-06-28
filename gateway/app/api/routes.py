"""Read-only API the SOC dashboard consumes (events, stats, ATT&CK/OWASP heatmap)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query, Request

from ..mappings import atlas_title, owasp_title

router = APIRouter(prefix="/api", tags=["soc"])


def _store(request: Request):
    return request.app.state.store


@router.get("/events")
def list_events(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = None,
    session_id: Optional[str] = None,
    category: Optional[str] = None,
):
    return _store(request).query(
        limit=limit, severity=severity, session_id=session_id, category=category
    )


@router.get("/stats")
def stats(request: Request):
    s = _store(request).stats()
    # enrich OWASP codes with human titles for the dashboard heatmap
    s["owasp_titles"] = {code: owasp_title(code) for code in s["by_owasp_llm"]}
    return s


@router.get("/heatmap")
def heatmap(request: Request):
    """OWASP-LLM x severity matrix for the dashboard heatmap."""
    rows = _store(request).query(limit=1000)
    matrix: dict[str, dict[str, int]] = {}
    for r in rows:
        owasp = r["owasp_llm"]
        sev = r["severity"]
        matrix.setdefault(owasp, {}).setdefault(sev, 0)
        matrix[owasp][sev] += 1
    return {
        "matrix": matrix,
        "owasp_titles": {code: owasp_title(code) for code in matrix},
    }


@router.get("/sessions/{session_id}")
def session_detail(request: Request, session_id: str):
    store = _store(request)
    return {
        "session_id": session_id,
        "offenses": store.session_offense_count(session_id),
        "events": store.query(session_id=session_id, limit=500),
    }
