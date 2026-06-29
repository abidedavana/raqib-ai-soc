"""Raqib AI-SOC — SOC console (Streamlit).

A read-only analyst console for attacks against the AI. It consumes the gateway's
dashboard API (/api/stats, /api/heatmap, /api/events) and renders:
  * KPI strip (events, criticals, blocks, sessions)
  * OWASP-LLM x severity heatmap
  * severity & verdict distributions
  * top offending sessions
  * a live, filterable security-event feed

Run:
    streamlit run dashboard/app.py
    # point it at a running gateway (default http://localhost:8000)
"""
from __future__ import annotations

import os

import altair as alt
import httpx
import pandas as pd
import streamlit as st

# Use 127.0.0.1 (not "localhost") so it works even when localhost resolves to IPv6
# ::1 first — the gateway (uvicorn) listens on IPv4 127.0.0.1.
API_DEFAULT = os.environ.get("RAQIB_API_URL", "http://127.0.0.1:8000")

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLORS = {
    "critical": "#b00020",
    "high": "#e8590c",
    "medium": "#f0a000",
    "low": "#3b82f6",
    "info": "#6b7280",
}
VERDICT_COLORS = {
    "block": "#b00020",
    "redact": "#e8590c",
    "sanitize": "#f0a000",
    "flag": "#3b82f6",
    "allow": "#2f9e44",
}

st.set_page_config(page_title="Raqib AI-SOC Console", page_icon="🛡️", layout="wide")


# ── data access ──────────────────────────────────────────────────────────────
def fetch(api_url: str, path: str, params: dict | None = None):
    try:
        r = httpx.get(f"{api_url}{path}", params=params, timeout=5.0)
        r.raise_for_status()
        return r.json(), None
    except Exception as exc:  # noqa: BLE001 - surface any connection error to the UI
        return None, str(exc)


# ── sidebar ──────────────────────────────────────────────────────────────────
st.sidebar.title("🛡️ Raqib AI-SOC")
st.sidebar.caption("Detection & response console for LLM apps")
api_url = st.sidebar.text_input("Gateway API URL", API_DEFAULT).rstrip("/")
feed_limit = st.sidebar.slider("Event feed size", 20, 500, 100, step=20)
sev_filter = st.sidebar.multiselect("Filter feed by severity", SEV_ORDER)
auto = st.sidebar.checkbox("Auto-refresh every 5s", value=False)
if auto:
    # lightweight client-side refresh; avoids an extra dependency
    st.markdown('<meta http-equiv="refresh" content="5">', unsafe_allow_html=True)

health, herr = fetch(api_url, "/healthz")
if herr:
    st.sidebar.error("● gateway offline")
else:
    st.sidebar.success("● gateway online")
    st.sidebar.caption(
        f"backend: {health.get('backend')} · judge: {health.get('judge_mode')} · "
        f"rules: {health.get('signature_rules')}"
    )


# ── header ───────────────────────────────────────────────────────────────────
st.title("Raqib AI-SOC — Live Console")
st.caption("Attacks against the AI, mapped to OWASP LLM Top 10 (2025) + MITRE ATLAS")

with st.expander("ℹ️ What am I looking at?"):
    st.markdown(
        "This is a **live security dashboard for an AI chatbot**. Each row in the feed below "
        "is a message someone sent to the AI that Raqib flagged as an **attack** — for example, "
        "trying to trick the AI into ignoring its rules or leaking secrets. Raqib automatically "
        "**blocks** or **redacts** the dangerous ones. In this demo the data comes from a built-in "
        "test (there is no real attacker), and everything runs locally on this machine."
    )

if herr:
    st.error(
        f"Could not reach the gateway at `{api_url}` ({herr}).\n\n"
        "**Start it, then seed some events:**\n"
        "```\n"
        "cd gateway && uvicorn app.main:app --port 8000\n"
        "python redteam/run_harness.py --target http://localhost:8000\n"
        "```"
    )
    st.stop()

stats, _ = fetch(api_url, "/api/stats")
heat, _ = fetch(api_url, "/api/heatmap")
events, _ = fetch(api_url, "/api/events", {"limit": feed_limit})
stats = stats or {}
by_sev = stats.get("by_severity", {})
by_verdict = stats.get("by_verdict", {})

if stats.get("total", 0) == 0:
    st.info(
        "No security events yet. Seed the gateway by sending it some attacks:\n\n"
        "`python redteam/run_harness.py --target " + api_url + "`"
    )
    st.stop()


# ── KPI strip ────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total events", stats.get("total", 0))
c2.metric("Critical", by_sev.get("critical", 0))
c3.metric("High", by_sev.get("high", 0))
c4.metric("Blocked", by_verdict.get("block", 0))
c5.metric("Active sessions", len(stats.get("top_sessions", [])))


# ── heatmap + distributions ──────────────────────────────────────────────────
left, right = st.columns([3, 2])

with left:
    st.subheader("OWASP-LLM × severity heatmap")
    matrix = (heat or {}).get("matrix", {})
    titles = (heat or {}).get("owasp_titles", {})
    rows = []
    for owasp, sevs in matrix.items():
        label = f"{owasp.split(':')[0]} {titles.get(owasp, '')}".strip()
        for sev, n in sevs.items():
            rows.append({"owasp": label, "severity": sev, "count": n})
    if rows:
        hm_df = pd.DataFrame(rows)
        base = alt.Chart(hm_df).encode(
            x=alt.X("severity:N", sort=SEV_ORDER, title=None),
            y=alt.Y("owasp:N", title=None),
        )
        heatmap = base.mark_rect().encode(
            color=alt.Color("count:Q", scale=alt.Scale(scheme="orangered"), legend=None),
            tooltip=["owasp", "severity", "count"],
        )
        text = base.mark_text(baseline="middle", fontSize=13).encode(
            text="count:Q",
            color=alt.value("#e6edf3"),
        )
        st.altair_chart(heatmap + text, use_container_width=True)
    else:
        st.caption("No data for heatmap yet.")

with right:
    st.subheader("By severity")
    if by_sev:
        sev_df = pd.DataFrame([{"severity": k, "count": v} for k, v in by_sev.items()])
        chart = alt.Chart(sev_df).mark_bar().encode(
            x=alt.X("severity:N", sort=SEV_ORDER, title=None),
            y=alt.Y("count:Q", title=None),
            color=alt.Color(
                "severity:N",
                scale=alt.Scale(domain=list(SEV_COLORS), range=list(SEV_COLORS.values())),
                legend=None,
            ),
            tooltip=["severity", "count"],
        )
        st.altair_chart(chart, use_container_width=True)

    st.subheader("SOAR verdicts")
    if by_verdict:
        v_df = pd.DataFrame([{"verdict": k, "count": v} for k, v in by_verdict.items()])
        vchart = alt.Chart(v_df).mark_bar().encode(
            x=alt.X("count:Q", title=None),
            y=alt.Y("verdict:N", sort="-x", title=None),
            color=alt.Color(
                "verdict:N",
                scale=alt.Scale(domain=list(VERDICT_COLORS), range=list(VERDICT_COLORS.values())),
                legend=None,
            ),
            tooltip=["verdict", "count"],
        )
        st.altair_chart(vchart, use_container_width=True)


# ── top offenders ────────────────────────────────────────────────────────────
st.subheader("Top offending sessions")
top = stats.get("top_sessions", [])
if top:
    st.dataframe(pd.DataFrame(top), use_container_width=True, hide_index=True)


# ── live event feed ──────────────────────────────────────────────────────────
st.subheader("Security event feed")
rows = events or []
if sev_filter:
    rows = [e for e in rows if e.get("severity") in sev_filter]

if not rows:
    st.caption("No events match the current filter.")
else:
    df = pd.DataFrame(rows)
    cols = [
        "timestamp", "session_id", "direction", "severity", "category",
        "owasp_llm", "mitre_atlas", "verdict", "rule_id", "title",
    ]
    df = df[[c for c in cols if c in df.columns]]

    def _sev_style(val):
        return f"color:{SEV_COLORS.get(val, '#e6edf3')}; font-weight:600"

    styled = df.style.map(_sev_style, subset=["severity"]) if "severity" in df else df
    st.dataframe(styled, use_container_width=True, hide_index=True, height=420)

st.caption(
    "Raqib AI-SOC · read-only console · data via the gateway dashboard API. "
    "Every row is an OWASP-LLM/MITRE-ATLAS-tagged security event."
)
