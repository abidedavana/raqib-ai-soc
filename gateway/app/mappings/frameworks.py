"""Framework reference data: OWASP LLM Top 10 (2025) and MITRE ATLAS.

Centralising the IDs here means every detection speaks the same language as the
two frameworks an MSSP cares about, and there is exactly one place to verify the
IDs against the official sources:

  * OWASP LLM Top 10 (2025): https://genai.owasp.org/llm-top-10/
  * MITRE ATLAS matrix:      https://atlas.mitre.org/matrices/ATLAS

NOTE: ATLAS technique IDs evolve. Treat this table as the single source of
truth for the codebase and re-verify it against the live matrix before relying
on a specific sub-technique ID in a report.
"""
from __future__ import annotations

# ── OWASP LLM Top 10 — 2025 ──────────────────────────────────────────────────
OWASP_LLM: dict[str, str] = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}

# ── MITRE ATLAS techniques (subset relevant to runtime LLM attacks) ───────────
MITRE_ATLAS: dict[str, str] = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "LLM Meta Prompt Extraction",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0048": "External Harms",
    "AML.T0061": "LLM Prompt Self-Replication",
}


def owasp_title(code: str) -> str:
    return OWASP_LLM.get(code, "Unknown OWASP-LLM category")


def atlas_title(code: str) -> str:
    return MITRE_ATLAS.get(code, "Unknown ATLAS technique")


def describe(owasp_code: str, atlas_code: str) -> str:
    return f"{owasp_code} {owasp_title(owasp_code)} / {atlas_code} {atlas_title(atlas_code)}"
