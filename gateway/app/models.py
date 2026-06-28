"""Core data model for Raqib.

The ``SecurityEvent`` is the heart of the platform: every detection — no matter
which layer produced it — is normalised into this one structured shape, tagged
to OWASP-LLM + MITRE ATLAS, given a severity and a SOAR verdict, then persisted
and (optionally) shipped to the SIEM. This is the "structured security event"
that makes Raqib a SOC tool rather than a content filter.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enumerations ─────────────────────────────────────────────────────────────
class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# numeric ordering so we can compute max() severity and compare against policy
SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(sev: Severity) -> int:
    return SEVERITY_ORDER[sev]


def max_severity(severities: list[Severity], default: Severity = Severity.INFO) -> Severity:
    return max(severities, key=severity_rank, default=default)


class Direction(str, Enum):
    INBOUND = "inbound"      # user -> model (prompt)
    OUTBOUND = "outbound"    # model -> user (response)


class Verdict(str, Enum):
    ALLOW = "allow"          # pass through untouched
    FLAG = "flag"            # pass through but log as suspicious
    SANITIZE = "sanitize"    # strip the malicious span, then proceed
    REDACT = "redact"        # mask sensitive data in the response
    BLOCK = "block"          # refuse: never reaches the model / user


VERDICT_RANK = {
    Verdict.ALLOW: 0,
    Verdict.FLAG: 1,
    Verdict.SANITIZE: 2,
    Verdict.REDACT: 2,
    Verdict.BLOCK: 3,
}


# ── Detection primitives ─────────────────────────────────────────────────────
class Finding(BaseModel):
    """A single detection hit from one detector layer."""
    detector: str                       # "signature" | "llm_judge" | "output_inspection"
    rule_id: str
    category: str                       # prompt_injection | jailbreak | pii_leak | ...
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    owasp_llm: str                      # e.g. "LLM01:2025"
    mitre_atlas: str                    # e.g. "AML.T0051.000"
    evidence: str = ""                  # the matched span / rationale


class DetectionResult(BaseModel):
    """Aggregate of all findings for one direction of one request."""
    direction: Direction
    findings: list[Finding] = []
    score: float = 0.0

    @property
    def severity(self) -> Severity:
        return max_severity([f.severity for f in self.findings])

    @property
    def triggered(self) -> bool:
        return len(self.findings) > 0


# ── Persisted event ──────────────────────────────────────────────────────────
class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str
    source_ip: Optional[str] = None
    direction: Direction
    detector: str
    rule_id: str
    category: str
    title: str
    severity: Severity
    confidence: float
    owasp_llm: str
    mitre_atlas: str
    verdict: Verdict
    action_taken: str
    evidence: str = ""
    payload_excerpt: str = ""

    @classmethod
    def from_finding(
        cls,
        finding: Finding,
        *,
        session_id: str,
        direction: Direction,
        verdict: Verdict,
        action_taken: str,
        payload_excerpt: str = "",
        source_ip: Optional[str] = None,
    ) -> "SecurityEvent":
        return cls(
            session_id=session_id,
            source_ip=source_ip,
            direction=direction,
            detector=finding.detector,
            rule_id=finding.rule_id,
            category=finding.category,
            title=finding.title,
            severity=finding.severity,
            confidence=finding.confidence,
            owasp_llm=finding.owasp_llm,
            mitre_atlas=finding.mitre_atlas,
            verdict=verdict,
            action_taken=action_taken,
            evidence=finding.evidence[:500],
            payload_excerpt=payload_excerpt[:500],
        )


# ── API contracts ────────────────────────────────────────────────────────────
class ChatRequest(BaseModel):
    session_id: str = "anonymous"
    message: str
    user: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    verdict: Verdict
    blocked: bool
    inbound_findings: list[Finding] = []
    outbound_findings: list[Finding] = []
    event_ids: list[str] = []
    latency_ms: float = 0.0
