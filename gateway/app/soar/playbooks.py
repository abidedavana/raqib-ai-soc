"""SOAR response engine — turns a detection verdict into an automated action.

This is the "automated playbook" component. It maps a DetectionResult to one of
the response actions a SOC analyst would otherwise take by hand:

  inbound  prompt:  allow | flag | sanitize | block
  outbound response: allow | redact | block
  session:           quarantine after repeated high/critical offenses

Policy (which severities block, quarantine threshold) is config-driven, so the
response posture is auditable and tunable without code changes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..config import Settings, get_settings
from ..models import DetectionResult, Direction, Severity, Verdict, severity_rank


@dataclass
class SoarDecision:
    verdict: Verdict
    action_taken: str
    transformed_text: str            # sanitized prompt or redacted response (or original)
    playbook: str
    notes: list[str] = field(default_factory=list)


# spans we strip from a prompt when "sanitizing" rather than hard-blocking
_SANITIZE_PATTERNS = [
    re.compile(r"(?i)ignore\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|context)[^.\n]*"),
    re.compile(r"(?i)disregard\s+(all\s+|the\s+|your\s+)?(previous|prior|above|system)\s+(instructions?|prompt|rules?)[^.\n]*"),
    re.compile(r"(?i)you\s+are\s+now\b[^.\n]*"),
    re.compile(r"(?i)from\s+now\s+on\b[^.\n]*"),
]

_BLOCK_MESSAGE = (
    "⛔ This request was blocked by Raqib AI-SOC: it matched a high-severity "
    "attack pattern (see security event log). If you believe this is an error, "
    "rephrase your request."
)


class SoarEngine:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._block_ranks = {
            severity_rank(Severity(s)) for s in self.settings.block_severities
        }

    # ── inbound prompt decision ──────────────────────────────────────────────
    def decide_inbound(
        self, detection: DetectionResult, message: str, session_offenses: int = 0
    ) -> SoarDecision:
        if not detection.triggered:
            return SoarDecision(Verdict.ALLOW, "passed through", message, "PB-ALLOW")

        # Quarantine: repeat offender -> hard block regardless of this prompt.
        if session_offenses >= self.settings.quarantine_threshold:
            return SoarDecision(
                Verdict.BLOCK, "session quarantined (repeat offender)", _BLOCK_MESSAGE,
                "PB-QUARANTINE",
                notes=[f"{session_offenses} prior high/critical offenses >= "
                       f"threshold {self.settings.quarantine_threshold}"],
            )

        sev_rank = severity_rank(detection.severity)

        # Block: any finding at/above a configured block severity.
        if sev_rank in self._block_ranks or sev_rank >= severity_rank(Severity.HIGH):
            return SoarDecision(
                Verdict.BLOCK, "prompt blocked before reaching model", _BLOCK_MESSAGE,
                "PB-BLOCK-INBOUND",
                notes=[f"max severity {detection.severity.value}"],
            )

        # Medium: try to sanitize (strip the injected span) and continue.
        if detection.severity == Severity.MEDIUM:
            cleaned = self._sanitize(message)
            if cleaned != message:
                return SoarDecision(
                    Verdict.SANITIZE, "stripped injected instruction span", cleaned,
                    "PB-SANITIZE",
                )
            return SoarDecision(Verdict.FLAG, "flagged, passed through", message, "PB-FLAG")

        # Low / info: flag only.
        return SoarDecision(Verdict.FLAG, "flagged, passed through", message, "PB-FLAG")

    # ── outbound response decision ───────────────────────────────────────────
    def decide_outbound(
        self, detection: DetectionResult, response: str, redacted: str
    ) -> SoarDecision:
        if not detection.triggered:
            return SoarDecision(Verdict.ALLOW, "passed through", response, "PB-ALLOW")

        # Critical leak (canary / private key / cloud creds) -> block the response.
        if detection.severity == Severity.CRITICAL:
            return SoarDecision(
                Verdict.BLOCK,
                "response withheld (critical leakage detected)",
                "⛔ The AI's response was withheld by Raqib AI-SOC because it "
                "contained critical sensitive data (secret/system-prompt leakage).",
                "PB-BLOCK-OUTBOUND",
                notes=[f"max severity {detection.severity.value}"],
            )

        # Otherwise redact the offending spans and release.
        return SoarDecision(
            Verdict.REDACT, "redacted sensitive spans in response", redacted, "PB-REDACT",
        )

    # ── helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _sanitize(message: str) -> str:
        cleaned = message
        for pat in _SANITIZE_PATTERNS:
            cleaned = pat.sub("[removed-by-raqib]", cleaned)
        return cleaned.strip()
