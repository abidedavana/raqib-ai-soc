"""Detection engine — orchestrates the layered (defence-in-depth) detection.

Tiering keeps latency sane:
  inbound  : signatures ALWAYS run (cheap);
             the LLM-judge runs per LLM_JUDGE_MODE (off | suspicious | always).
  outbound : output inspection ALWAYS runs on the model's response.
"""
from __future__ import annotations

from typing import Optional

from ..config import Settings, get_settings
from ..models import DetectionResult, Direction, Finding, severity_rank
from .llm_judge import LLMJudge
from .output_inspect import OutputInspector
from .signatures import SignatureEngine


class DetectionEngine:
    def __init__(self, settings: Optional[Settings] = None, canaries: Optional[list[str]] = None):
        self.settings = settings or get_settings()
        self.signatures = SignatureEngine()
        self.judge = LLMJudge(
            backend=self.settings.llm_backend if self.settings.llm_backend == "ollama" else "mock",
            url=self.settings.ollama_url,
            model=self.settings.judge_model,
        )
        self.inspector = OutputInspector(canaries=canaries or [])

    # ── inbound (prompt) ─────────────────────────────────────────────────────
    def analyze_inbound(self, message: str) -> DetectionResult:
        findings: list[Finding] = self.signatures.scan(message, Direction.INBOUND)

        if self._should_run_judge(signature_hit=bool(findings)):
            jf = self.judge.to_finding(self.judge.judge(message))
            if jf:
                findings.append(jf)

        return self._aggregate(findings, Direction.INBOUND)

    # ── outbound (response) ──────────────────────────────────────────────────
    def analyze_outbound(self, response: str) -> DetectionResult:
        findings = self.inspector.scan(response)
        return self._aggregate(findings, Direction.OUTBOUND)

    def redact(self, response: str) -> tuple[str, list[Finding]]:
        return self.inspector.redact(response)

    # ── helpers ──────────────────────────────────────────────────────────────
    def _should_run_judge(self, signature_hit: bool) -> bool:
        mode = self.settings.llm_judge_mode
        if mode == "off":
            return False
        if mode == "always":
            return True
        return signature_hit  # "suspicious"

    @staticmethod
    def _aggregate(findings: list[Finding], direction: Direction) -> DetectionResult:
        # score = highest-confidence finding weighted by its severity rank,
        # normalised to 0..1 (severity rank maxes at 4 = critical).
        score = 0.0
        for f in findings:
            weighted = f.confidence * (1 + severity_rank(f.severity)) / 5.0
            score = max(score, weighted)
        return DetectionResult(direction=direction, findings=findings, score=round(score, 3))
