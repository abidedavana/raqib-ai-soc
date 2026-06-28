"""Signature layer — the cheap, deterministic first tier of defence in depth.

Loads the version-controlled YAML rules (detection-as-code) and matches them
against text with compiled regexes. No model call, runs on every prompt.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import yaml

from ..models import Direction, Finding, Severity

RULES_PATH = Path(__file__).parent / "rules" / "signatures.yaml"


class SignatureRule:
    """One compiled detection rule from signatures.yaml."""

    def __init__(self, raw: dict):
        self.id: str = raw["id"]
        self.category: str = raw["category"]
        self.title: str = raw["title"]
        self.severity: Severity = Severity(raw["severity"])
        self.confidence: float = float(raw["confidence"])
        self.owasp_llm: str = raw["owasp_llm"]
        self.mitre_atlas: str = raw["mitre_atlas"]
        self.direction: Direction = Direction(raw.get("direction", "inbound"))
        self.patterns: list[re.Pattern] = [re.compile(p) for p in raw["patterns"]]

    def match(self, text: str) -> Optional[Finding]:
        for pattern in self.patterns:
            m = pattern.search(text)
            if m:
                evidence = (m.group(0) or "")[:200]
                return Finding(
                    detector="signature",
                    rule_id=self.id,
                    category=self.category,
                    title=self.title,
                    severity=self.severity,
                    confidence=self.confidence,
                    owasp_llm=self.owasp_llm,
                    mitre_atlas=self.mitre_atlas,
                    evidence=f"matched /{pattern.pattern[:60]}/ -> '{evidence}'",
                )
        return None


class SignatureEngine:
    def __init__(self, rules_path: Path = RULES_PATH):
        self.rules_path = rules_path
        self.rules: list[SignatureRule] = []
        self.load()

    def load(self) -> None:
        with open(self.rules_path, "r", encoding="utf-8") as fh:
            raw_rules = yaml.safe_load(fh) or []
        self.rules = [SignatureRule(r) for r in raw_rules]

    def scan(self, text: str, direction: Direction = Direction.INBOUND) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            if rule.direction != direction:
                continue
            f = rule.match(text)
            if f:
                findings.append(f)
        return findings

    @property
    def rule_count(self) -> int:
        return len(self.rules)
