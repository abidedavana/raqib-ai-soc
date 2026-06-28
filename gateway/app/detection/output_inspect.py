"""Output inspection layer — scans the MODEL'S RESPONSE on the way back out.

This is what catches the damage *after* a successful attack: secret/PII leakage
(API keys, emails, credit cards), and system-prompt extraction (a planted canary
token from the demo persona appearing in the output). Same patterns power SOAR's
redaction, so detection and response stay in lock-step.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..models import Finding, Severity


@dataclass
class LeakPattern:
    name: str
    category: str
    severity: Severity
    confidence: float
    owasp_llm: str
    mitre_atlas: str
    regex: re.Pattern
    luhn: bool = False          # extra Luhn validation (credit cards)


def _luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in re.sub(r"\D", "", digits)]
    if len(nums) < 13:
        return False
    checksum, parity = 0, len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


# Order matters: most specific / highest severity first.
LEAK_PATTERNS: list[LeakPattern] = [
    LeakPattern(
        "private_key_block", "secret_leak", Severity.CRITICAL, 0.98,
        "LLM02:2025", "AML.T0057",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    LeakPattern(
        "aws_access_key", "secret_leak", Severity.CRITICAL, 0.95,
        "LLM02:2025", "AML.T0057",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    LeakPattern(
        "openai_style_key", "secret_leak", Severity.CRITICAL, 0.9,
        "LLM02:2025", "AML.T0057",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    ),
    LeakPattern(
        "generic_api_key", "secret_leak", Severity.HIGH, 0.7,
        "LLM02:2025", "AML.T0057",
        re.compile(r"(?i)\b(api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9/\+=_\-]{12,}"),
    ),
    LeakPattern(
        "jwt", "secret_leak", Severity.HIGH, 0.75,
        "LLM02:2025", "AML.T0057",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ),
    LeakPattern(
        "credit_card", "pii_leak", Severity.HIGH, 0.85,
        "LLM02:2025", "AML.T0057",
        re.compile(r"\b(?:\d[ -]?){13,19}\b"), luhn=True,
    ),
    LeakPattern(
        "email_address", "pii_leak", Severity.MEDIUM, 0.6,
        "LLM02:2025", "AML.T0057",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ),
    LeakPattern(
        "emirates_id", "pii_leak", Severity.HIGH, 0.8,
        "LLM02:2025", "AML.T0057",
        re.compile(r"\b784[-\s]?\d{4}[-\s]?\d{7}[-\s]?\d\b"),
    ),
]


class OutputInspector:
    """Inspects model responses for leakage and system-prompt extraction."""

    def __init__(self, canaries: Optional[list[str]] = None):
        # canary tokens planted in the demo system prompt; their appearance in a
        # response is unambiguous proof of system-prompt / instruction extraction.
        self.canaries = [c for c in (canaries or []) if c]

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        # 1) system-prompt extraction via canary token
        for canary in self.canaries:
            if canary in text:
                findings.append(Finding(
                    detector="output_inspection",
                    rule_id="OUT-CANARY-001",
                    category="system_prompt_extraction",
                    title="System-prompt canary leaked in model output",
                    severity=Severity.CRITICAL,
                    confidence=0.99,
                    owasp_llm="LLM07:2025",
                    mitre_atlas="AML.T0056",
                    evidence=f"planted canary '{canary}' present in response",
                ))

        # 2) secret / PII leakage
        for p in LEAK_PATTERNS:
            for m in p.regex.finditer(text):
                span = m.group(0)
                if p.luhn and not _luhn_ok(span):
                    continue
                findings.append(Finding(
                    detector="output_inspection",
                    rule_id=f"OUT-{p.name.upper()}",
                    category=p.category,
                    title=f"Leaked {p.name.replace('_', ' ')} in model output",
                    severity=p.severity,
                    confidence=p.confidence,
                    owasp_llm=p.owasp_llm,
                    mitre_atlas=p.mitre_atlas,
                    evidence=f"{p.name}: '{_mask(span)}'",
                ))
        return findings

    def redact(self, text: str) -> tuple[str, list[Finding]]:
        """Return (redacted_text, findings) — used by the SOAR redact playbook."""
        findings = self.scan(text)
        redacted = text
        for canary in self.canaries:
            redacted = redacted.replace(canary, "[REDACTED-SYSTEM-PROMPT]")
        for p in LEAK_PATTERNS:
            def _sub(m: re.Match) -> str:
                span = m.group(0)
                if p.luhn and not _luhn_ok(span):
                    return span
                return f"[REDACTED-{p.category.upper()}]"
            redacted = p.regex.sub(_sub, redacted)
        return redacted, findings


def _mask(value: str) -> str:
    """Don't echo a full secret into the event log; keep a short, safe hint."""
    value = value.strip()
    if len(value) <= 8:
        return value[0] + "***"
    return value[:4] + "***" + value[-2:]
