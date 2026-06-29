# Runbook — Prompt-Injection Incident Response

A SOC-style, six-step procedure for handling a prompt-injection detection against
an LLM application, mapped to what Raqib does automatically and what an analyst
does manually. This is the workflow the platform operationalises.

**Frameworks:** OWASP LLM01:2025 · MITRE ATLAS AML.T0051 / AML.T0054 · NIST AI RMF
(Measure/Manage) · ISO/IEC 42001 · EU AI Act (logging & human-oversight
obligations, applicable from August 2026).

---

## 1. Identify
Detect anomalous prompts/outputs via monitoring.
- **Raqib (auto):** signature + judge detection raises a `SecurityEvent`; it
  surfaces on the dashboard feed and the OWASP/ATLAS heatmap.
- **Analyst:** triage the event — severity, `rule_id`, `session_id`, evidence
  snippet, OWASP/ATLAS tags. Is it a true positive?

## 2. Contain
Stop the attack from having effect.
- **Raqib (auto):** SOAR `block` (prompt never reaches the model), `sanitize`
  (strip the injected span), or `quarantine` (repeat-offender session).
- **Analyst:** if an attacker session is active, confirm quarantine; consider a
  temporary block on the source identity/API key.

## 3. Analyze & classify
Determine the injection type and blast radius from the logs.
- **Analyst:** classify (direct vs indirect, jailbreak, extraction, exfiltration)
  using the event `category` + payload. Pull the session timeline
  (`/api/sessions/{id}`). Did any **outbound** event fire — i.e., did the model
  actually leak (canary / key / PII)? That distinguishes *attempt* from *impact*.

## 4. Remediate
Remove impact and close the hole.
- **Raqib (auto):** outbound `redact` / `block` prevents leaked data from reaching
  the user.
- **Analyst:** if a real secret leaked, **rotate it** (the planted canary/key is a
  drill for exactly this). Tune or add a signature for the bypass; if the judge
  missed it, consider enabling `LLM_JUDGE_MODE=always` or a stronger model.

## 5. Report
Record the incident for audit/compliance.
- **Raqib (auto):** the `SecurityEvent` (severity, OWASP/ATLAS mapping, verdict,
  action, evidence) is persisted and forwarded to Wazuh — the audit trail the EU
  AI Act and ISO 42001 expect.
- **Analyst:** write up timeline, classification, impact, remediation; attach the
  relevant red-team report section if it's a known class.

## 6. Harden
Reduce recurrence.
- **Analyst:** add a regression case to the [red-team harness](../../redteam/),
  re-run it, and confirm the new detection holds (the CI gate enforces it). Review
  the [coverage matrix](../owasp-atlas-mapping.md) for adjacent gaps.

---

### Quick reference — severity → default action
| Severity | Inbound | Outbound |
|----------|---------|----------|
| critical | block | block response |
| high | block | redact |
| medium | sanitize / flag | redact |
| low | flag | allow |

> **Honesty note:** detection is probabilistic. This runbook assumes false
> negatives happen — step 6 (harden) is how the system learns, and the
> [measured report](../../redteam/reports/detection-report.md) is how you prove it
> is improving rather than asserting it.
