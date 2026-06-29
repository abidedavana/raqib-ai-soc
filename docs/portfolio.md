# Portfolio copy — Raqib AI-SOC

Copy-paste material for your CV, LinkedIn, and interviews. Everything here is
**measured and truthful** — keep it that way; the honesty is the selling point.

Repo: https://github.com/abidedavana/raqib-ai-soc

---

## One-liner
> Self-hosted **AI-SOC**: a security gateway that detects, logs and auto-responds
> to attacks against LLM apps (prompt injection, jailbreaks, data leakage,
> system-prompt extraction), mapped to OWASP-LLM Top 10 and MITRE ATLAS.

## CV bullets (concise, quantified)
- Built **Raqib**, a self-hosted AI-SOC — a FastAPI security gateway that detects prompt injection, jailbreaks, secret/PII leakage and system-prompt extraction in real time, tagging each detection to the **OWASP LLM Top 10 (2025)** and **MITRE ATLAS**.
- Engineered a **3-layer detection stack** (version-controlled signature rules, an LLM-as-judge, and response output inspection) with **SOAR playbooks** (block / sanitize / redact / quarantine).
- Validated the platform with a **built-in red-team harness**, measuring **76.9% detection at 10% false positives** across 26 attacks spanning 5 techniques — with every miss documented rather than hidden.
- Delivered structured security events to a **Streamlit SOC dashboard** (OWASP/ATLAS heatmap, live feed) and a **Wazuh SIEM** forwarder, with **GitHub Actions CI** gating detection-rate regressions.
- Designed for **$0, fully self-hosted** operation (local Ollama models) — the deployment model regulated UAE government / critical-infrastructure workloads require.

## LinkedIn "Projects" blurb
> **Raqib (رقيب) — Self-Hosted AI-SOC for LLM Applications.** A defensive
> detection-and-response platform that sits in front of any LLM app and gives it
> SOC-grade protection. It intercepts every prompt and response, runs layered
> detection (signatures → LLM-as-judge → output inspection), auto-responds with
> SOAR playbooks, and logs each attack as a structured security event mapped to
> OWASP-LLM Top 10 and MITRE ATLAS — feeding a SOC dashboard and a Wazuh SIEM.
> It ships with a red-team harness that measures real detection and false-positive
> rates (76.9% / 10%) and documents the gaps. Offense-informed defense for the
> threat model WAFs were never built for. Python · FastAPI · Ollama · Wazuh · $0/local.

## 30-second elevator pitch
> "I learned to break LLMs with Garak and PyRIT, so I built the SOC platform that
> detects and stops those attacks. Raqib is a gateway that catches prompt
> injection, jailbreaks and data leakage, maps each to OWASP-LLM and MITRE ATLAS,
> runs automated response playbooks, and feeds a SIEM. I didn't claim to solve
> prompt injection — I measured it: 77% detection at 10% false positives, with
> every miss documented."

## Interview talking points (be ready to defend these)
- **Why a gateway?** Prompt injection is a runtime threat that traditional WAFs and
  API gateways don't understand; a purpose-built proxy is the right control point.
- **Why layered?** No single method catches injection (it's inherent to LLMs mixing
  instructions and data). Defence in depth: cheap regex first, semantic judge next,
  output inspection as the safety net.
- **The honesty angle.** I report detection AND false-positive rates and list the
  misses (obfuscation, non-English, subtle extraction). A credible control names
  its blind spots.
- **The latency trade-off.** The LLM-judge is gated (`off`/`suspicious`/`always`)
  because a model call per request is expensive — `suspicious` is the default,
  `always` maximises recall.
- **Fail-safe design.** Judge / SIEM / model failures degrade gracefully; they
  never crash the request or silently disable detection.
- **Why it matters in the UAE.** Self-hosted + OWASP/ATLAS/EU-AI-Act framing fits
  the regulated government / critical-infrastructure market (G42/Core42, Help AG, CPX).

## Honesty guardrails (do NOT overstate)
- Don't say "I solved prompt injection." Say "I detect and respond to it, and here
  are the measured rates and limits."
- The 76.9% / 10% figures are with the **heuristic-fallback judge** (no GPU). Note
  that a real Ollama model is expected to improve recall — but don't quote a number
  you haven't measured.
