# Detection methodology

Raqib detects attacks against an LLM the way a mature SOC detects attacks against
anything else: **defence in depth**, cheapest filter first, every hit normalised
into a structured, framework-tagged security event.

## Why layers (and not one clever model)

No single technique catches prompt injection — it's a fundamental consequence of
LLMs processing instructions and data in the same token stream. So Raqib stacks
three independent detectors with different failure modes; an attack has to evade
all of them to get through clean.

```
            ┌──────────────┐   ┌──────────────┐   ┌────────────────────┐
  prompt ──▶│ 1 Signatures │──▶│ 2 LLM-judge  │   │ 3 Output inspection │──▶ response
            │  (regex)     │   │  (semantic)  │   │  (leak detection)   │
            └──────────────┘   └──────────────┘   └────────────────────┘
              cheap, precise     recall on novel     catches the damage
              low recall         phrasing            after a successful attack
```

### 1. Signature layer — `signatures.py`
Pure regex/keyword rules authored as **YAML detection-as-code** (think Sigma for
the LLM attack surface). Fast, deterministic, runs on *every* prompt, and easy to
tune and review in version control. Strong precision on known patterns; blind to
novel phrasing, other languages, and obfuscation.

### 2. LLM-as-judge layer — `llm_judge.py`
A local model classifies the prompt as injection / jailbreak / data-exfiltration
with a confidence score, catching semantic attacks regex misses. It is
**pluggable** (Ollama backend) with a **deterministic heuristic fallback** so the
platform — and CI — always run with zero external dependencies. If Ollama is
unreachable, it degrades to the heuristic instead of failing open.

### 3. Output-inspection layer — `output_inspect.py`
Scans the model's *response* for the consequences of a successful attack: secret
and PII leakage (cloud keys, API tokens, cards, emails) and **system-prompt
extraction** via a planted canary token. This is the safety net for whatever the
inbound layers missed.

## Tiering for latency

A model call per request is expensive, so the judge is gated by `LLM_JUDGE_MODE`:

| Mode | Behaviour | Trade-off |
|------|-----------|-----------|
| `off` | signatures + output inspection only | fastest, lowest recall |
| `suspicious` *(default)* | judge runs **only when a signature already fired** | balanced |
| `always` | judge runs on every prompt | highest recall, highest latency |

This is a real engineering tension worth naming in an interview: the
`suspicious` default means an attack that evades the signature layer *also*
evades the judge. `always` closes that gap at a latency cost. The
[red-team report](../redteam/reports/detection-report.md) is generated in
`always` mode to measure the platform's ceiling.

## Verdict & response

Findings are aggregated into a max-severity and a score, then the
[SOAR engine](../gateway/app/soar/playbooks.py) maps that to an action:

| Direction | Severity | Verdict |
|-----------|----------|---------|
| inbound | high / critical | **block** (model never sees the prompt) |
| inbound | medium | **sanitize** (strip the injected span) or **flag** |
| inbound | low | **flag** |
| outbound | critical (canary / key) | **block** the response |
| outbound | other leakage | **redact** the spans |
| session | ≥ `QUARANTINE_THRESHOLD` offenses | **quarantine** |

## Known limitations (by design, stated up front)

- **Obfuscation**: homoglyph/full-width and heavy encoding can defeat ASCII regex.
- **Language coverage**: signatures are English-centric.
- **Semantic subtlety**: keyword-free extraction relies on the judge; the
  heuristic fallback is weaker than a real model.
- **Indirect injection** is detected when the poisoned content reaches the prompt
  Raqib sees; content fetched and acted on entirely inside an agent loop is out of
  view.

These are measured, not hidden — see the [red-team report](../redteam/reports/detection-report.md).
