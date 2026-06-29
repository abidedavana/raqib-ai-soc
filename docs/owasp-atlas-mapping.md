# OWASP-LLM Top 10 (2025) & MITRE ATLAS mapping

Every detection in Raqib is tagged with an **OWASP LLM Top 10 (2025)** id and a
**MITRE ATLAS** technique, so attacks against the AI speak the same language a SOC
and a risk/compliance team already use.

- OWASP LLM Top 10 (2025): https://genai.owasp.org/llm-top-10/
- MITRE ATLAS matrix: https://atlas.mitre.org/matrices/ATLAS

> **Verify before you cite.** ATLAS technique ids evolve. The table below mirrors
> the ids hard-coded in [`gateway/app/mappings/frameworks.py`](../gateway/app/mappings/frameworks.py);
> re-check them against the live ATLAS matrix before quoting a specific
> sub-technique in a report. Reporting an id you haven't verified is exactly the
> kind of inflation this project avoids.

## Detection → framework matrix

### Signature layer (`gateway/app/detection/rules/signatures.yaml`)

| Rule | Detects | Severity | OWASP-LLM | MITRE ATLAS |
|------|---------|----------|-----------|-------------|
| `SIG-INJ-001` | Instruction override (*ignore previous instructions*) | high | LLM01:2025 Prompt Injection | AML.T0051.000 Direct |
| `SIG-INJ-002` | Role reassignment / new-instructions injection | high | LLM01:2025 | AML.T0051.000 |
| `SIG-JB-001` | Known jailbreak persona (DAN / developer mode) | high | LLM01:2025 | AML.T0054 Jailbreak |
| `SIG-JB-002` | Safety-bypass framing (hypothetical / grandma) | medium | LLM01:2025 | AML.T0054 |
| `SIG-EXFIL-001` | System-prompt / instruction extraction | high | LLM07:2025 System Prompt Leakage | AML.T0056 Meta Prompt Extraction |
| `SIG-EVAD-001` | Encoding / obfuscation evasion (base64 / ROT13 / spacing) | medium | LLM01:2025 | AML.T0051.000 |
| `SIG-AGENCY-001` | Tool / agent abuse (destructive or exfil action) | critical | LLM06:2025 Excessive Agency | AML.T0053 Plugin Compromise |
| `SIG-DOS-001` | Unbounded consumption / repetition amplification | low | LLM10:2025 Unbounded Consumption | AML.T0048 External Harms |

### LLM-as-judge layer (`gateway/app/detection/llm_judge.py`)

| Rule | Detects | OWASP-LLM | MITRE ATLAS |
|------|---------|-----------|-------------|
| `JUDGE-PROMPT_INJECTION` | Semantic injection (novel phrasing) | LLM01:2025 | AML.T0051.000 |
| `JUDGE-JAILBREAK` | Semantic jailbreak | LLM01:2025 | AML.T0054 |
| `JUDGE-DATA_EXFILTRATION` | Intent to extract secrets/data | LLM02:2025 Sensitive Info Disclosure | AML.T0057 Data Leakage |

### Output-inspection layer (`gateway/app/detection/output_inspect.py`)

| Rule | Detects | Severity | OWASP-LLM | MITRE ATLAS |
|------|---------|----------|-----------|-------------|
| `OUT-CANARY-001` | Planted system-prompt canary in response | critical | LLM07:2025 | AML.T0056 |
| `OUT-PRIVATE_KEY_BLOCK` | Private key material leaked | critical | LLM02:2025 | AML.T0057 |
| `OUT-AWS_ACCESS_KEY` | Cloud access key leaked | critical | LLM02:2025 | AML.T0057 |
| `OUT-OPENAI_STYLE_KEY` | `sk-…` API key leaked | critical | LLM02:2025 | AML.T0057 |
| `OUT-GENERIC_API_KEY` | Generic api_key/secret/token leaked | high | LLM02:2025 | AML.T0057 |
| `OUT-JWT` | JSON Web Token leaked | high | LLM02:2025 | AML.T0057 |
| `OUT-CREDIT_CARD` | Card number (Luhn-validated) | high | LLM02:2025 | AML.T0057 |
| `OUT-EMAIL_ADDRESS` | Email PII | medium | LLM02:2025 | AML.T0057 |
| `OUT-EMIRATES_ID` | Emirates ID PII | high | LLM02:2025 | AML.T0057 |

## OWASP-LLM Top 10 (2025) coverage — honestly

| OWASP-LLM | Covered? | How / why not |
|-----------|----------|---------------|
| LLM01 Prompt Injection | ✅ Core | Signatures + judge (direct & indirect) |
| LLM02 Sensitive Information Disclosure | ✅ Core | Output inspection (secrets/PII) |
| LLM03 Supply Chain | ❌ Out of scope | A model/dependency provenance concern, not a runtime gateway signal |
| LLM04 Data & Model Poisoning | ❌ Out of scope | Training-time threat; not observable at inference |
| LLM05 Improper Output Handling | 🟡 Partial | Output inspection flags leaked data; downstream encoding/escaping is the app's job |
| LLM06 Excessive Agency | ✅ Partial | Detects destructive/exfil tool-call patterns in prompts |
| LLM07 System Prompt Leakage | ✅ Core | Extraction signatures + canary output inspection |
| LLM08 Vector & Embedding Weaknesses | ❌ Out of scope | RAG store internals are outside the gateway |
| LLM09 Misinformation | 🟡 Minimal | Not a primary target; would need factuality scoring |
| LLM10 Unbounded Consumption | 🟡 Partial | Repetition/amplification signature; full rate accounting is future work |

Drawing the box honestly — what Raqib does **not** cover and why — is a deliberate
part of the design. A gateway is the right control for runtime prompt/response
threats (LLM01, LLM02, LLM06, LLM07); supply-chain and training-time risks
(LLM03, LLM04, LLM08) belong to other controls.
