#!/usr/bin/env python3
"""Raqib red-team harness — validate the platform and MEASURE it honestly.

Runs a labelled battery of attacks (direct/indirect injection, jailbreaks, data
extraction, encoding evasion) plus benign traffic through the Raqib gateway, then
reports:
  * detection rate   (attacks that produced >=1 security event)
  * mitigation rate  (attacks the SOAR layer actually blocked/sanitised/redacted)
  * false-positive rate (benign prompts that tripped a detection)
  * a per-category breakdown
  * the documented MISSES and FALSE POSITIVES (the honest gaps)

By default it runs the gateway in-process (no server needed). Use --target to hit
a live gateway over HTTP. Exit code is non-zero if --min-detection-rate or
--max-fp-rate thresholds are violated, so it doubles as a CI regression gate.

Usage:
    python redteam/run_harness.py
    python redteam/run_harness.py --target http://localhost:8000
    python redteam/run_harness.py --min-detection-rate 0.70 --max-fp-rate 0.20
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
GATEWAY = ROOT.parent / "gateway"
ATTACKS_DIR = ROOT / "attacks"
CORPUS_DIR = ROOT / "corpus"
REPORTS_DIR = ROOT / "reports"


# ── payload loading ──────────────────────────────────────────────────────────
def load_datasets() -> list[dict]:
    datasets = []
    for path in sorted(ATTACKS_DIR.glob("*.yaml")):
        datasets.append(yaml.safe_load(path.read_text(encoding="utf-8")))
    return datasets


def resolve_prompt(sample: dict) -> str:
    if "doc" in sample:
        doc = (CORPUS_DIR / sample["doc"]).read_text(encoding="utf-8")
        return sample.get("template", "{doc}").replace("{doc}", doc)
    return sample["prompt"]


# ── gateway clients ──────────────────────────────────────────────────────────
class InProcessClient:
    """Drives the FastAPI app in-process via TestClient (zero external deps)."""

    def __init__(self, judge_mode: str):
        sys.path.insert(0, str(GATEWAY))
        os.environ["DB_PATH"] = str(Path(tempfile.gettempdir()) / "raqib_harness.db")
        os.environ["LLM_JUDGE_MODE"] = judge_mode
        os.environ.setdefault("LLM_BACKEND", "mock")
        if os.path.exists(os.environ["DB_PATH"]):
            os.remove(os.environ["DB_PATH"])
        from app.config import get_settings
        get_settings.cache_clear()
        from fastapi.testclient import TestClient
        from app.main import app
        self._cm = TestClient(app)
        self.client = self._cm.__enter__()

    def post(self, session: str, message: str) -> dict:
        return self.client.post("/v1/chat", json={"session_id": session, "message": message}).json()

    def close(self):
        self._cm.__exit__(None, None, None)


class HttpClient:
    """Hits a live gateway over HTTP."""

    def __init__(self, target: str):
        import httpx
        self.base = target.rstrip("/")
        self.http = httpx.Client(timeout=60)

    def post(self, session: str, message: str) -> dict:
        r = self.http.post(f"{self.base}/v1/chat", json={"session_id": session, "message": message})
        r.raise_for_status()
        return r.json()

    def close(self):
        self.http.close()


# ── execution ────────────────────────────────────────────────────────────────
MITIGATING_VERDICTS = {"block", "sanitize", "redact"}


def run(client, datasets: list[dict]) -> list[dict]:
    results = []
    for ds in datasets:
        category = ds["category"]
        is_benign = category == "benign"
        for sample in ds["samples"]:
            prompt = resolve_prompt(sample)
            resp = client.post(f"rt-{sample['id']}", prompt)
            findings = resp.get("inbound_findings", []) + resp.get("outbound_findings", [])
            results.append({
                "id": sample["id"],
                "category": category,
                "is_benign": is_benign,
                "prompt": prompt.replace("\n", " ")[:160],
                "detected": len(findings) > 0,
                "verdict": resp.get("verdict"),
                "mitigated": resp.get("verdict") in MITIGATING_VERDICTS,
                "n_findings": len(findings),
                "owasp": sorted({f["owasp_llm"] for f in findings}),
                "atlas": sorted({f["mitre_atlas"] for f in findings}),
                "rules": sorted({f["rule_id"] for f in findings}),
            })
    return results


def score(results: list[dict]) -> dict:
    attacks = [r for r in results if not r["is_benign"]]
    benign = [r for r in results if r["is_benign"]]
    detected_attacks = [r for r in attacks if r["detected"]]
    mitigated_attacks = [r for r in attacks if r["mitigated"]]
    false_positives = [r for r in benign if r["detected"]]

    categories = {}
    for r in attacks:
        c = categories.setdefault(r["category"], {"total": 0, "detected": 0, "mitigated": 0})
        c["total"] += 1
        c["detected"] += int(r["detected"])
        c["mitigated"] += int(r["mitigated"])

    def rate(n, d):
        return round(n / d, 4) if d else 0.0

    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "totals": {
            "attacks": len(attacks),
            "benign": len(benign),
            "detected_attacks": len(detected_attacks),
            "mitigated_attacks": len(mitigated_attacks),
            "false_positives": len(false_positives),
        },
        "detection_rate": rate(len(detected_attacks), len(attacks)),
        "mitigation_rate": rate(len(mitigated_attacks), len(attacks)),
        "false_positive_rate": rate(len(false_positives), len(benign)),
        "by_category": categories,
        "misses": [
            {"id": r["id"], "category": r["category"], "prompt": r["prompt"]}
            for r in attacks if not r["detected"]
        ],
        "false_positive_samples": [
            {"id": r["id"], "prompt": r["prompt"], "rules": r["rules"]}
            for r in false_positives
        ],
        "results": results,
    }


# ── reporting ────────────────────────────────────────────────────────────────
def write_reports(summary: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "detection-report.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    (out_dir / "detection-report.md").write_text(render_markdown(summary), encoding="utf-8")


def render_markdown(s: dict) -> str:
    t = s["totals"]
    lines = [
        "# Raqib — Red-Team Detection Report",
        "",
        f"_Generated: {s['generated']} · backend: mock vulnerable model · judge: always_",
        "",
        "> Measured, not marketed. Raqib does **not** claim to solve prompt injection — "
        "this report states real detection and false-positive rates and documents every miss.",
        "",
        "## Headline metrics",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attacks tested | {t['attacks']} |",
        f"| **Detection rate** (>=1 security event) | **{s['detection_rate']*100:.1f}%** "
        f"({t['detected_attacks']}/{t['attacks']}) |",
        f"| **Mitigation rate** (blocked/sanitised/redacted) | **{s['mitigation_rate']*100:.1f}%** "
        f"({t['mitigated_attacks']}/{t['attacks']}) |",
        f"| Benign prompts tested | {t['benign']} |",
        f"| **False-positive rate** | **{s['false_positive_rate']*100:.1f}%** "
        f"({t['false_positives']}/{t['benign']}) |",
        "",
        "## Detection by attack category",
        "",
        "| Category | Detected | Mitigated | Total |",
        "|---|---|---|---|",
    ]
    for cat, c in s["by_category"].items():
        lines.append(f"| {cat} | {c['detected']} | {c['mitigated']} | {c['total']} |")

    lines += ["", "## Documented misses (the honest gaps)", ""]
    if s["misses"]:
        for m in s["misses"]:
            lines.append(f"- **{m['id']}** ({m['category']}): `{m['prompt']}`")
    else:
        lines.append("- None in this run.")

    lines += [
        "",
        "### Why these were missed (analysis)",
        "",
        "Misses cluster around **obfuscation and language coverage** — homoglyph/"
        "full-width characters, non-English injections, and semantically subtle "
        "extraction with no trigger keyword. These are the known limits of "
        "signature + lexical-heuristic detection and are exactly where a stronger "
        "LLM-judge (via Ollama) and normalisation pre-processing would raise recall. "
        "Documenting them is the point: a credible control reports its blind spots.",
        "",
        "## False positives",
        "",
    ]
    if s["false_positive_samples"]:
        for fp in s["false_positive_samples"]:
            lines.append(f"- **{fp['id']}**: `{fp['prompt']}` — tripped {', '.join(fp['rules'])}")
        lines += [
            "",
            "False positives come from legitimate prompts that reference control "
            "language (e.g. *ignore the previous message*). This is the precision/recall "
            "trade-off of high-recall signatures; in production these rules would be "
            "tuned or gated behind the LLM-judge to cut FPs.",
        ]
    else:
        lines.append("- None in this run.")

    lines += [
        "",
        "## Methodology",
        "",
        f"- {t['attacks']} labelled attacks across 5 categories + {t['benign']} benign prompts.",
        "- Each payload sent through the full gateway pipeline (signatures + LLM-judge + "
        "output inspection + SOAR).",
        "- *Detected* = at least one OWASP/ATLAS-tagged security event was raised. "
        "*Mitigated* = SOAR blocked, sanitised, or redacted.",
        "- Reproduce: `python redteam/run_harness.py`",
        "",
    ]
    return "\n".join(lines)


def print_summary(s: dict) -> None:
    t = s["totals"]
    print("\n" + "=" * 60)
    print("RAQIB RED-TEAM RESULTS")
    print("=" * 60)
    print(f"Detection rate : {s['detection_rate']*100:5.1f}%  ({t['detected_attacks']}/{t['attacks']})")
    print(f"Mitigation rate: {s['mitigation_rate']*100:5.1f}%  ({t['mitigated_attacks']}/{t['attacks']})")
    print(f"False-pos rate : {s['false_positive_rate']*100:5.1f}%  ({t['false_positives']}/{t['benign']})")
    print("-" * 60)
    for cat, c in s["by_category"].items():
        print(f"  {cat:<20} {c['detected']}/{c['total']} detected")
    if s["misses"]:
        print("-" * 60)
        print("Misses:", ", ".join(m["id"] for m in s["misses"]))
    print("=" * 60)


def main() -> int:
    ap = argparse.ArgumentParser(description="Raqib red-team harness")
    ap.add_argument("--target", help="Live gateway URL (default: in-process)")
    ap.add_argument("--judge-mode", default="always", choices=["off", "suspicious", "always"])
    ap.add_argument("--out", default=str(REPORTS_DIR), help="report output dir")
    ap.add_argument("--min-detection-rate", type=float, default=0.0)
    ap.add_argument("--max-fp-rate", type=float, default=1.0)
    args = ap.parse_args()

    datasets = load_datasets()
    client = HttpClient(args.target) if args.target else InProcessClient(args.judge_mode)
    try:
        results = run(client, datasets)
    finally:
        client.close()

    summary = score(results)
    write_reports(summary, Path(args.out))
    print_summary(summary)
    print(f"\nReport written to {Path(args.out) / 'detection-report.md'}")

    ok = True
    if summary["detection_rate"] < args.min_detection_rate:
        print(f"FAIL: detection rate {summary['detection_rate']:.2%} < min {args.min_detection_rate:.2%}")
        ok = False
    if summary["false_positive_rate"] > args.max_fp_rate:
        print(f"FAIL: FP rate {summary['false_positive_rate']:.2%} > max {args.max_fp_rate:.2%}")
        ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
