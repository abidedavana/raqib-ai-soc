# SOC Dashboard — the analyst console

A live, read-only SOC console for attacks against the AI. It consumes the
gateway's dashboard API and turns the structured security events into the view a
Tier 1/2 analyst would actually work from.

![dashboard placeholder](../docs/screenshots/dashboard.png)
<!-- Replace the line above with a real screenshot once you run it (see below). -->

## What it shows
- **KPI strip** — total events, criticals, highs, blocked, active sessions
- **OWASP-LLM × severity heatmap** — where the attacks concentrate
- **Severity** and **SOAR verdict** distributions
- **Top offending sessions** — repeat attackers (drives quarantine)
- **Live security-event feed** — every OWASP/ATLAS-tagged detection, filterable by severity, with optional 5-second auto-refresh

## Run it (3 terminals, or run them in the background)

```bash
# 1) start the gateway
cd gateway
python -m venv .venv && . .venv/Scripts/activate     # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --port 8000

# 2) seed it with attack telemetry (this is also the red-team harness)
python redteam/run_harness.py --target http://localhost:8000

# 3) launch the dashboard
cd dashboard
python -m venv .venv && . .venv/Scripts/activate
pip install -r requirements.txt
streamlit run app.py
# opens http://localhost:8501
```

The gateway URL defaults to `http://localhost:8000`; override via the sidebar or
the `RAQIB_API_URL` environment variable.

> **Tip for your portfolio:** after seeding, take a screenshot and save it to
> `docs/screenshots/dashboard.png` — it becomes the hero image in the main README.
