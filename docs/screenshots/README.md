# Screenshots

Drop your captured images here. The main README and the dashboard README expect:

| File | What to capture |
|------|-----------------|
| `dashboard.png` | The SOC dashboard with seeded data (KPI strip + heatmap + event feed visible) |
| `dashboard-heatmap.png` *(optional)* | Close-up of the OWASP-LLM × severity heatmap |
| `blocked-attack.png` *(optional)* | The `/v1/chat` Swagger response showing a blocked injection |

## How to capture the dashboard shot

```powershell
# 1) start the gateway (terminal 1)
cd gateway; .\.venv\Scripts\Activate.ps1
uvicorn app.main:app --port 8000

# 2) seed it with attacks (terminal 2)
python redteam/run_harness.py --target http://localhost:8000

# 3) launch the dashboard (terminal 2)
cd dashboard; .\.venv\Scripts\Activate.ps1
streamlit run app.py
```

Then in the browser at `http://localhost:8501`: press **Win + Shift + S** (Windows
Snipping Tool), capture the page, and save it here as `dashboard.png`. Finally,
uncomment the screenshot line near the top of the main [`README.md`](../../README.md).

> Tip: in the dashboard sidebar, set the event-feed size to ~100 and leave the
> severity filter empty so the shot shows a full, busy console.
