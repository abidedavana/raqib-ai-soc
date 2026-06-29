# ---------------------------------------------------------------------------
# Raqib launcher. Double-click start.bat (or the desktop shortcut) to run this.
# It sets things up the first time, starts the gateway + dashboard, seeds some
# demo attacks, and opens your browser. To stop: double-click stop.bat.
# ---------------------------------------------------------------------------
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$gw   = Join-Path $repo "gateway"
$dash = Join-Path $repo "dashboard"

Write-Host ""
Write-Host " ===================================" -ForegroundColor Cyan
Write-Host "   RAQIB  AI-SOC   launcher" -ForegroundColor Cyan
Write-Host " ===================================" -ForegroundColor Cyan
Write-Host ""

# Need Python for first-time setup
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python isn't installed. Get it from https://www.python.org/downloads/ (tick 'Add to PATH')." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"; exit 1
}

# Make sure both components are set up (only does work the first time)
function Initialize-Component($dir, $name) {
    $py = Join-Path $dir ".venv\Scripts\python.exe"
    if (-not (Test-Path $py)) {
        Write-Host "First-time setup for the $name (a few minutes, one time only)..." -ForegroundColor Yellow
        python -m venv (Join-Path $dir ".venv")
        & $py -m pip install --disable-pip-version-check -q -r (Join-Path $dir "requirements.txt")
        Write-Host "  $name ready." -ForegroundColor Green
    }
    return $py
}
$gwPy = Initialize-Component $gw   "gateway"
$dPy  = Initialize-Component $dash "dashboard"

# Clean slate: stop anything already on our ports
Get-NetTCPConnection -LocalPort 8000, 8501 -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }

# 1) Gateway in a minimised window (launch python directly so closing the window stops it cleanly)
Write-Host "Starting the gateway..." -ForegroundColor Gray
Start-Process -FilePath $gwPy -WorkingDirectory $gw -WindowStyle Minimized -ArgumentList "-m", "uvicorn", "app.main:app", "--port", "8000"

# 2) Wait for the gateway to answer
$up = $false
for ($i = 0; $i -lt 40; $i++) {
    try { Invoke-RestMethod "http://127.0.0.1:8000/healthz" -TimeoutSec 2 | Out-Null; $up = $true; break }
    catch { Start-Sleep -Milliseconds 500 }
}
if ($up) { Write-Host "  Gateway is up." -ForegroundColor Green }
else { Write-Host "  Gateway is slow to start. Check the minimised gateway window." -ForegroundColor Yellow }

# 3) Seed demo attacks so the dashboard has data
if ($up) {
    Write-Host "Loading demo attacks..." -ForegroundColor Gray
    try { & $gwPy (Join-Path $repo "redteam\run_harness.py") --target "http://127.0.0.1:8000" | Out-Null } catch {}
}

# 4) Dashboard in a minimised window (launch python directly)
Write-Host "Starting the dashboard..." -ForegroundColor Gray
Start-Process -FilePath $dPy -WorkingDirectory $dash -WindowStyle Minimized -ArgumentList "-m", "streamlit", "run", "app.py", "--server.headless", "true"

for ($i = 0; $i -lt 50; $i++) {
    try { Invoke-WebRequest "http://127.0.0.1:8501" -TimeoutSec 2 -UseBasicParsing | Out-Null; break }
    catch { Start-Sleep -Milliseconds 600 }
}

# 5) Open the browser
Start-Process "http://127.0.0.1:8501"

Write-Host ""
Write-Host " =====================================================" -ForegroundColor Green
Write-Host "  Raqib is running! Your browser should have opened." -ForegroundColor Green
Write-Host "    Dashboard    : http://127.0.0.1:8501" -ForegroundColor White
Write-Host "    API / try-it : http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host " =====================================================" -ForegroundColor Green
Write-Host ""
Write-Host " To STOP Raqib later: double-click stop.bat" -ForegroundColor Cyan
Write-Host " (Closing this window is fine - Raqib keeps running.)" -ForegroundColor Gray
Read-Host " Press Enter to close this window"
