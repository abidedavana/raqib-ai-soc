# Stops Raqib (the gateway on 8000 and the dashboard on 8501).
$found = Get-NetTCPConnection -LocalPort 8000, 8501 -State Listen -ErrorAction SilentlyContinue
if ($found) {
    $found | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Write-Host "Raqib has been stopped." -ForegroundColor Green
}
else {
    Write-Host "Raqib doesn't appear to be running." -ForegroundColor Yellow
}
Start-Sleep -Seconds 2
