Write-Host "Cleaning up AutoForge temporary logs and build artifacts..." -ForegroundColor Yellow

Get-ChildItem -Path . -Include "hs_err_pid*.log", "replay_pid*.log" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem -Path . -Name "__pycache__" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "AutoForge workspace cleaned successfully!" -ForegroundColor Green
