Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   AutoForge Full Pipeline Test Suite     " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

if (Test-Path ".\mvnw.cmd") {
    .\mvnw.cmd test
} else {
    mvn test
}
if ($LASTEXITCODE -eq 0) {
    Write-Host "All tests passed successfully!" -ForegroundColor Green
} else {
    Write-Host "Pipeline tests encountered failures." -ForegroundColor Red
    exit $LASTEXITCODE
}
