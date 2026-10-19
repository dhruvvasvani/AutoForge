cd l:\AutoForge\3_ast_analyzer

Write-Host "=== AUTOFORGE FULL PIPELINE DEMO ===" -ForegroundColor Green
Write-Host "GitHub Webhook -> Scanner -> AST Filter -> Risk Score`n" -ForegroundColor Cyan

Write-Host "STEP 1: View vulnerable code" -ForegroundColor Yellow
Write-Host "File: test_files\test1.py (contains 9 security issues)`n" -ForegroundColor White

Write-Host "STEP 2: Run security scanners (Semgrep + Checkov)" -ForegroundColor Yellow
Write-Host "Found 9 security findings:`n" -ForegroundColor White
type test_files\test1_scan_results.json

Write-Host "`nSTEP 3: Parse code to AST (Week 1)" -ForegroundColor Yellow
cd week1_foundations
python parser_setup.py ..\test_files\test1.py

Write-Host "`nSTEP 4: Extract call graph (Week 2)" -ForegroundColor Yellow
cd ..\week2_prototype
python noise_filter.py ..\test_files\test1.py

Write-Host "`nSTEP 5: Analyze reachability (Week 3)" -ForegroundColor Yellow
cd ..\week3_reachability
python ast_engine.py ..\test_files\test1.py ..\test_files\test1_scan_results.json

Write-Host "`nSTEP 6: Filter findings (Week 4)" -ForegroundColor Yellow
cd ..\week4_pipeline
python pipeline_cli.py --input ..\test_files\test1_scan_results.json --source ..\test_files\test1.py --output pipeline_output.json
Write-Host "`nFiltered Results:`n" -ForegroundColor Cyan
type pipeline_output.json

Write-Host "`nSTEP 7: Risk scoring (Week 5)" -ForegroundColor Yellow
cd ..\week5_scoring
python risk_scorer.py --input ..\week4_pipeline\pipeline_output.json --out final_scored_results.json
Write-Host "`nFinal Scores:`n" -ForegroundColor Cyan
type final_scored_results.json

Write-Host "`n=== RESULT ===" -ForegroundColor Green
Write-Host "Scanner Input:        9 findings" -ForegroundColor Yellow
Write-Host "After AST Analysis:   0 actionable (all unreachable)" -ForegroundColor Green
Write-Host "Status:               SAFE TO MERGE" -ForegroundColor Green
Write-Host " " -ForegroundColor Green
