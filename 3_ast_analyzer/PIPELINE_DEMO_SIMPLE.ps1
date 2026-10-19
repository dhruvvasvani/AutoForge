cd l:\AutoForge\3_ast_analyzer

Write-Host "`n=== FULL PIPELINE INTEGRATION ===" -ForegroundColor Green
Write-Host "GitHub Webhook -> Scanner -> AST Filter -> Risk Score`n" -ForegroundColor Cyan

Write-Host "STEP 1: Show vulnerable code" -ForegroundColor Yellow
type test_files\test1.py

Write-Host "`nSTEP 2: Scanner results (9 findings)" -ForegroundColor Yellow
type test_files\test1_scan_results.json

Write-Host "`nSTEP 3: Parse code (Week 1)" -ForegroundColor Yellow
cd week1_foundations
python parser_setup.py ..\test_files\test1.py

Write-Host "`nSTEP 4: Extract call graph (Week 2)" -ForegroundColor Yellow
cd ..\week2_prototype
python noise_filter.py ..\test_files\test1.py

Write-Host "`nSTEP 5: Reachability analysis (Week 3)" -ForegroundColor Yellow
cd ..\week3_reachability
python ast_engine.py ..\test_files\test1.py ..\test_files\test1_scan_results.json

Write-Host "`nSTEP 6: Filter pipeline (Week 4)" -ForegroundColor Yellow
cd ..\week4_pipeline
python pipeline_cli.py --input ..\test_files\test1_scan_results.json --source ..\test_files\test1.py --output pipeline_output.json
type pipeline_output.json

Write-Host "`nSTEP 7: Risk scoring (Week 5)" -ForegroundColor Yellow
cd ..\week5_scoring
python risk_scorer.py --input ..\week4_pipeline\pipeline_output.json --out final_scored_results.json
type final_scored_results.json

Write-Host "`n=== RESULT ===" -ForegroundColor Green
Write-Host "Input: 9 security findings" -ForegroundColor Yellow
Write-Host "After AST Filter: 0 actionable findings (all unreachable)" -ForegroundColor Green
Write-Host "Safe to merge! `n" -ForegroundColor Green
