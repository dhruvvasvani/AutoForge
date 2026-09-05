Push-Location 3_ast_analyzer

Write-Host "
==========================================" -ForegroundColor Cyan
Write-Host " STARTING AST ANALYZER FULL SUITE PIPELINE" -ForegroundColor Cyan
Write-Host "==========================================
" -ForegroundColor Cyan

Write-Host "[WEEK 1] Running Tree-sitter Parser Setup..." -ForegroundColor Yellow
python week1_foundations/parser_setup.py

Write-Host "
[WEEK 2] Running Noise Filtering Prototype..." -ForegroundColor Yellow
python week2_prototype/noise_filter.py week1_foundations/sample_mock.py

Write-Host "
[WEEK 3] Running AST Reachability Engine..." -ForegroundColor Yellow
python week3_reachability/ast_engine.py

Write-Host "
[WEEK 4] Running Pipeline CLI..." -ForegroundColor Yellow
python week4_pipeline/pipeline_cli.py --source week1_foundations/sample_mock.py --input sample_data/combined_scan_results.json

Write-Host "
[WEEK 5] Running Cross-File Analysis & Risk Scoring Engine..." -ForegroundColor Yellow
python week5_cross_file/cross_file_engine.py --source-root week5_cross_file/sample_project --scan week5_cross_file/sample_scan.json
python week5_scoring/risk_scorer.py --input week5_scoring/risk_results.json

Write-Host "
==========================================" -ForegroundColor Green
Write-Host " ALL AST SUITE TESTS COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "==========================================
" -ForegroundColor Green

Pop-Location
