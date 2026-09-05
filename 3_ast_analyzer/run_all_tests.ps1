# AutoForge AST Analyzer - Full Test Suite
# Runs all 5 weeks + unit tests in sequence

Write-Host "`n=== WEEK 1: Parser Setup ===" -ForegroundColor Cyan
cd "l:\AutoForge\3_ast_analyzer\week1_foundations"
python parser_setup.py sample_mock.py

Write-Host "`n=== WEEK 2: Call Graph Extraction ===" -ForegroundColor Cyan
cd "l:\AutoForge\3_ast_analyzer\week2_prototype"
python noise_filter.py ../week1_foundations/sample_mock.py

Write-Host "`n=== WEEK 3: Reachability Analysis ===" -ForegroundColor Cyan
cd "l:\AutoForge\3_ast_analyzer\week3_reachability"
python ast_engine.py ../week1_foundations/sample_mock.py ../sample_data/combined_scan_results.json

Write-Host "`n=== WEEK 4: Full Pipeline ===" -ForegroundColor Cyan
cd "l:\AutoForge\3_ast_analyzer\week4_pipeline"
python pipeline_cli.py --input ../sample_data/combined_scan_results.json --source ../week1_foundations/sample_mock.py --output pipeline_results.json
Write-Host "`nPipeline output:"
type pipeline_results.json

Write-Host "`n=== WEEK 5: Risk Scoring ===" -ForegroundColor Cyan
cd "l:\AutoForge\3_ast_analyzer\week5_scoring"
python risk_scorer.py --input ../week4_pipeline/pipeline_results.json --out risk_results.json
Write-Host "`nRisk scoring output:"
type risk_results.json

Write-Host "`n=== UNIT TESTS ===" -ForegroundColor Cyan
cd "l:\AutoForge\3_ast_analyzer"
python -m pytest tests/test_ast_engine.py -v --tb=short

Write-Host "`n=== ALL TESTS COMPLETE ===" -ForegroundColor Green
