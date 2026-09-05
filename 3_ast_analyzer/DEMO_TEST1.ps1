# AutoForge AST Analyzer — LIVE DEMO (test1.py)
# Shows how vulnerability filtering works on REAL vulnerable code

Write-Host "`n" -ForegroundColor Green
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  AutoForge — Security Finding Noise Filter                    ║" -ForegroundColor Green
Write-Host "║  Demonstrating: test1.py (Real vulnerable code)              ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

$TEST_FILE = "l:\AutoForge\3_ast_analyzer\test_files\test1.py"
$SCAN_FILE = "l:\AutoForge\3_ast_analyzer\test_files\test1_scan_results.json"

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "STEP 1: Show the vulnerable code" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan

Write-Host "File: $TEST_FILE`n" -ForegroundColor Yellow
Write-Host "Key vulnerabilities found:" -ForegroundColor Yellow
Write-Host "  ✗ Line 43:  SQL Injection in authenticate_user()" -ForegroundColor Red
Write-Host "  ✗ Line 55:  Command Injection in export_user_tasks()" -ForegroundColor Red
Write-Host "  ✗ Line 62:  Insecure Pickle in restore_session()" -ForegroundColor Red
Write-Host "  ✗ Line 78:  Hardcoded Secret in generate_token()" -ForegroundColor Red
Write-Host "  ✗ Line 81:  Weak MD5 Crypto in generate_token()" -ForegroundColor Red
Write-Host "  ⚠ Line 90:  DEAD CODE - unused_security_check() (NOISE!)" -ForegroundColor Yellow

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "STEP 2: Parse code (Week 1 — Tree-sitter AST Parser)" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Running parser on your code...`n" -ForegroundColor Yellow

cd "l:\AutoForge\3_ast_analyzer\week1_foundations"
python parser_setup.py $TEST_FILE

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "STEP 3: Extract call graph (Week 2 — Find who calls who)" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Building call relationships...`n" -ForegroundColor Yellow

cd "l:\AutoForge\3_ast_analyzer\week2_prototype"
python noise_filter.py $TEST_FILE

Write-Host "`n📊 What this shows:" -ForegroundColor Cyan
Write-Host "  • main() → calls _init_db()" -ForegroundColor White
Write-Host "  • TaskManager → initialized methods" -ForegroundColor White
Write-Host "  • RemoteTaskServer → defined but NOT called from main" -ForegroundColor Yellow
Write-Host "  ⚠ RemoteTaskServer.start_server() is UNREACHABLE from entry point!" -ForegroundColor Red

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "STEP 4: Analyze reachability (Week 3 — BFS traversal)" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Performing BFS to find all reachable functions...`n" -ForegroundColor Yellow

cd "l:\AutoForge\3_ast_analyzer\week3_reachability"
python ast_engine.py $TEST_FILE $SCAN_FILE

Write-Host "`n📊 Result interpretation:" -ForegroundColor Cyan
Write-Host "  ✓ REACHABLE: Functions called from main() or event handlers" -ForegroundColor Green
Write-Host "  ✗ UNREACHABLE: Defined but never called = potential noise" -ForegroundColor Red

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "STEP 5: Filter scan results (Week 4 — Remove noise)" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Running full pipeline: scan findings → reachability filter → cleaned results`n" -ForegroundColor Yellow

cd "l:\AutoForge\3_ast_analyzer\week4_pipeline"
python pipeline_cli.py --input $SCAN_FILE --source $TEST_FILE --output test1_filtered.json

Write-Host "`n📄 Pipeline Output:" -ForegroundColor Cyan
type test1_filtered.json | Write-Host -ForegroundColor White

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "STEP 6: Risk Scoring (Week 5 — P0-P3 Priority Matrix)" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Scoring findings by severity + reachability...`n" -ForegroundColor Yellow

cd "l:\AutoForge\3_ast_analyzer\week5_scoring"
python risk_scorer.py --input ../week4_pipeline/test1_filtered.json --out test1_scored.json

Write-Host "`n📊 Final Scored Results:" -ForegroundColor Cyan
type test1_scored.json | Write-Host -ForegroundColor White

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "SUMMARY" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green

Write-Host "`n✅ What we demonstrated:" -ForegroundColor Green
Write-Host "  1. Parsed your code → found all functions & calls" -ForegroundColor White
Write-Host "  2. Built call graph → determined reachability" -ForegroundColor White
Write-Host "  3. Identified UNREACHABLE functions → noise!" -ForegroundColor White
Write-Host "  4. Filtered scan findings → removed false positives" -ForegroundColor White
Write-Host "  5. Scored remaining findings → P0-P3 risk levels" -ForegroundColor White

Write-Host "`n💡 Key insight:" -ForegroundColor Cyan
Write-Host "   Developers ignore 95% of scanner alerts (noise fatigue)" -ForegroundColor Yellow
Write-Host "   Our tool filters it → shows only REAL REACHABLE risks" -ForegroundColor Green

Write-Host "`n🎯 Result:" -ForegroundColor Cyan
Write-Host "   Input:  10 security findings" -ForegroundColor Yellow
Write-Host "   Output: ~5 actionable findings (50% noise filtered)" -ForegroundColor Green

Write-Host "`n" -ForegroundColor Green
