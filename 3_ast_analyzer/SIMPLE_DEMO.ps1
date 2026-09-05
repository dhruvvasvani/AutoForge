# Quick vulnerability showcase for test1.py
# Just paste these commands one by one in terminal

# 1. Show the code structure
Write-Host "`n📄 Opening your test file..." -ForegroundColor Cyan
code l:\AutoForge\3_ast_analyzer\test_files\test1.py

# OR just cat it:
Write-Host "`n📄 Your vulnerable code:" -ForegroundColor Cyan
Write-Host "═════════════════════════════════" -ForegroundColor Cyan
type l:\AutoForge\3_ast_analyzer\test_files\test1.py
Write-Host "═════════════════════════════════" -ForegroundColor Cyan

# 2. Show what security scanners found
Write-Host "`n🔍 Security scan findings (9 issues):" -ForegroundColor Yellow
type l:\AutoForge\3_ast_analyzer\test_files\test1_scan_results.json

# 3. Parse the code - show AST structure
Write-Host "`n🔍 STEP 1: Parse code (see all functions):" -ForegroundColor Green
cd "l:\AutoForge\3_ast_analyzer\week1_foundations"
python parser_setup.py ..\test_files\test1.py

# 4. Extract call graph - show who calls who
Write-Host "`n📊 STEP 2: Extract call graph (who calls who):" -ForegroundColor Green
cd "l:\AutoForge\3_ast_analyzer\week2_prototype"
python noise_filter.py ..\test_files\test1.py

# 5. Find reachable functions
Write-Host "`n✅ STEP 3: Reachability Analysis:" -ForegroundColor Green
cd "l:\AutoForge\3_ast_analyzer\week3_reachability"
python ast_engine.py ..\test_files\test1.py ..\test_files\test1_scan_results.json
