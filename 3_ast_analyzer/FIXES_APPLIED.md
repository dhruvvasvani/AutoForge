# Fixes Applied (per Gemini code review)

Applied to `week3_reachability/ast_engine.py`. Old unpatched version kept
alongside as `ast_engine_before_fixes.py` for diff reference.

| # | Bug | Severity | Fix |
|---|---|---|---|
| 1 | Default-reachable assumption not validated | CRITICAL | `tag_findings` only marks REACHABLE_CODE on explicit membership check (`func_name and func_name in reachable_funcs`) — never defaults to reachable for missing/unresolved names |
| 2 | Uninitialized function entries drop calls | HIGH | `call_graph.setdefault(current_func, [])` called before every write, both on function-def and on call-site |
| 3 | Graph rebuilt per alert (100x slower) | HIGH | `analyze()` builds the call graph exactly once, reuses it for every finding in the batch |
| 4 | Entry points not validated | HIGH | `find_reachable()` checks entry points against the graph before BFS starts, logs any that are missing instead of silently ignoring |
| 5 | No error handling | MEDIUM | try/except around file reads, tree-sitter parse, and JSON load, with `logging.error(...)` + graceful empty-result return instead of raw traceback |
| 6 | Ambiguous module-level tracking | MEDIUM | Module-level ("global") scope key is now prefixed with the file's own module name (`sample_mock::<module>`) so one analyzer instance reused across files won't merge unrelated module-level calls |

## Week 5 additions (per Gemini plan)

- `week5_cross_file/cross_file_engine.py` — resolves `import x` / `from x import y`,
 merges per-file call graphs into one project-wide graph, BFS now depth-tracked
 with optional `--depth-limit`.
- `week4_pipeline/pipeline_cli.py` — now takes `--source-root`, `--depth-limit`,
 `--format markdown` and auto-routes to the week5 cross-file engine when any
 of those are passed; plain `--source` still runs the original week3 single-file
 path unchanged.

## Verified

```
python pipeline_cli.py --input scan.json --source file.py --output out.json # week3/4 mode, unchanged
python pipeline_cli.py --input scan.json --source-root project/ --depth-limit 2 # week5 mode
python pipeline_cli.py --input scan.json --source-root project/ --format markdown # week5 markdown report
```
All three tested against sample data, correct reachable/noise counts in each mode.
