# Week 3 Code Review: AST Reachability Analysis Engine
**AutoForge DevSecOps Platform | Module: 3_ast_analyzer**

**Date:** 2026-08-30 
**Files Reviewed:** 
- `3_ast_analyzer/ast_engine.py` (v1)
- `3_ast_analyzer/v2_analyzer/ast_engine.py` (v2)

---

## Executive Summary

The AST Reachability Analysis Engine successfully uses Tree-sitter to build call graphs and BFS to compute reachable functions, effectively filtering false positive security alerts. However, **critical gaps exist in nested function handling, edge-case management, and performance optimization** that could undermine accuracy on complex codebases.

**Overall Assessment:** Functional but needs hardening before production use

---

## 1. Tree-Sitter AST Parsing Logic

### Strengths
- **Robust parsing:** Tree-sitter correctly parses Python AST even with syntax errors (graceful degradation)
- **Dual format support:** Handles both list and dict JSON structures robustly
- **Byte-offset extraction:** Correctly extracts identifiers using Tree-sitter's byte boundaries

### Critical Issues

#### 1.1 **Nested Function Definitions Not Captured**
**Severity:** HIGH

The `traverse()` function has a logical flaw—it processes function definitions with an **early `return`** statement:

```python
if node.type == "function_definition":
 name_node = node.child_by_field_name("name")
 if name_node:
 func_name = code[name_node.start_byte:name_node.end_byte]
 previous_func = current_func
 current_func = func_name
 if func_name not in call_graph:
 call_graph[func_name] = []
 for child in node.children:
 traverse(child)
 current_func = previous_func
 return # ← EARLY EXIT: Skips processing remaining AST nodes
```

**Problem:** When a function is encountered, the function returns immediately after processing its children. This means:
- Nested functions (functions inside other functions) are not registered as separate graph nodes
- Sibling functions after a definition are never processed
- Call graphs from nested scopes may be lost

**Example:**
```python
def outer():
 def inner():
 helper()
 inner()

def helper():
 pass
```

The call graph would be:
- `outer: ["inner"]` ✓
- **Missing:** `inner: ["helper"]` ✗ (because traversal returns early)

**Impact:** Reachability analysis incorrectly marks `helper()` as unreachable, generating false positives.

**Fix:** Remove the early `return` statement. Continue iterating sibling nodes:
```python
if node.type == "function_definition":
 # ... existing code ...
 for child in node.children:
 traverse(child)
 current_func = previous_func
 # Do NOT return here - allow traversal to continue
else: # Only process calls in non-function contexts (or refactor entirely)
 if node.type == "call":
 # ... call processing ...
 for child in node.children:
 traverse(child)
```

---

#### 1.2 **Incorrect Function Call Extraction for Complex Expressions**
**Severity:** MEDIUM

The code extracts called functions using `node.child_by_field_name("function")`:
```python
if node.type == "call":
 func_node = node.child_by_field_name("function")
 if func_node:
 called_func = code[func_node.start_byte:func_node.end_byte]
```

**Problem:** For complex call patterns, this extracts only part of the expression:
- `obj.method()` → extracted as `obj.method` (correct, but qualified name)
- `module.submodule.func()` → extracted as full qualified path (hard to match against defined functions)
- `(lambda x: x)()` → extracted as lambda expression (meaningless)

**Impact:** Calls to methods and module-qualified functions are never matched against the call graph, resulting in false negatives (functions marked unreachable when they are reachable).

**Example:**
```python
class Service:
 def authenticate(self):
 pass

def handle_login():
 svc = Service()
 svc.authenticate() # ← Extracted as "svc.authenticate", not matched to "authenticate"
```

**Fix:** Distinguish between:
1. Simple function calls: `foo()` → `foo`
2. Method calls: `obj.method()` → `obj.method` (or map to class methods)
3. Module imports: `module.func()` → `func` (after resolving imports)

Recommend building a **name resolution table** during the first pass, or marking these as "external" calls.

---

#### 1.3 **Uninitialized Function Entries**
**Severity:** MEDIUM

The code only creates call_graph entries for **defined** functions:
```python
if func_name not in call_graph:
 call_graph[func_name] = []
```

But later checks:
```python
if current_func in call_graph and called_func not in call_graph[current_func]:
 call_graph[current_func].append(called_func)
```

**Problem:** If a function `foo()` is called before any function definition that calls it is encountered (e.g., due to tree traversal order), then `current_func` may not be in `call_graph` yet, and the call is silently dropped.

**Impact:** Call graph is incomplete, leading to false negatives in reachability.

**Fix:** Ensure all encountered functions (defined or called) are initialized in the graph:
```python
# When processing any function call:
if current_func not in call_graph:
 call_graph[current_func] = []
if called_func not in call_graph[current_func]:
 call_graph[current_func].append(called_func)
```

---

### Design Concerns

#### 1.4 **Top-Level Code Execution**
The code uses `current_func = "global"` to track function calls at the module level. While functional, this is ambiguous:
- Module-level `subprocess.run(shell=True)` is attributed to "global"
- Entry point "main" may not exist; code could execute at module load time

**Recommendation:** Explicitly handle module-level execution:
```python
current_func = "__global__" # or "__module_init__"
```

---

## 2. BFS Graph Traversal & Cyclic Dependency Handling

### Strengths
- **Cycle handling:** The `if neighbor not in reachable` check correctly prevents infinite loops
- **Correct algorithm:** BFS is appropriate for this problem
- **Queue-based:** Efficient `deque` implementation

### Issues

#### 2.1 **Missing Nodes in Graph**
**Severity:** MEDIUM

When the BFS processes an entry point or discovered function, it calls:
```python
neighbors = call_graph.get(curr, [])
```

**Problem:** If a function is never defined in the analyzed files (e.g., it's from an external library or stub), it won't be in `call_graph`. The BFS silently treats it as having no outgoing edges.

**Example:**
```python
import requests # External library

def login_handler():
 requests.post(url) # ← Never defined in analyzed files
```

If `login_handler` is an entry point, the analysis stops there and never explores functions that might be called inside the `requests.post()` implementation (which is fine for static analysis, but misleading if we consider external libraries).

**Impact:** Minor for pure reachability analysis, but should be logged/warned about.

**Recommendation:** Add a set to track "external" functions:
```python
def compute_reachable_nodes(self, call_graph):
 reachable = set(self.entry_points)
 external_calls = set()
 queue = deque(self.entry_points)
 
 while queue:
 curr = queue.popleft()
 if curr not in call_graph:
 external_calls.add(curr)
 continue
 neighbors = call_graph[curr]
 # ... rest of BFS ...
 
 return reachable, external_calls # Return both for logging
```

---

#### 2.2 **Entry Points Not Validated**
**Severity:** LOW

Entry points are assumed to exist. If none of them are in the analyzed code:
```python
entry_points=["handle_login", "get_user_profile"]
```

And these functions don't exist in the codebase, **the reachable set will only contain the entry points themselves**, and all other functions are marked unreachable (false positives).

**Recommendation:** Warn if entry points aren't found:
```python
def compute_reachable_nodes(self, call_graph):
 invalid_entries = set(self.entry_points) - set(call_graph.keys())
 if invalid_entries:
 print(f"Warning: Entry points not found in call graph: {invalid_entries}")
 # ... rest of BFS ...
```

---

## 3. Scan Results Filtering

### Issues

#### 3.1 **Function Name Resolution Failures**
**Severity:** HIGH

The code attempts to extract function names from alerts:
```python
extra = alert.get("extra", {})
target_func = extra.get("function_name") if isinstance(extra, dict) else None
if not target_func:
 target_func = alert.get("function_name")

is_reachable = target_func in reachable_funcs if target_func else True
```

**Problem:**
- If no `function_name` is found, it defaults to `True` (assumes reachable)
- Different scanners (Semgrep vs. Checkov) have different JSON schemas—function names may be buried in different fields
- No logging of extraction failures

**Example from sample data:** The combined_scan_results.json has alerts with `file` and `line`, but **no explicit function_name**. The analyzer would default all of them to "REACHABLE_CODE" without actually performing reachability analysis!

**Impact:** Critical—reachability filtering is bypassed for most real-world alerts.

**Fix:** Build a reverse mapping from line numbers to functions:
```python
def get_function_at_line(self, file_path, line_num):
 """Return the function containing the given line."""
 # Parse file and build a line->function map
 # ...
```

Then use this to resolve function names from line numbers.

---

#### 3.2 **Graph Built Per Alert (Inefficient)**
**Severity:** MEDIUM-HIGH (Performance)

The code rebuilds the call graph for each alert:
```python
for alert in alerts:
 file_path = alert.get("path", "") or alert.get("file_path", "")
 if os.path.exists(file_path):
 graph = self.build_call_graph(file_path)
 for k, v in graph.items():
 combined_graph.setdefault(k, []).extend(v)
```

**Problem:**
- Same file may be processed multiple times if it has multiple alerts
- No caching of parsed graphs
- For a codebase with 1000 files and 10,000 alerts, this rebuilds graphs 10,000 times

**Impact:** O(alerts × files) complexity. For large codebases, this is prohibitively slow.

**Fix:** Build the complete call graph once, then query it:
```python
def filter_scan_results(self, json_file_path, code_root_path):
 # Build graph once from entire codebase
 combined_graph = self.build_call_graph_from_directory(code_root_path)
 reachable_funcs = self.compute_reachable_nodes(combined_graph)
 
 # Load alerts
 alerts = self.load_json(json_file_path)
 
 # Query for each alert (O(1) per alert)
 for alert in alerts:
 # ...
```

---

#### 3.3 **Field Name Inconsistencies Not Handled**
**Severity:** MEDIUM

Different scanners use different field names:
- Semgrep: `path`, `line`, `message`
- Checkov: `file_path`, `check_id`, etc.

The code checks both `path` and `file_path` for the file, but doesn't normalize function name locations.

**Fix:** Create a normalizer:
```python
def normalize_alert(self, alert, scanner_type="unknown"):
 """Map scanner-specific fields to canonical form."""
 normalized = {
 "file": alert.get("path") or alert.get("file_path") or alert.get("file"),
 "line": alert.get("line") or alert.get("location", {}).get("line"),
 "function": self._extract_function_from_context(alert),
 }
 return normalized
```

---

## 4. Performance & Scalability

### Current Bottlenecks
| Operation | Complexity | Issue |
|-----------|-----------|-------|
| Graph building (per file) | O(file_size) | Tree-sitter parse + traversal |
| Call graph merge | O(alerts × files) | Rebuilds per alert |
| BFS traversal | O(nodes + edges) | Acceptable |
| Function name extraction | O(alerts) | Slow if parsing each file again |

### Recommendations
1. **Cache graph builds** – Memoize `build_call_graph()` by file path
2. **Batch file processing** – Build graph from entire directory once
3. **Parallel processing** – Process files in parallel using `concurrent.futures`
4. **Line-to-function mapping** – Build once at startup, reuse for all alerts

### Estimated Impact
- **Before:** 10,000 alerts on 100 files = 100 parse operations (but many duplicates)
- **After:** 100 files + 10,000 lookups = 100 parse operations (no duplicates)
- **Speedup:** 10-50x for typical codebases

---

## 5. Error Handling & Robustness

### Current State: Minimal error handling
```python
if not os.path.exists(file_path):
 return {}
```

### Missing
- No try-except for JSON parsing failures
- No error recovery for malformed Python files
- No logging of parsing failures
- Silent failures when tree-sitter fails

### Recommendation: Add structured error handling
```python
def build_call_graph(self, file_path, logger=None):
 try:
 if not os.path.exists(file_path):
 if logger: logger.warning(f"File not found: {file_path}")
 return {}
 
 with open(file_path, "r", encoding="utf-8") as f:
 code = f.read()
 
 tree = parser.parse(bytes(code, "utf-8"))
 if tree.root_node is None:
 if logger: logger.error(f"Failed to parse {file_path}")
 return {}
 
 # ... rest of logic ...
 except Exception as e:
 if logger: logger.error(f"Error processing {file_path}: {e}")
 return {}
```

---

## 6. Test Coverage Gaps

### What's Missing
- [ ] Test nested function definitions
- [ ] Test cyclic function calls (A → B → A)
- [ ] Test entry points that don't exist in code
- [ ] Test alerts without function names
- [ ] Test external/imported function calls
- [ ] Test large codebases (performance regression)
- [ ] Test malformed JSON inputs
- [ ] Test files that don't parse

### Recommended Test Cases
```python
# test_ast_engine.py

def test_nested_function_calls():
 """Verify nested functions are captured."""
 code = """
 def outer():
 def inner():
 helper()
 inner()
 def helper():
 pass
 """
 # Save to temp file, build graph
 # Assert: inner→[helper], outer→[inner]

def test_cyclic_calls():
 """Verify BFS handles cycles without infinite loops."""
 code = """
 def foo():
 bar()
 def bar():
 foo()
 """
 # Build graph, compute reachable from [foo]
 # Assert: reachable == {foo, bar} (finite set)

def test_method_calls():
 """Verify method calls are captured (or logged as external)."""
 # Test obj.method() patterns

def test_missing_entry_points():
 """Verify warning when entry point doesn't exist."""
 # Analyzer with entry_points=["nonexistent"]
 # Assert: warning logged
```

---

## 7. Recommendations Summary

### Immediate Fixes (Before Production)
1. **Remove early `return` in `traverse()`** – Fix nested function capture (Critical)
2. **Resolve function names from line numbers** – Don't default to "reachable" (Critical)
3. **Cache graph builds** – Avoid redundant parsing (High)
4. **Validate entry points exist** – Warn if missing (High)

### Short-term Improvements
5. Handle method calls and qualified names properly (Medium)
6. Build reverse line→function mapping (Medium)
7. Add comprehensive error handling and logging (Medium)
8. Create alert normalizer for multi-scanner support (Medium)

### Long-term Enhancements
9. Support multiple languages (Java, Go, C#) via Tree-sitter
10. Integrate with IDE/plugin for real-time feedback
11. Build incremental/differential reachability analysis
12. Support async/concurrent code path analysis
13. Handle dynamic imports and reflection patterns

---

## 8. Code Quality Observations

### Positive
- Clear class structure and method organization
- Reasonable variable naming
- Type hints would help (add `from typing import...`)
- Docstrings present in v2 version

### Improvements Needed
- Add type hints to all function signatures
- Add logging module instead of print statements
- Separate concerns: parsing, graph building, filtering into distinct classes
- Externalize entry points and configuration

### Example: Better structure
```python
from typing import Dict, Set, List
from collections import deque
import logging

logger = logging.getLogger(__name__)

class CallGraphBuilder:
 """Builds call graphs from Python AST."""
 def build_from_file(self, file_path: str) -> Dict[str, List[str]]:
 pass
 
 def build_from_directory(self, directory: str) -> Dict[str, List[str]]:
 pass

class ReachabilityAnalyzer:
 """Analyzes reachability using BFS."""
 def compute_reachable(self, call_graph: Dict[str, List[str]], 
 entry_points: List[str]) -> Set[str]:
 pass

class ScanResultsFilter:
 """Filters security scan results based on reachability."""
 def filter_results(self, alerts: List[dict], 
 reachable_funcs: Set[str]) -> List[dict]:
 pass
```

---

## Conclusion

The AST Reachability Analysis Engine demonstrates a **solid architectural approach** to reducing false positives in security scanning. The use of Tree-sitter and BFS is sound. However, **critical bugs in AST traversal, function name resolution, and efficiency issues must be addressed before production deployment**.

**Priority:** Fix items 1-2 (nested functions, function name extraction) before scanning production codebases.

**Estimated Effort:**
- Critical fixes: 2-3 hours
- Performance optimization: 2-3 hours 
- Comprehensive testing: 3-4 hours
- Total: ~8-10 hours for production-ready code

**Next Steps:**
1. Implement fixes in order of severity
2. Add unit tests for each fix
3. Run regression tests on existing pipelines
4. Document function name extraction strategy for scanner normalization
