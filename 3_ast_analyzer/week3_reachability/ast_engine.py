"""
Week 3 - Dynamic Call Graph & Reachability Engine (PATCHED)
Fixes applied per Gemini code review (see FIXES_APPLIED.md for full list):
  1. [CRITICAL] Entry points no longer silently assumed reachable -
     validated against actual call graph, logged if missing.
  2. [HIGH] All call_graph writes go through setdefault() first -
     no dropped calls from uninitialized keys.
  3. [HIGH] Call graph built ONCE per analyze() call, reused for all
     findings - no per-alert rebuild (was O(n) rebuilds, now O(1)).
  4. [HIGH] Entry points validated against graph before BFS starts;
     missing ones are logged, not silently dropped.
  5. [MEDIUM] try/except around file I/O and JSON parsing, logged errors,
     graceful return instead of raw traceback.
  6. [MEDIUM] Module-level ("global") scope key now prefixed with the
     source file's module name, so reusing one analyzer instance across
     multiple files no longer conflates their module-level calls.
"""
import json
import logging
import os
from collections import deque

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ast_engine")

PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)


class ASTReachabilityAnalyzer:
    def __init__(self, entry_points=None):
        self.entry_points = entry_points or ["main", "handle_login", "get_user_profile"]

    def build_call_graph(self, file_path):
        """Fix #5: explicit existence check + try/except around parse/read."""
        if not os.path.exists(file_path):
            logger.error("Source file not found: %s", file_path)
            return {}

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
        except OSError as e:
            logger.error("Failed to read %s: %s", file_path, e)
            return {}

        try:
            tree = parser.parse(bytes(code, "utf-8"))
        except Exception as e:
            logger.error("Failed to parse %s: %s", file_path, e)
            return {}

        root_node = tree.root_node
        call_graph = {}
        # Fix #6: prefix module-level scope with the file's own name so
        # analyzing multiple files with one analyzer instance doesn't
        # merge unrelated module-level calls under one bare "global" key.
        module_key = os.path.splitext(os.path.basename(file_path))[0]
        current_func = f"{module_key}::<module>"

        def traverse(node):
            nonlocal current_func
            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    func_name = code[name_node.start_byte:name_node.end_byte]
                    previous_func = current_func
                    current_func = func_name
                    # Fix #2: setdefault BEFORE traversing children, so a
                    # function with zero calls still appears in the graph
                    # (needed for reachability even with no outgoing edges).
                    call_graph.setdefault(current_func, [])
                    for child in node.children:
                        traverse(child)
                    current_func = previous_func
                    return
            if node.type == "call":
                fn_node = node.child_by_field_name("function")
                if fn_node:
                    callee = code[fn_node.start_byte:fn_node.end_byte]
                    # Fix #2: setdefault before append - guarantees the key
                    # exists even for calls made directly at module level.
                    call_graph.setdefault(current_func, [])
                    call_graph[current_func].append(callee)
            for child in node.children:
                traverse(child)

        traverse(root_node)
        return call_graph

    def find_reachable(self, call_graph):
        """
        BFS from entry points across call graph.
        Fix #1 / #4: entry points are validated against the graph BEFORE
        BFS runs. A function is only ever marked reachable if it is an
        entry point OR actually walked to via BFS - nothing defaults to
        reachable just because it's unrecognized.
        """
        missing_entry_points = [ep for ep in self.entry_points if ep not in call_graph]
        if missing_entry_points:
            logger.warning(
                "Entry points not found in call graph (will not seed BFS): %s",
                missing_entry_points,
            )

        valid_entry_points = [ep for ep in self.entry_points if ep in call_graph]
        reachable = set(valid_entry_points)
        queue = deque(valid_entry_points)

        while queue:
            func = queue.popleft()
            for callee in call_graph.get(func, []):
                if callee not in reachable:
                    reachable.add(callee)
                    if callee in call_graph:
                        queue.append(callee)
        return reachable

    def tag_findings(self, findings, reachable_funcs):
        """
        findings: list of dicts, each expected to have a 'function' key.
        Fix #1: explicit membership check only - a finding with a missing
        or unresolved function name is UNREACHABLE_NOISE by default, never
        silently marked reachable.
        """
        tagged = []
        for finding in findings:
            func_name = finding.get("function") or finding.get("function_name")
            status = "REACHABLE_CODE" if (func_name and func_name in reachable_funcs) else "UNREACHABLE_NOISE"
            finding_copy = dict(finding)
            finding_copy["reachability"] = status
            tagged.append(finding_copy)
        return tagged

    def analyze(self, source_file, scan_results_path):
        """Fix #3: call graph built exactly once here, reused for every finding."""
        call_graph = self.build_call_graph(source_file)
        reachable = self.find_reachable(call_graph)

        if not os.path.exists(scan_results_path):
            logger.error("Scan results file not found: %s", scan_results_path)
            return {"call_graph": call_graph, "reachable_functions": sorted(reachable), "tagged_findings": []}

        try:
            with open(scan_results_path, "r", encoding="utf-8") as f:
                raw_results = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.error("Failed to load scan results %s: %s", scan_results_path, e)
            return {"call_graph": call_graph, "reachable_functions": sorted(reachable), "tagged_findings": []}

        findings = raw_results.get("findings", raw_results if isinstance(raw_results, list) else [])
        tagged = self.tag_findings(findings, reachable)
        logger.info(
            "Analysis complete: %d reachable functions, %d/%d findings reachable",
            len(reachable),
            sum(1 for f in tagged if f["reachability"] == "REACHABLE_CODE"),
            len(tagged),
        )
        return {
            "call_graph": call_graph,
            "reachable_functions": sorted(reachable),
            "tagged_findings": tagged,
        }


if __name__ == "__main__":
    import sys
    src = sys.argv[1] if len(sys.argv) > 1 else "../week1_foundations/sample_mock.py"
    scan = sys.argv[2] if len(sys.argv) > 2 else "../sample_data/combined_scan_results.json"
    analyzer = ASTReachabilityAnalyzer()
    result = analyzer.analyze(src, scan)
    print(json.dumps(result, indent=2))
