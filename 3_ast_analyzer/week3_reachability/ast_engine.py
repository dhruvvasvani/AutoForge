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
                    call_graph.setdefault(current_func, [])
                    for child in node.children:
                        traverse(child)
                    current_func = previous_func
                    return
            if node.type == "call":
                fn_node = node.child_by_field_name("function")
                if fn_node:
                    callee = code[fn_node.start_byte:fn_node.end_byte]
                    call_graph.setdefault(current_func, [])
                    call_graph[current_func].append(callee)
            for child in node.children:
                traverse(child)

        traverse(root_node)
        return call_graph

    def find_reachable(self, call_graph):
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
        tagged = []
        for finding in findings:
            func_name = finding.get("function") or finding.get("function_name")
            status = "REACHABLE_CODE" if (func_name and func_name in reachable_funcs) else "UNREACHABLE_NOISE"
            finding_copy = dict(finding)
            finding_copy["reachability"] = status
            tagged.append(finding_copy)
        return tagged

    def analyze(self, source_file, scan_results_path):
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

        findings = raw_results if isinstance(raw_results, list) else (raw_results.get('findings', []) if isinstance(raw_results, dict) else [])
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
    src = sys.argv[1] if len(sys.argv) > 1 else "week1_foundations/sample_mock.py"
    scan = sys.argv[2] if len(sys.argv) > 2 else "sample_data/combined_scan_results.json"
    analyzer = ASTReachabilityAnalyzer()
    result = analyzer.analyze(src, scan)
    print(json.dumps(result, indent=2))

