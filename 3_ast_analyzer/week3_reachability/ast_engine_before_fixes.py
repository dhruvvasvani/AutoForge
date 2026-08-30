"""
Week 3 - Dynamic Call Graph & Reachability Engine
Objective: build call-graph, BFS traversal, tag SAST findings
REACHABLE_CODE vs UNREACHABLE_NOISE.
"""
import json
import os
from collections import deque

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)


class ASTReachabilityAnalyzer:
    def __init__(self, entry_points=None):
        self.entry_points = entry_points or ["main", "handle_login", "get_user_profile"]

    def build_call_graph(self, file_path):
        if not os.path.exists(file_path):
            return {}
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()
        tree = parser.parse(bytes(code, "utf-8"))
        root_node = tree.root_node
        call_graph = {}
        current_func = "global"

        def traverse(node):
            nonlocal current_func
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
        """BFS from entry points across call graph. Returns set of reachable func names."""
        reachable = set()
        queue = deque([ep for ep in self.entry_points if ep in call_graph])
        for ep in self.entry_points:
            reachable.add(ep)

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
        findings: list of dicts, each expected to have a 'function' key
        (SAST scanners usually report a function/method name or line context).
        Returns findings annotated with reachability tag.
        """
        tagged = []
        for finding in findings:
            func_name = finding.get("function") or finding.get("function_name")
            status = "REACHABLE_CODE" if func_name in reachable_funcs else "UNREACHABLE_NOISE"
            finding_copy = dict(finding)
            finding_copy["reachability"] = status
            tagged.append(finding_copy)
        return tagged

    def analyze(self, source_file, scan_results_path):
        call_graph = self.build_call_graph(source_file)
        reachable = self.find_reachable(call_graph)

        with open(scan_results_path, "r", encoding="utf-8") as f:
            raw_results = json.load(f)

        findings = raw_results.get("findings", raw_results if isinstance(raw_results, list) else [])
        tagged = self.tag_findings(findings, reachable)
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
