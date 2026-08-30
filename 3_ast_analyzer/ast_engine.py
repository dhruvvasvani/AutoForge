import json
import os
import tree_sitter_python as tspython
from tree_sitter import Language, Parser
from collections import deque

# Initialize Tree-sitter Parser for Python
PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)

class ASTReachabilityAnalyzer:
    def __init__(self, entry_points=None):
        self.entry_points = entry_points or ["main", "handle_login", "get_user_profile"]

    def build_call_graph(self, file_path):
        """Dynamic Tree-Sitter AST parser to extract call graph from Python source files."""
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
                func_node = node.child_by_field_name("function")
                if func_node:
                    called_func = code[func_node.start_byte:func_node.end_byte]
                    if current_func in call_graph and called_func not in call_graph[current_func]:
                        call_graph[current_func].append(called_func)

            for child in node.children:
                traverse(child)

        traverse(root_node)
        return call_graph

    def compute_reachable_nodes(self, call_graph):
        """BFS graph traversal to calculate all reachable functions from entry points."""
        reachable = set(self.entry_points)
        queue = deque(self.entry_points)

        while queue:
            curr = queue.popleft()
            neighbors = call_graph.get(curr, [])
            for neighbor in neighbors:
                if neighbor not in reachable:
                    reachable.add(neighbor)
                    queue.append(neighbor)
        return reachable

    def filter_scan_results(self, json_file_path):
        """Reads scan findings and classifies reachability status dynamically."""
        if not os.path.exists(json_file_path):
            print(f"File not found: {json_file_path}")
            return []

        with open(json_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Robust Check: Handle both List [] and Dict {} root structures
        if isinstance(data, list):
            alerts = data
        elif isinstance(data, dict):
            alerts = data.get("results", [])
        else:
            alerts = []

        combined_graph = {}
        for alert in alerts:
            file_path = alert.get("path", "") or alert.get("file_path", "")
            if os.path.exists(file_path):
                graph = self.build_call_graph(file_path)
                for k, v in graph.items():
                    combined_graph.setdefault(k, []).extend(v)

        reachable_funcs = self.compute_reachable_nodes(combined_graph)

        analyzed_alerts = []
        for alert in alerts:
            extra = alert.get("extra", {})
            target_func = extra.get("function_name") if isinstance(extra, dict) else None
            if not target_func:
                target_func = alert.get("function_name")

            is_reachable = target_func in reachable_funcs if target_func else True
            alert["status"] = "REACHABLE_CODE" if is_reachable else "UNREACHABLE_NOISE"
            alert["is_reachable"] = is_reachable
            analyzed_alerts.append(alert)

        return analyzed_alerts

if __name__ == "__main__":
    analyzer = ASTReachabilityAnalyzer(entry_points=["handle_login", "get_user_profile"])
    target_json = "combined_scan_results.json"
    
    if os.path.exists(target_json):
        results = analyzer.filter_scan_results(target_json)
        print(f"AST Reachability Analysis Completed. Total Evaluated: {len(results)}")
        print(json.dumps(results, indent=2))
    else:
        print("Run local scanner pipeline first to generate combined_scan_results.json")