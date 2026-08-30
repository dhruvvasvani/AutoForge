"""
AST Reachability Analysis Engine - CORRECTED VERSION
Addresses Week 3 code review findings:
- Fixes nested function capture (removed early return)
- Adds line-to-function mapping for alert resolution
- Implements caching for performance
- Adds comprehensive error handling
"""

import json
import os
import logging
from typing import Dict, Set, List, Optional, Tuple
from collections import deque
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)


class CallGraphBuilder:
    """Builds call graphs from Python source files using Tree-sitter AST."""
    
    def __init__(self, cache_enabled: bool = True):
        self.cache_enabled = cache_enabled
        self._graph_cache: Dict[str, Dict[str, List[str]]] = {}
        self._line_to_func_cache: Dict[str, Dict[int, str]] = {}
    
    def build_call_graph(self, file_path: str) -> Dict[str, List[str]]:
        """
        Build a call graph from a Python file.
        
        Returns:
            Dict mapping function names to lists of called function names.
        """
        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            return {}
        
        # Check cache
        if self.cache_enabled and file_path in self._graph_cache:
            return self._graph_cache[file_path]
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return {}
        
        try:
            tree = parser.parse(bytes(code, "utf-8"))
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
            return {}
        
        if tree.root_node is None:
            logger.error(f"Parser returned None for {file_path}")
            return {}
        
        call_graph: Dict[str, List[str]] = {}
        current_func = "__module_init__"
        
        def traverse(node):
            """
            Traverse AST and extract function definitions and calls.
            FIXED: Removed early return to properly handle siblings and nested functions.
            """
            nonlocal current_func
            
            # Handle function definitions
            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    func_name = code[name_node.start_byte:name_node.end_byte].strip()
                    
                    # Initialize this function in the graph if not already present
                    if func_name not in call_graph:
                        call_graph[func_name] = []
                    
                    previous_func = current_func
                    current_func = func_name
                    
                    # Traverse children to find nested functions and calls
                    for child in node.children:
                        traverse(child)
                    
                    current_func = previous_func
                    # FIXED: DO NOT RETURN - continue processing siblings
            
            # Handle function calls
            elif node.type == "call":
                func_node = node.child_by_field_name("function")
                if func_node:
                    called_func = code[func_node.start_byte:func_node.end_byte].strip()
                    
                    # Initialize current function if not present
                    if current_func not in call_graph:
                        call_graph[current_func] = []
                    
                    # Add call only if not duplicate
                    if called_func not in call_graph[current_func]:
                        call_graph[current_func].append(called_func)
                        logger.debug(f"{current_func} -> {called_func}")
            
            # Continue traversing other node types
            for child in node.children:
                traverse(child)
        
        traverse(tree.root_node)
        
        # Cache the result
        if self.cache_enabled:
            self._graph_cache[file_path] = call_graph
        
        logger.info(f"Built call graph for {file_path}: {len(call_graph)} functions")
        return call_graph
    
    def build_call_graph_from_directory(self, directory: str) -> Dict[str, List[str]]:
        """
        Build combined call graph from all Python files in a directory.
        """
        combined_graph: Dict[str, List[str]] = {}
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    try:
                        graph = self.build_call_graph(file_path)
                        for func_name, calls in graph.items():
                            if func_name not in combined_graph:
                                combined_graph[func_name] = []
                            combined_graph[func_name].extend(calls)
                    except Exception as e:
                        logger.error(f"Failed to process {file_path}: {e}")
        
        logger.info(f"Built combined graph: {len(combined_graph)} functions")
        return combined_graph
    
    def build_line_to_function_map(self, file_path: str) -> Dict[int, str]:
        """
        Build a mapping from line numbers to function names.
        Useful for resolving function names from line numbers in alerts.
        """
        if not os.path.exists(file_path):
            return {}
        
        if self.cache_enabled and file_path in self._line_to_func_cache:
            return self._line_to_func_cache[file_path]
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
            tree = parser.parse(bytes(code, "utf-8"))
        except Exception as e:
            logger.error(f"Failed to build line map for {file_path}: {e}")
            return {}
        
        line_to_func: Dict[int, str] = {}
        
        def traverse(node, current_func="__module_init__"):
            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    func_name = code[name_node.start_byte:name_node.end_byte].strip()
                    # Mark all lines in this function
                    start_line = node.start_point[0] + 1
                    end_line = node.end_point[0] + 1
                    for line_num in range(start_line, end_line + 1):
                        line_to_func[line_num] = func_name
                    
                    current_func = func_name
            
            for child in node.children:
                traverse(child, current_func)
        
        traverse(tree.root_node)
        
        if self.cache_enabled:
            self._line_to_func_cache[file_path] = line_to_func
        
        logger.info(f"Built line map for {file_path}: {len(line_to_func)} lines mapped")
        return line_to_func


class ReachabilityAnalyzer:
    """Analyzes reachability using BFS traversal."""
    
    def __init__(self, entry_points: Optional[List[str]] = None):
        self.entry_points = entry_points or ["main", "handle_login", "get_user_profile"]
        self.external_calls: Set[str] = set()
    
    def compute_reachable_nodes(self, call_graph: Dict[str, List[str]]) -> Set[str]:
        """
        Compute all reachable functions from entry points using BFS.
        IMPROVED: Tracks external/missing functions.
        """
        reachable: Set[str] = set(self.entry_points)
        queue = deque(self.entry_points)
        self.external_calls = set()
        
        # Validate entry points
        invalid_entries = set(self.entry_points) - set(call_graph.keys())
        if invalid_entries:
            logger.warning(f"Entry points not found in call graph: {invalid_entries}")
        
        while queue:
            curr = queue.popleft()
            
            # Skip if function not in graph (external/imported)
            if curr not in call_graph:
                self.external_calls.add(curr)
                continue
            
            neighbors = call_graph[curr]
            for neighbor in neighbors:
                if neighbor not in reachable:
                    reachable.add(neighbor)
                    queue.append(neighbor)
        
        logger.info(f"Computed reachable: {len(reachable)} functions, "
                   f"{len(self.external_calls)} external calls")
        return reachable


class AlertNormalizer:
    """Normalizes alerts from different scanners to a canonical format."""
    
    @staticmethod
    def normalize(alert: dict, file_to_func_map: Dict[str, Dict[int, str]]) -> dict:
        """
        Normalize alert from various scanner formats.
        Attempts to extract function name from multiple sources.
        """
        normalized = {
            "original": alert,
            "file": alert.get("path") or alert.get("file_path") or alert.get("file"),
            "line": alert.get("line") or alert.get("location", {}).get("line"),
            "severity": alert.get("severity") or alert.get("level"),
            "function": None,
            "extraction_method": None,
        }
        
        # Try explicit function_name field
        if "function_name" in alert:
            normalized["function"] = alert["function_name"]
            normalized["extraction_method"] = "explicit_field"
        elif "extra" in alert and isinstance(alert["extra"], dict):
            if "function_name" in alert["extra"]:
                normalized["function"] = alert["extra"]["function_name"]
                normalized["extraction_method"] = "extra_field"
        
        # Try line-to-function mapping
        if not normalized["function"] and normalized["file"] and normalized["line"]:
            if normalized["file"] in file_to_func_map:
                func = file_to_func_map[normalized["file"]].get(normalized["line"])
                if func:
                    normalized["function"] = func
                    normalized["extraction_method"] = "line_mapping"
        
        return normalized


class ASTReachabilityAnalyzer:
    """
    Main orchestrator for AST-based reachability analysis.
    IMPROVED: Separation of concerns, better caching, error handling.
    """
    
    def __init__(self, entry_points: Optional[List[str]] = None):
        self.entry_points = entry_points or ["main", "handle_login", "get_user_profile"]
        self.graph_builder = CallGraphBuilder(cache_enabled=True)
        self.reachability = ReachabilityAnalyzer(entry_points=entry_points)
    
    def filter_scan_results(self, json_file_path: str, 
                           code_root_path: Optional[str] = None) -> List[dict]:
        """
        Filter security scan results based on reachability analysis.
        IMPROVED: Builds graph once, uses caching, normalizes alerts.
        """
        if not os.path.exists(json_file_path):
            logger.error(f"File not found: {json_file_path}")
            return []
        
        # Load alerts
        try:
            with open(json_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse JSON {json_file_path}: {e}")
            return []
        
        if isinstance(data, list):
            alerts = data
        elif isinstance(data, dict):
            alerts = data.get("results", [])
        else:
            logger.error(f"Unexpected JSON structure in {json_file_path}")
            return []
        
        # Extract unique files from alerts
        alert_files = set()
        for alert in alerts:
            file_path = alert.get("path") or alert.get("file_path") or alert.get("file")
            if file_path:
                alert_files.add(file_path)
        
        logger.info(f"Processing {len(alerts)} alerts from {len(alert_files)} files")
        
        # Build combined call graph (FIXED: built once, not per-alert)
        combined_graph: Dict[str, List[str]] = {}
        file_to_func_map: Dict[str, Dict[int, str]] = {}
        
        for file_path in alert_files:
            if os.path.exists(file_path):
                graph = self.graph_builder.build_call_graph(file_path)
                for func_name, calls in graph.items():
                    if func_name not in combined_graph:
                        combined_graph[func_name] = []
                    combined_graph[func_name].extend(calls)
                
                line_map = self.graph_builder.build_line_to_function_map(file_path)
                file_to_func_map[file_path] = line_map
        
        # Compute reachability
        reachable_funcs = self.reachability.compute_reachable_nodes(combined_graph)
        
        # Analyze alerts
        analyzed_alerts = []
        for alert in alerts:
            normalized = AlertNormalizer.normalize(alert, file_to_func_map)
            
            # Determine reachability
            if normalized["function"]:
                is_reachable = normalized["function"] in reachable_funcs
                status = "REACHABLE_CODE" if is_reachable else "UNREACHABLE_NOISE"
            else:
                # If we couldn't determine function, mark as reachable (conservative)
                is_reachable = True
                status = "REACHABLE_CODE"
                logger.warning(f"Could not determine function for alert: {normalized['original']}")
            
            alert["status"] = status
            alert["is_reachable"] = is_reachable
            alert["detected_function"] = normalized["function"]
            alert["function_detection_method"] = normalized["extraction_method"]
            
            analyzed_alerts.append(alert)
        
        # Summary statistics
        reachable_count = sum(1 for a in analyzed_alerts if a["is_reachable"])
        unreachable_count = len(analyzed_alerts) - reachable_count
        
        logger.info(f"Analysis complete: {reachable_count} reachable, "
                   f"{unreachable_count} unreachable (noise)")
        
        return analyzed_alerts


if __name__ == "__main__":
    analyzer = ASTReachabilityAnalyzer(
        entry_points=["handle_login", "get_user_profile"]
    )
    
    target_json = "combined_scan_results.json"
    
    if os.path.exists(target_json):
        results = analyzer.filter_scan_results(target_json)
        print(f"\nAST Reachability Analysis Completed.")
        print(f"Total Alerts Evaluated: {len(results)}")
        print(f"Reachable: {sum(1 for r in results if r['is_reachable'])}")
        print(f"Noise (Unreachable): {sum(1 for r in results if not r['is_reachable'])}")
        print("\n" + "=" * 80)
        print(json.dumps(results, indent=2))
    else:
        print("Run local scanner pipeline first to generate combined_scan_results.json")
