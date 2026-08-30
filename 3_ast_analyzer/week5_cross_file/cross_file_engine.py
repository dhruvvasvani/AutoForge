"""
Week 5 - Cross-File Reachability Analysis & Depth Tracking
Objective: extend single-file call graph to project-wide graph by resolving
import / from-import statements, and add depth-limited BFS so vulnerable
functions can be classified by how deep they sit from an entry point.
"""
import argparse
import json
import os
from collections import deque

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)


class CrossFileReachabilityAnalyzer:
    def __init__(self, entry_points=None, depth_limit=None):
        self.entry_points = entry_points or ["main", "handle_login", "get_user_profile"]
        self.depth_limit = depth_limit  # None = unlimited
        self.import_map = {}   # module_alias -> resolved module name, per file
        self.call_graph = {}   # "file::func" -> ["file::func" or bare callee, ...]
        self.dotted_to_key = {}  # "utils.db" -> "db" (module_key), built before graph pass

    # ---------- import resolution ----------
    def _parse_imports(self, root_node, code):
        """Return dict: local_name -> module (handles `import x` and `from x import y`)."""
        local_map = {}
        for node in root_node.children:
            if node.type == "import_statement":
                for child in node.children:
                    if child.type == "dotted_name":
                        mod = code[child.start_byte:child.end_byte]
                        local_map[mod.split(".")[0]] = mod
                    elif child.type == "aliased_import":
                        name_node = child.child_by_field_name("name")
                        alias_node = child.child_by_field_name("alias")
                        if name_node and alias_node:
                            mod = code[name_node.start_byte:name_node.end_byte]
                            alias = code[alias_node.start_byte:alias_node.end_byte]
                            local_map[alias] = mod
            elif node.type == "import_from_statement":
                module_node = node.child_by_field_name("module_name")
                module = code[module_node.start_byte:module_node.end_byte] if module_node else ""
                for child in node.children:
                    if child.type == "dotted_name" and child != module_node:
                        name = code[child.start_byte:child.end_byte]
                        local_map[name] = f"{module}.{name}"
                    elif child.type == "aliased_import":
                        name_node = child.child_by_field_name("name")
                        alias_node = child.child_by_field_name("alias")
                        if name_node and alias_node:
                            name = code[name_node.start_byte:name_node.end_byte]
                            alias = code[alias_node.start_byte:alias_node.end_byte]
                            local_map[alias] = f"{module}.{name}"
        return local_map

    # ---------- per-file call graph ----------
    def _build_file_graph(self, file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()
        tree = parser.parse(bytes(code, "utf-8"))
        root = tree.root_node

        imports = self._parse_imports(root, code)
        module_key = os.path.splitext(os.path.basename(file_path))[0]
        current_func = f"{module_key}::global"

        def qualify(name):
            """Resolve bare name to a defined 'module_key::func' when the source
            module is known (either local file or a resolved import); otherwise
            fall back to a dotted external reference (stdlib/3rd-party call)."""
            base = name.split(".")[0]
            rest = name[len(base):]  # e.g. ".save_record" or ""
            if base in imports:
                dotted_module = imports[base]
                # dotted_module may itself include the function, e.g. "utils.db.save_record"
                # from `from utils.db import save_record`. Try longest-prefix match
                # against known modules first.
                candidate = dotted_module + rest
                parts = candidate.split(".")
                for cut in range(len(parts) - 1, 0, -1):
                    mod_dotted = ".".join(parts[:cut])
                    func_part = ".".join(parts[cut:])
                    if mod_dotted in self.dotted_to_key and func_part:
                        return f"{self.dotted_to_key[mod_dotted]}::{func_part}"
                return candidate  # unresolved external (e.g. 3rd-party lib)
            return f"{module_key}::{name}"  # local call, same file

        def traverse(node):
            nonlocal current_func
            if node.type == "function_definition":
                name_node = node.child_by_field_name("name")
                if name_node:
                    fname = code[name_node.start_byte:name_node.end_byte]
                    previous = current_func
                    current_func = f"{module_key}::{fname}"
                    self.call_graph.setdefault(current_func, [])
                    for child in node.children:
                        traverse(child)
                    current_func = previous
                    return
            if node.type == "call":
                fn_node = node.child_by_field_name("function")
                if fn_node:
                    callee_raw = code[fn_node.start_byte:fn_node.end_byte]
                    callee_qualified = qualify(callee_raw)
                    self.call_graph.setdefault(current_func, [])
                    self.call_graph[current_func].append(callee_qualified)
            for child in node.children:
                traverse(child)

        traverse(root)

    def build_project_graph(self, source_root):
        """Walk source_root, index dotted module paths, then build a merged
        call graph across all .py files (two passes: index, then resolve)."""
        self.call_graph = {}
        self.dotted_to_key = {}
        py_files = []
        for dirpath, _, files in os.walk(source_root):
            for fname in files:
                if fname.endswith(".py") and fname != "__init__.py":
                    full_path = os.path.join(dirpath, fname)
                    py_files.append(full_path)
                    rel = os.path.relpath(full_path, source_root)
                    dotted = os.path.splitext(rel)[0].replace(os.sep, ".")
                    module_key = os.path.splitext(fname)[0]
                    self.dotted_to_key[dotted] = module_key
                    # also index the bare filename in case imports use a shorter path
                    self.dotted_to_key.setdefault(module_key, module_key)

        for full_path in py_files:
            self._build_file_graph(full_path)
        return self.call_graph

    # ---------- depth-limited BFS ----------
    def find_reachable_with_depth(self):
        """
        BFS from entry points across the merged call graph.
        Returns dict: func_key -> shortest depth from any entry point.
        Entry points are matched by suffix (module::func endswith ::entry_name)
        so callers don't need to know which file defines the entry point.
        """
        depths = {}
        queue = deque()

        for func_key in self.call_graph:
            short_name = func_key.split("::")[-1]
            if short_name in self.entry_points:
                depths[func_key] = 0
                queue.append((func_key, 0))

        while queue:
            func, depth = queue.popleft()
            if self.depth_limit is not None and depth >= self.depth_limit:
                continue
            for callee in self.call_graph.get(func, []):
                if callee not in depths:
                    depths[callee] = depth + 1
                    queue.append((callee, depth + 1))

        return depths

    def analyze(self, source_root, scan_results_path):
        self.build_project_graph(source_root)
        depths = self.find_reachable_with_depth()

        with open(scan_results_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        findings = raw.get("findings", raw if isinstance(raw, list) else [])

        tagged = []
        for finding in findings:
            func_name = finding.get("function") or finding.get("function_name")
            # match by suffix since scan results usually don't know module prefix
            matched_key = next((k for k in depths if k.endswith(f"::{func_name}")), None)
            f = dict(finding)
            if matched_key is not None:
                f["reachability"] = "REACHABLE_CODE"
                f["depth"] = depths[matched_key]
                f["depth_limited"] = self.depth_limit is not None and depths[matched_key] >= (self.depth_limit or 0)
            else:
                f["reachability"] = "UNREACHABLE_NOISE"
                f["depth"] = None
            tagged.append(f)

        return {
            "call_graph": self.call_graph,
            "reachable_by_depth": depths,
            "tagged_findings": tagged,
        }


def to_markdown(result: dict, depth_limit) -> str:
    lines = ["# Cross-File Reachability Report", ""]
    lines.append(f"Depth limit: {depth_limit if depth_limit is not None else 'unlimited'}")
    lines.append("")
    lines.append("| Finding | Function | Reachability | Depth |")
    lines.append("|---|---|---|---|")
    for f in result["tagged_findings"]:
        fid = f.get("id") or f.get("rule", "?")
        fn = f.get("function") or f.get("function_name") or "?"
        lines.append(f"| {fid} | {fn} | {f['reachability']} | {f.get('depth', '-')} |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Week 5: cross-file reachability + depth-limited BFS")
    ap.add_argument("--source-root", required=True, help="Project root to scan for .py files")
    ap.add_argument("--scan", required=True, help="Raw SAST scan results JSON")
    ap.add_argument("--out", default="cross_file_results.json")
    ap.add_argument("--depth-limit", type=int, default=None, help="Max BFS depth from entry points")
    ap.add_argument("--entry-points", nargs="*", default=None)
    ap.add_argument("--format", choices=["json", "markdown"], default="json")
    args = ap.parse_args()

    analyzer = CrossFileReachabilityAnalyzer(
        entry_points=args.entry_points, depth_limit=args.depth_limit
    )
    result = analyzer.analyze(args.source_root, args.scan)

    if args.format == "markdown":
        out_path = args.out if args.out.endswith(".md") else args.out.rsplit(".", 1)[0] + ".md"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(to_markdown(result, args.depth_limit))
        print(f"Wrote {out_path}")
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "reachable_by_depth": result["reachable_by_depth"],
                    "tagged_findings": result["tagged_findings"],
                },
                f,
                indent=2,
            )
        print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
