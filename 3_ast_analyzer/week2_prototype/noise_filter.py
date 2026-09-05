import tree_sitter_python as tspython
from tree_sitter import Language, Parser

PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)

DEFAULT_ENTRY_POINTS = ["main", "handle_login", "get_user_prof_file"]


def extract_functions(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()
    tree = parser.parse(bytes(code, "utf-8"))
    root = tree.root_node

    calls = {}
    current_func = None

    def walk(node):
        nonlocal current_func
        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                current_func = code[name_node.start_byte:name_node.end_byte]
                calls.setdefault(current_func, [])
        elif node.type == "call" and current_func:
            fn_node = node.child_by_field_name("function")
            if fn_node:
                callee = code[fn_node.start_byte:fn_node.end_byte]
                calls[current_func].append(callee)
        for child in node.children:
            walk(child)

    walk(root)
    return calls


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "../week1_foundations/sample_mock.py"
    graph = extract_functions(target)
    for fn, callees in graph.items():
        print(f"{fn} -> {callees}")

