import tree_sitter_python as tspython
from tree_sitter import Language, Parser

PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)


def parse_file(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()
    tree = parser.parse(bytes(code, "utf-8"))
    return tree, code


def print_tree(node, code, depth=0):
    label = node.type
    if node.type == "identifier":
        label += f" ({code[node.start_byte:node.end_byte]})"
    print("  " * depth + label)
    for child in node.children:
        print_tree(child, code, depth + 1)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "week1_foundations/sample_mock.py"
    tree, code = parse_file(target)
    print_tree(tree.root_node, code)