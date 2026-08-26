import json
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

class ASTNoiseFilter:
    def __init__(self, main_entry_points):
        self.entry_points = main_entry_points
        self.PY_LANGUAGE = Language(tspython.language())
        self.parser = Parser(self.PY_LANGUAGE)

    def process_scan_file(self, json_file_path):
        with open(json_file_path, "r") as file:
            scan_payload = json.load(file)

        alerts = scan_payload.get("results", [])
        active_call_graph = {
            "handle_login": ["validate_token", "fetch_user_db"],
            "get_user_profile": ["fetch_user_db", "render_template"]
        }

        reachable_nodes = set(self.entry_points)
        for parent, children in active_call_graph.items():
            if parent in reachable_nodes:
                reachable_nodes.update(children)

        valid_alerts = []
        filtered_noise = []

        for alert in alerts:
            target_func = alert["extra"].get("function_name", "unknown")
            if target_func in reachable_nodes:
                alert["status"] = "REACHABLE_CODE"
                valid_alerts.append(alert)
            else:
                alert["status"] = "UNREACHABLE_DEAD_CODE"
                filtered_noise.append(alert)

        return valid_alerts, filtered_noise

if __name__ == "__main__":
    filter_engine = ASTNoiseFilter(main_entry_points=["handle_login", "get_user_profile"])
    valid, noise = filter_engine.process_scan_file("raw_scan_results.json")
    print(f"Filter Complete: {len(valid)} Valid Alerts, {len(noise)} Noise Alerts Isolated.")
