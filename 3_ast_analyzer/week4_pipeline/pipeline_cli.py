"""
Week 4 - Automated Pipeline Filtering Integration (UPDATED for Week 5)
Adds --depth-limit and --format flags per Gemini plan: routes to the
cross-file engine (week5) when either flag is used, otherwise runs the
original single-file week3 engine unchanged.
"""
import argparse
import json
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "week3_reachability"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "week5_cross_file"))
from ast_engine import ASTReachabilityAnalyzer  # noqa: E402
from cross_file_engine import CrossFileReachabilityAnalyzer, to_markdown  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("filter_pipeline")


def run_single_file(source_file, scan_results_path, output_path, entry_points=None):
    analyzer = ASTReachabilityAnalyzer(entry_points=entry_points)
    result = analyzer.analyze(source_file, scan_results_path)

    clean = [f for f in result["tagged_findings"] if f["reachability"] == "REACHABLE_CODE"]
    noise = [f for f in result["tagged_findings"] if f["reachability"] == "UNREACHABLE_NOISE"]

    output = {
        "summary": {
            "total_findings": len(result["tagged_findings"]),
            "reachable": len(clean),
            "noise_filtered": len(noise),
        },
        "reachable_functions": result["reachable_functions"],
        "clean_findings": clean,
        "filtered_noise": noise,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    return output


def run_cross_file(source_root, scan_results_path, output_path, entry_points, depth_limit, out_format):
    analyzer = CrossFileReachabilityAnalyzer(entry_points=entry_points, depth_limit=depth_limit)
    result = analyzer.analyze(source_root, scan_results_path)

    if out_format == "markdown":
        md_path = output_path if output_path.endswith(".md") else output_path.rsplit(".", 1)[0] + ".md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(to_markdown(result, depth_limit))
        logger.info("Wrote markdown report to %s", md_path)
        return {"output_path": md_path, "tagged_findings": result["tagged_findings"]}

    clean = [f for f in result["tagged_findings"] if f["reachability"] == "REACHABLE_CODE"]
    noise = [f for f in result["tagged_findings"] if f["reachability"] == "UNREACHABLE_NOISE"]
    output = {
        "summary": {
            "total_findings": len(result["tagged_findings"]),
            "reachable": len(clean),
            "noise_filtered": len(noise),
            "depth_limit": depth_limit,
        },
        "clean_findings": clean,
        "filtered_noise": noise,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    return output


def main():
    parser = argparse.ArgumentParser(description="AutoForge noise-filtering pipeline (Week 4 + Week 5)")
    parser.add_argument("--input", default="combined_scan_results.json")
    parser.add_argument("--output", default="filtered_scan_results.json")
    parser.add_argument("--source", help="Single source .py file (week3 mode)")
    parser.add_argument("--source-root", help="Project root dir - triggers cross-file mode (week5)")
    parser.add_argument("--entry-points", nargs="*", default=None)
    parser.add_argument("--depth-limit", type=int, default=None, help="Max BFS depth (week5 cross-file mode)")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        logger.error("Input file not found: %s", args.input)
        sys.exit(1)

    if args.source_root or args.depth_limit is not None or args.format == "markdown":
        # Week 5 cross-file mode
        source_root = args.source_root or "."
        output = run_cross_file(
            source_root, args.input, args.output, args.entry_points, args.depth_limit, args.format
        )
        logger.info("Cross-file pipeline complete -> %s", args.output)
    else:
        # Week 3/4 single-file mode (unchanged behavior)
        source = args.source or args.input
        output = run_single_file(source, args.input, args.output, args.entry_points)
        logger.info("Single-file pipeline complete -> %s", args.output)

    print(json.dumps(output.get("summary", {}), indent=2))


if __name__ == "__main__":
    main()
