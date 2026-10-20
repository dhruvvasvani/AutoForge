"""Generate labeled synthetic feature rows for noise-filter development tests."""

from __future__ import annotations

import json
import random
from pathlib import Path


def generate_ast_dataset(
    num_samples: int = 500,
    output_file: str | Path | None = None,
    seed: int = 42,
) -> str:
    if isinstance(num_samples, bool) or not isinstance(num_samples, int) or num_samples < 1:
        raise ValueError("num_samples must be a positive integer")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")

    destination = (
        Path(output_file)
        if output_file is not None
        else Path(__file__).resolve().parents[2] / "data" / "synthetic_ast_dataset.json"
    )
    rng = random.Random(seed)
    dataset = []
    for index in range(num_samples):
        tainted = rng.choice((0, 1))
        complexity = rng.randint(1, 20)
        nesting = rng.randint(1, 8)
        sink_distance = rng.randint(1, 10)
        sanitizer_present = rng.choice((0, 1))
        is_vulnerability = int(
            tainted == 1
            and not sanitizer_present
            and sink_distance <= 3
            and complexity > 2
        )
        dataset.append(
            {
                "id": f"synthetic_ast_node_{index}",
                "cyclomatic_complexity": complexity,
                "max_nesting_depth": nesting,
                "sink_distance": sink_distance,
                "user_input_tainted": tainted,
                "sanitizer_present": sanitizer_present,
                "is_real_vulnerability": is_vulnerability,
            }
        )

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(dataset, indent=2), encoding="utf-8")
    return str(destination)


if __name__ == "__main__":
    print(f"Generated synthetic AST feature data at: {generate_ast_dataset()}")
