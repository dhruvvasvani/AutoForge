from __future__ import annotations

import argparse
import os
import shutil
import uuid
from pathlib import Path


def promote(candidate: Path, active: Path) -> None:
    candidate = candidate.resolve(strict=True)
    active = active.resolve()
    if not candidate.is_file():
        raise ValueError("candidate checkpoint must be a file")
    if candidate == active:
        raise ValueError("candidate and active checkpoint must be different files")
    active.parent.mkdir(parents=True, exist_ok=True)
    temporary = active.with_name(f".{active.name}.{uuid.uuid4().hex}.tmp")
    try:
        shutil.copy2(candidate, temporary)
        if temporary.stat().st_size == 0:
            raise ValueError("candidate checkpoint is empty")
        os.replace(temporary, active)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Atomically promote a manually reviewed CPG-GNN checkpoint."
    )
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--active", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        promote(arguments.candidate, arguments.active)
    except OSError as error:
        parser.error(f"checkpoint promotion failed: {error}")
    except ValueError as error:
        parser.error(str(error))
    print(f"Promoted {arguments.candidate} to {arguments.active}")


if __name__ == "__main__":
    main()
