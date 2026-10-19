"""Process-pool execution for independent source-file analysis tasks."""

from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor
from typing import Callable, Iterable, TypeVar

Input = TypeVar("Input")
Output = TypeVar("Output")


class ParallelExecutor:
    def __init__(self, max_workers: int | None = None) -> None:
        if max_workers is not None and max_workers < 1:
            raise ValueError("max_workers must be positive")
        self.max_workers = max_workers or (os.cpu_count() or 1)

    def map(self, function: Callable[[Input], Output], items: Iterable[Input]) -> list[Output]:
        work = list(items)
        if not work:
            return []
        workers = min(self.max_workers, len(work))
        if workers == 1:
            return [function(item) for item in work]
        with ProcessPoolExecutor(max_workers=workers) as executor:
            return list(executor.map(function, work))
