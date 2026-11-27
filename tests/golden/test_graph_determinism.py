# SPDX-License-Identifier: Apache-2.0
"""Phase 10.3 determinism golden test (Exit Gate #6, ADR-031)."""

import json
import os
from pathlib import Path

from siftsec.ingest.graph import build_graph_and_score

_SCENARIO_1 = (
    Path(__file__).resolve().parents[1] / "fixtures" / "graph" / "scenario_1_notebook_to_s3.json"
)


def test_graph_determinism_across_10_runs_and_thread_counts() -> None:
    """ADR-031: 10 runs across RAYON_NUM_THREADS in {1, 2, 4, 8} must be byte-identical."""
    payload = json.loads(_SCENARIO_1.read_text(encoding="utf-8"))
    outputs: list[str] = []
    thread_counts = ["1", "2", "4", "8", "1", "2", "4", "8", "1", "4"]

    prev = os.environ.get("RAYON_NUM_THREADS")
    try:
        for threads in thread_counts:
            os.environ["RAYON_NUM_THREADS"] = threads
            res = build_graph_and_score(payload)
            outputs.append(res.model_dump_json(by_alias=True))
    finally:
        if prev is None:
            os.environ.pop("RAYON_NUM_THREADS", None)
        else:
            os.environ["RAYON_NUM_THREADS"] = prev

    assert len(outputs) == 10
    assert len(set(outputs)) == 1
