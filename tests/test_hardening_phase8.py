import json
import logging
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from siftsec.cli import app
from siftsec.utils.logger import configure_logging

runner = CliRunner()


def test_json_logger_redacts_secrets(capsys: pytest.CaptureFixture[str]) -> None:
    log = configure_logging(verbose=True, json_logs=True)
    log.warning("Leaked key AKIAIOSFODNN7EXAMPLE in test")
    captured = capsys.readouterr().err.strip()
    data = json.loads(captured)
    assert data["level"] == "WARNING"
    assert "AKIAIOSFODNN7EXAMPLE" not in data["message"]
    assert "AKIA****" in data["message"]
    # Reset back to Rich handler after test
    configure_logging()


def test_cli_timings_debug_bundle_and_plugins(tmp_path: Path) -> None:
    bundle = tmp_path / "diag.zip"
    res = runner.invoke(
        app,
        ["scan", "--demo", "--timings", "--log-json", "--debug-bundle", str(bundle)],
    )
    assert res.exit_code in (0, 1)
    assert bundle.exists()

    with zipfile.ZipFile(bundle, "r") as zf:
        names = set(zf.namelist())
        assert {
            "versions.json",
            "config_effective.json",
            "coverage_gaps.json",
            "timings.json",
        } <= names
        timings_data = json.loads(zf.read("timings.json"))
        assert "collect_seconds" in timings_data
        assert "evaluate_seconds" in timings_data
        versions_data = json.loads(zf.read("versions.json"))
        assert "siftsec" in versions_data

    res_plugins = runner.invoke(app, ["plugins"])
    assert res_plugins.exit_code == 0

    # Ensure root siftsec logger still works without raising
    assert logging.getLogger("siftsec") is not None
