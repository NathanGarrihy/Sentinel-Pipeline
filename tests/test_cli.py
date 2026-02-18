import json
import os

import pytest
from typer.testing import CliRunner

from sentinel.cli.main import app

runner = CliRunner()

# All CLI tests need a valid config file and --skip-preflight
# because the callback now loads sentinel.yaml before any command runs.
VALID_CONFIG = """\
sentinel:
  version: "0.1.0"
  scanners:
    - name: echo
      command: ["echo"]
      type: sast
  signing:
    tool: python
"""


@pytest.fixture()
def config_file(tmp_path):
    """Create a temporary sentinel.yaml and chdir to its directory."""
    f = tmp_path / "sentinel.yaml"
    f.write_text(VALID_CONFIG)
    original = os.getcwd()
    os.chdir(tmp_path)
    yield f
    os.chdir(original)


class TestVerifyEnv:
    def test_exit_code_zero(self, config_file) -> None:
        result = runner.invoke(app, ["--skip-preflight", "verify-env"])
        assert result.exit_code == 0

    def test_output_is_valid_json(self, config_file) -> None:
        result = runner.invoke(app, ["--skip-preflight", "verify-env"])
        # Rich console output may include ANSI codes; strip them
        output = result.output.strip()
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_output_contains_pdr_fields(self, config_file) -> None:
        result = runner.invoke(app, ["--skip-preflight", "verify-env"])
        output = result.output.strip()
        data = json.loads(output)
        assert "input_hash" in data
        assert "policy_version" in data
        assert "decision" in data
        assert "evidence_path" in data
        assert "timestamp" in data
        assert data["decision"] == "PASS"
        assert data["policy_version"] == "0.1.0"
        assert data["evidence_path"] == "stdout://verify-env"


class TestCLICallback:
    def test_missing_config_exits_with_error(self, tmp_path) -> None:
        result = runner.invoke(
            app, ["--config", str(tmp_path / "nonexistent.yaml"), "verify-env"]
        )
        assert result.exit_code == 1

    def test_skip_preflight_flag(self, config_file) -> None:
        result = runner.invoke(app, ["--skip-preflight", "verify-env"])
        assert result.exit_code == 0

    def test_explicit_config_path(self, config_file) -> None:
        result = runner.invoke(
            app, ["--config", str(config_file), "--skip-preflight", "verify-env"]
        )
        assert result.exit_code == 0
