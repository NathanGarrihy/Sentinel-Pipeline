import os

import pytest
from typer.testing import CliRunner

from sentinel.cli.main import app

runner = CliRunner()

VALID_CONFIG = """\
sentinel:
  version: "0.1.0"
  policy_version: "0.1.0"
  scanners:
    - name: echo
      command: ["echo", "{target}"]
      type: sast
      required: false
  signing:
    tool: python
"""

CONFIG_WITH_OPTIONAL = """\
sentinel:
  version: "0.1.0"
  policy_version: "0.1.0"
  scanners:
    - name: echo
      command: ["echo", "{target}"]
      type: sast
      required: true
    - name: false_tool
      command: ["__sentinel_nonexistent__", "{target}"]
      type: iac
      required: false
  signing:
    tool: python
"""


@pytest.fixture()
def config_file(tmp_path):
    f = tmp_path / "sentinel.yaml"
    f.write_text(VALID_CONFIG)
    original = os.getcwd()
    os.chdir(tmp_path)
    yield f
    os.chdir(original)


@pytest.fixture()
def config_with_optional(tmp_path):
    f = tmp_path / "sentinel.yaml"
    f.write_text(CONFIG_WITH_OPTIONAL)
    original = os.getcwd()
    os.chdir(tmp_path)
    yield f
    os.chdir(original)


class TestScanCommand:
    def test_exits_zero_when_required_scanner_succeeds(self, config_file) -> None:
        result = runner.invoke(app, ["--skip-preflight", "scan", "--skip-signing", "myapp:latest"])
        assert result.exit_code == 0

    def test_target_is_injected(self, config_file) -> None:
        """The target argument must appear in the summary output."""
        result = runner.invoke(app, ["--skip-preflight", "scan", "--skip-signing", "myapp:latest"])
        assert "myapp:latest" in result.output

    def test_summary_table_contains_scanner_name(self, config_file) -> None:
        result = runner.invoke(app, ["--skip-preflight", "scan", "--skip-signing", "."])
        assert "echo" in result.output

    def test_missing_target_argument_exits_nonzero(self, config_file) -> None:
        result = runner.invoke(app, ["--skip-preflight", "scan"])
        assert result.exit_code != 0

    def test_scan_command_registered(self, config_file) -> None:
        """Ensure 'scan' appears in the help output."""
        result = runner.invoke(app, ["--help"])
        assert "scan" in result.output
