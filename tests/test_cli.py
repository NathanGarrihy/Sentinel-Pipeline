import json

from typer.testing import CliRunner

from sentinel.cli.main import app

runner = CliRunner()


class TestVerifyEnv:
    def test_exit_code_zero(self) -> None:
        result = runner.invoke(app, ["verify-env"])
        assert result.exit_code == 0

    def test_output_is_valid_json(self) -> None:
        result = runner.invoke(app, ["verify-env"])
        # Rich console output may include ANSI codes; strip them
        output = result.output.strip()
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_output_contains_pdr_fields(self) -> None:
        result = runner.invoke(app, ["verify-env"])
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
