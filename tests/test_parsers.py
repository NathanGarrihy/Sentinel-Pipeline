"""Tests for scanner output parsers.

Each parser class is tested independently. Tests cover:
  - Happy path (valid JSON, expected exit codes)
  - Empty stdout
  - Malformed JSON
  - Tool-specific exit code semantics (e.g. semgrep exit 2 = error)
  - Edge cases documented in the architecture review
"""

import json

from sentinel.core.parsers.checkov import CheckovParser
from sentinel.core.parsers.semgrep import SemgrepParser
from sentinel.core.parsers.syft import SyftParser
from sentinel.core.parsers.trivy import TrivyParser


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------

class TestSemgrepParser:
    def setup_method(self):
        self.parser = SemgrepParser()

    def test_pass_no_findings(self) -> None:
        stdout = json.dumps({"results": [], "errors": []})
        result = self.parser.parse(stdout, exit_code=0)
        assert result.finding_count == 0
        assert result.is_error is False

    def test_findings_present(self) -> None:
        stdout = json.dumps({"results": [{"check_id": "rule1"}, {"check_id": "rule2"}]})
        result = self.parser.parse(stdout, exit_code=1)
        assert result.finding_count == 2
        assert result.is_error is False

    def test_exit_2_is_error(self) -> None:
        # Exit 2 = semgrep config/parse error — not a policy verdict
        result = self.parser.parse("", exit_code=2)
        assert result.is_error is True
        assert "error code 2" in result.parse_error

    def test_exit_3_is_error(self) -> None:
        result = self.parser.parse("", exit_code=3)
        assert result.is_error is True

    def test_empty_stdout_is_error(self) -> None:
        result = self.parser.parse("", exit_code=0)
        assert result.is_error is True
        assert result.parse_error is not None

    def test_malformed_json_is_error(self) -> None:
        result = self.parser.parse("{not valid json", exit_code=1)
        assert result.is_error is True

    def test_missing_results_key_is_error(self) -> None:
        result = self.parser.parse(json.dumps({"errors": []}), exit_code=0)
        assert result.is_error is True

    def test_raw_findings_populated(self) -> None:
        findings = [{"check_id": "rule1"}]
        stdout = json.dumps({"results": findings})
        result = self.parser.parse(stdout, exit_code=1)
        assert result.raw_findings == findings


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------

class TestTrivyParser:
    def setup_method(self):
        self.parser = TrivyParser()

    def test_pass_no_vulnerabilities(self) -> None:
        # Clean image — Results is null
        stdout = json.dumps({"SchemaVersion": 2, "Results": None})
        result = self.parser.parse(stdout, exit_code=0)
        assert result.finding_count == 0
        assert result.is_error is False

    def test_pass_empty_results_list(self) -> None:
        stdout = json.dumps({"Results": []})
        result = self.parser.parse(stdout, exit_code=0)
        assert result.finding_count == 0
        assert result.is_error is False

    def test_vulnerabilities_counted(self) -> None:
        stdout = json.dumps({
            "Results": [
                {"Target": "layer1", "Vulnerabilities": [{"VulnID": "CVE-1"}, {"VulnID": "CVE-2"}]},
                {"Target": "layer2", "Vulnerabilities": [{"VulnID": "CVE-3"}]},
            ]
        })
        result = self.parser.parse(stdout, exit_code=1)
        assert result.finding_count == 3
        assert result.is_error is False

    def test_null_vulnerabilities_in_result(self) -> None:
        # Some Results entries have null Vulnerabilities — must not crash
        stdout = json.dumps({
            "Results": [{"Target": "layer1", "Vulnerabilities": None}]
        })
        result = self.parser.parse(stdout, exit_code=0)
        assert result.finding_count == 0
        assert result.is_error is False

    def test_exit_2_is_error(self) -> None:
        result = self.parser.parse("", exit_code=2)
        assert result.is_error is True
        assert "error code 2" in result.parse_error

    def test_empty_stdout_is_error(self) -> None:
        result = self.parser.parse("", exit_code=0)
        assert result.is_error is True

    def test_malformed_json_is_error(self) -> None:
        result = self.parser.parse("{bad", exit_code=1)
        assert result.is_error is True


# ---------------------------------------------------------------------------
# Checkov
# ---------------------------------------------------------------------------

class TestCheckovParser:
    def setup_method(self):
        self.parser = CheckovParser()

    def test_pass_no_failures(self) -> None:
        stdout = json.dumps({"results": {"passed_checks": [], "failed_checks": []}})
        result = self.parser.parse(stdout, exit_code=0)
        assert result.finding_count == 0
        assert result.is_error is False

    def test_failures_counted(self) -> None:
        stdout = json.dumps({
            "results": {"failed_checks": [{"check_id": "CKV_1"}, {"check_id": "CKV_2"}]}
        })
        result = self.parser.parse(stdout, exit_code=1)
        assert result.finding_count == 2
        assert result.is_error is False

    def test_array_output_flattened(self) -> None:
        # Checkov recursive mode emits a JSON array
        stdout = json.dumps([
            {"results": {"failed_checks": [{"check_id": "CKV_1"}]}},
            {"results": {"failed_checks": [{"check_id": "CKV_2"}, {"check_id": "CKV_3"}]}},
        ])
        result = self.parser.parse(stdout, exit_code=1)
        assert result.finding_count == 3
        assert result.is_error is False

    def test_empty_stdout_is_error(self) -> None:
        result = self.parser.parse("", exit_code=0)
        assert result.is_error is True

    def test_malformed_json_is_error(self) -> None:
        result = self.parser.parse("{bad", exit_code=1)
        assert result.is_error is True

    def test_missing_failed_checks_key(self) -> None:
        # Unexpected schema — should not crash, treat as 0 failures
        stdout = json.dumps({"results": {}})
        result = self.parser.parse(stdout, exit_code=0)
        assert result.finding_count == 0
        assert result.is_error is False


# ---------------------------------------------------------------------------
# Syft
# ---------------------------------------------------------------------------

class TestSyftParser:
    def setup_method(self):
        self.parser = SyftParser()

    def test_pass_valid_sbom(self) -> None:
        stdout = json.dumps({"schema": {}, "artifacts": [{"name": "pkg1"}]})
        result = self.parser.parse(stdout, exit_code=0)
        assert result.finding_count == 0
        assert result.is_error is False

    def test_nonzero_exit_is_error(self) -> None:
        result = self.parser.parse("", exit_code=1)
        assert result.is_error is True
        assert "code 1" in result.parse_error

    def test_empty_stdout_is_error(self) -> None:
        result = self.parser.parse("", exit_code=0)
        assert result.is_error is True

    def test_missing_artifacts_key_is_error(self) -> None:
        # Output that looks like JSON but is not a syft SBOM
        stdout = json.dumps({"something": "else"})
        result = self.parser.parse(stdout, exit_code=0)
        assert result.is_error is True
        assert "artifacts" in result.parse_error

    def test_malformed_json_is_error(self) -> None:
        result = self.parser.parse("{bad", exit_code=0)
        assert result.is_error is True
