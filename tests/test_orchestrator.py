from unittest.mock import MagicMock

import pytest

from sentinel.core.config import ScannerConfig, ScannerType, SentinelConfig, SigningConfig
from sentinel.core.orchestrator import inject_target, run_scan
from sentinel.models.execution import ExecutionResult


def _make_result(stdout: str = "", exit_code: int = 0) -> ExecutionResult:
    import hashlib
    return ExecutionResult(
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
        output_hash=hashlib.sha256(stdout.encode()).hexdigest(),
    )


def _make_config(scanners: list[ScannerConfig]) -> SentinelConfig:
    return SentinelConfig(
        version="0.1.0",
        policy_version="0.1.0",
        scanners=scanners,
        signing=SigningConfig(tool="cosign", required=True),
    )


class TestInjectTarget:
    def test_replaces_placeholder(self) -> None:
        cmd = ["trivy", "image", "--format", "json", "{target}"]
        assert inject_target(cmd, "myapp:latest") == [
            "trivy", "image", "--format", "json", "myapp:latest"
        ]

    def test_replaces_multiple_occurrences(self) -> None:
        cmd = ["tool", "{target}", "--label", "{target}"]
        assert inject_target(cmd, "foo") == ["tool", "foo", "--label", "foo"]

    def test_no_placeholder_returns_command_unchanged(self) -> None:
        cmd = ["checkov", "-d", ".", "--output", "json"]
        assert inject_target(cmd, "myapp:latest") == cmd

    def test_empty_target_string(self) -> None:
        cmd = ["semgrep", "scan", "{target}"]
        assert inject_target(cmd, "") == ["semgrep", "scan", ""]

    def test_does_not_mutate_original(self) -> None:
        cmd = ["trivy", "{target}"]
        original = cmd.copy()
        inject_target(cmd, "foo")
        assert cmd == original


class TestRunScan:
    def _make_mock_executor(self, results: list[ExecutionResult]) -> MagicMock:
        executor = MagicMock()
        executor.execute.side_effect = results
        return executor

    def test_returns_one_result_per_scanner(self) -> None:
        config = _make_config([
            ScannerConfig(name="semgrep", command=["semgrep", "{target}"], type=ScannerType.SAST),
            ScannerConfig(name="trivy", command=["trivy", "{target}"], type=ScannerType.SCA),
        ])
        executor = self._make_mock_executor([_make_result("out1"), _make_result("out2")])

        results = run_scan(config, ".", executor)

        assert len(results) == 2
        assert results[0].scanner_name == "semgrep"
        assert results[1].scanner_name == "trivy"

    def test_target_stored_on_scan_result(self) -> None:
        config = _make_config([
            ScannerConfig(name="trivy", command=["trivy", "{target}"], type=ScannerType.SCA),
        ])
        executor = self._make_mock_executor([_make_result()])

        results = run_scan(config, "myapp:latest", executor)

        assert results[0].target == "myapp:latest"

    def test_target_is_injected_into_command(self) -> None:
        config = _make_config([
            ScannerConfig(
                name="trivy",
                command=["trivy", "image", "{target}"],
                type=ScannerType.SCA,
            ),
        ])
        executor = self._make_mock_executor([_make_result()])

        run_scan(config, "myapp:latest", executor)

        executor.execute.assert_called_once_with(["trivy", "image", "myapp:latest"])

    def test_scan_result_preserves_scanner_type(self) -> None:
        config = _make_config([
            ScannerConfig(name="syft", command=["syft", "{target}"], type=ScannerType.SBOM),
        ])
        executor = self._make_mock_executor([_make_result()])

        results = run_scan(config, "myapp:latest", executor)

        assert results[0].scanner_type == ScannerType.SBOM

    def test_scan_result_command_is_injected_tuple(self) -> None:
        config = _make_config([
            ScannerConfig(name="trivy", command=["trivy", "{target}"], type=ScannerType.SCA),
        ])
        executor = self._make_mock_executor([_make_result()])

        results = run_scan(config, "myapp:latest", executor)

        assert results[0].command == ("trivy", "myapp:latest")

    def test_all_scanners_run_even_if_one_exits_nonzero(self) -> None:
        """Non-zero exit must not abort the loop — all scanners must run."""
        config = _make_config([
            ScannerConfig(name="semgrep", command=["semgrep", "{target}"], type=ScannerType.SAST),
            ScannerConfig(name="trivy", command=["trivy", "{target}"], type=ScannerType.SCA),
        ])
        executor = self._make_mock_executor([
            _make_result(exit_code=1),  # semgrep finds issues
            _make_result(exit_code=0),  # trivy clean
        ])

        results = run_scan(config, ".", executor)

        assert len(results) == 2
        assert executor.execute.call_count == 2

    def test_execution_result_is_passed_through(self) -> None:
        execution = _make_result(stdout="findings", exit_code=1)
        config = _make_config([
            ScannerConfig(name="semgrep", command=["semgrep", "{target}"], type=ScannerType.SAST),
        ])
        executor = self._make_mock_executor([execution])

        results = run_scan(config, ".", executor)

        assert results[0].result is execution
