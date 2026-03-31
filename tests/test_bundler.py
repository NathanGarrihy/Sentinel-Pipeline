"""Tests for sentinel.core.bundler.

Covers bundle structure, manifest hash correctness, all signing paths
(success / failure / skipped), and atomic write behaviour.
"""

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentinel.core.bundler import BundleResult, build_bundle
from sentinel.core.config import ScannerType
from sentinel.models.execution import ExecutionResult
from sentinel.models.pdr import Decision, PolicyDecisionRecord
from sentinel.models.scan_result import ScanResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_execution_result(stdout: str = '{"findings": []}', exit_code: int = 0) -> ExecutionResult:
    return ExecutionResult(
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
        output_hash=hashlib.sha256(stdout.encode()).hexdigest(),
    )


def _make_scan_result(
    name: str = "semgrep",
    scanner_type: ScannerType = ScannerType.SAST,
    stdout: str = '{"findings": []}',
    exit_code: int = 0,
) -> ScanResult:
    return ScanResult(
        scanner_name=name,
        scanner_type=scanner_type,
        command=(name, "."),
        target=".",
        result=_make_execution_result(stdout, exit_code),
    )


def _make_pdr(name: str = "semgrep", decision: Decision = Decision.PASS) -> PolicyDecisionRecord:
    return PolicyDecisionRecord(
        input_hash=hashlib.sha256(b".").hexdigest(),
        policy_version="1.0.0",
        decision=decision,
        evidence_path=f"raw/{name}-output.json",
        timestamp=datetime.now(UTC),
    )


def _mock_cosign_executor(exit_code: int = 0, stderr: str = "") -> MagicMock:
    """Return a mock executor that simulates a cosign sign-blob call.

    On success (exit_code=0) it writes a dummy file at the path given by
    --output-signature, exactly as the real cosign binary would.
    """
    def _side_effect(command: list[str]) -> ExecutionResult:
        if exit_code == 0:
            # Write the dummy signature file so the bundler can zip it
            try:
                sig_path = Path(command[command.index("--output-signature") + 1])
                sig_path.write_text("MOCK_SIGNATURE", encoding="utf-8")
            except (ValueError, IndexError):
                pass
        return ExecutionResult(
            stdout="",
            stderr=stderr,
            exit_code=exit_code,
            output_hash=hashlib.sha256(b"").hexdigest(),
        )

    executor = MagicMock()
    executor.execute.side_effect = _side_effect
    return executor


def _zip_names(path: Path) -> set[str]:
    with zipfile.ZipFile(path) as zf:
        return set(zf.namelist())


def _zip_json(path: Path, member: str) -> dict:
    with zipfile.ZipFile(path) as zf:
        return json.loads(zf.read(member))


# ---------------------------------------------------------------------------
# Bundle structure
# ---------------------------------------------------------------------------

class TestBundleStructure:
    def test_required_files_present(self, tmp_path: Path) -> None:
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", _mock_cosign_executor(), tmp_path / "evidence.zip",
        )
        names = _zip_names(result.path)
        assert "manifest.json" in names
        assert "signing_status.json" in names
        assert "raw/semgrep-output.json" in names
        assert "pdr/pdr-semgrep.json" in names

    def test_multiple_scanners_all_files_present(self, tmp_path: Path) -> None:
        srs = [
            _make_scan_result("semgrep", ScannerType.SAST),
            _make_scan_result("trivy", ScannerType.SCA),
        ]
        pdrs = [_make_pdr("semgrep"), _make_pdr("trivy")]
        result = build_bundle(srs, pdrs, "1.0.0", _mock_cosign_executor(), tmp_path / "evidence.zip")

        names = _zip_names(result.path)
        for expected in [
            "raw/semgrep-output.json", "raw/trivy-output.json",
            "pdr/pdr-semgrep.json", "pdr/pdr-trivy.json",
        ]:
            assert expected in names

    def test_raw_file_content_matches_scanner_stdout(self, tmp_path: Path) -> None:
        raw = '{"results": [{"check_id": "sql-injection"}]}'
        result = build_bundle(
            [_make_scan_result(stdout=raw)], [_make_pdr()],
            "1.0.0", _mock_cosign_executor(), tmp_path / "evidence.zip",
        )
        with zipfile.ZipFile(result.path) as zf:
            assert zf.read("raw/semgrep-output.json").decode() == raw

    def test_empty_stdout_writes_empty_raw_file(self, tmp_path: Path) -> None:
        """Crashed scanner (no output) must still produce its evidence_path entry."""
        result = build_bundle(
            [_make_scan_result(stdout="", exit_code=1)], [_make_pdr(decision=Decision.FAIL)],
            "1.0.0", _mock_cosign_executor(), tmp_path / "evidence.zip",
        )
        with zipfile.ZipFile(result.path) as zf:
            assert zf.read("raw/semgrep-output.json") == b""


# ---------------------------------------------------------------------------
# Manifest correctness
# ---------------------------------------------------------------------------

class TestManifest:
    def test_contains_policy_version(self, tmp_path: Path) -> None:
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "2.3.1", _mock_cosign_executor(), tmp_path / "evidence.zip",
        )
        assert _zip_json(result.path, "manifest.json")["policy_version"] == "2.3.1"

    def test_pdr_hashes_verify_against_zip_contents(self, tmp_path: Path) -> None:
        """SHA-256 entries in manifest must match the actual PDR bytes in the zip."""
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", _mock_cosign_executor(), tmp_path / "evidence.zip",
        )
        manifest = _zip_json(result.path, "manifest.json")
        with zipfile.ZipFile(result.path) as zf:
            for pdr_path, expected_hash in manifest["pdrs"].items():
                actual = hashlib.sha256(zf.read(pdr_path)).hexdigest()
                assert actual == expected_hash

    def test_contains_timestamp(self, tmp_path: Path) -> None:
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", _mock_cosign_executor(), tmp_path / "evidence.zip",
        )
        manifest = _zip_json(result.path, "manifest.json")
        assert "timestamp" in manifest
        assert manifest["timestamp"]  # non-empty string


# ---------------------------------------------------------------------------
# Signing paths
# ---------------------------------------------------------------------------

class TestSigning:
    def test_success_returns_signed_status(self, tmp_path: Path) -> None:
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", _mock_cosign_executor(exit_code=0), tmp_path / "evidence.zip",
        )
        assert result.signing_status == "signed"
        assert result.signing_error is None

    def test_success_includes_sig_in_zip(self, tmp_path: Path) -> None:
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", _mock_cosign_executor(exit_code=0), tmp_path / "evidence.zip",
        )
        assert "signature.sig" in _zip_names(result.path)

    def test_failure_returns_failed_status(self, tmp_path: Path) -> None:
        executor = _mock_cosign_executor(exit_code=1, stderr="OIDC token not available")
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", executor, tmp_path / "evidence.zip",
        )
        assert result.signing_status == "failed"
        assert "OIDC token not available" in (result.signing_error or "")

    def test_failure_still_writes_bundle(self, tmp_path: Path) -> None:
        """Bundle must be written even when cosign fails."""
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", _mock_cosign_executor(exit_code=1, stderr="err"), tmp_path / "evidence.zip",
        )
        assert result.path.exists()
        assert "manifest.json" in _zip_names(result.path)

    def test_failure_no_sig_in_zip(self, tmp_path: Path) -> None:
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", _mock_cosign_executor(exit_code=1), tmp_path / "evidence.zip",
        )
        assert "signature.sig" not in _zip_names(result.path)

    def test_failure_fallback_error_mentions_exit_code(self, tmp_path: Path) -> None:
        """When cosign stderr is empty, signing_error must still mention the exit code."""
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", _mock_cosign_executor(exit_code=2, stderr=""), tmp_path / "evidence.zip",
        )
        assert result.signing_error is not None
        assert "2" in result.signing_error

    def test_skip_signing_returns_skipped_status(self, tmp_path: Path) -> None:
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", MagicMock(), tmp_path / "evidence.zip", skip_signing=True,
        )
        assert result.signing_status == "skipped"
        assert result.signing_error is None

    def test_skip_signing_does_not_invoke_executor(self, tmp_path: Path) -> None:
        executor = MagicMock()
        build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", executor, tmp_path / "evidence.zip", skip_signing=True,
        )
        executor.execute.assert_not_called()

    def test_skip_signing_no_sig_in_zip(self, tmp_path: Path) -> None:
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", MagicMock(), tmp_path / "evidence.zip", skip_signing=True,
        )
        assert "signature.sig" not in _zip_names(result.path)

    @pytest.mark.parametrize("skip,exit_code", [(True, 0), (False, 0), (False, 1)])
    def test_signing_status_json_always_present(
        self, tmp_path: Path, skip: bool, exit_code: int
    ) -> None:
        """signing_status.json must appear in the zip for every signing outcome."""
        out = tmp_path / f"evidence_{skip}_{exit_code}.zip"
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", _mock_cosign_executor(exit_code), out, skip_signing=skip,
        )
        assert "signing_status.json" in _zip_names(result.path)


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------

class TestAtomicWrite:
    def test_output_written_to_correct_path(self, tmp_path: Path) -> None:
        out = tmp_path / "my-evidence.zip"
        result = build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", _mock_cosign_executor(), out,
        )
        assert result.path == out
        assert out.exists()

    def test_tmp_file_not_left_behind(self, tmp_path: Path) -> None:
        out = tmp_path / "evidence.zip"
        build_bundle(
            [_make_scan_result()], [_make_pdr()],
            "1.0.0", _mock_cosign_executor(), out,
        )
        assert not (tmp_path / "evidence.tmp").exists()

    def test_bundle_result_is_frozen(self) -> None:
        result = BundleResult(path=Path("evidence.zip"), signing_status="signed")
        with pytest.raises((AttributeError, TypeError)):
            result.path = Path("other.zip")  # type: ignore[misc]
