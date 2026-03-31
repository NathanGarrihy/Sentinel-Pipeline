"""Tests for the PDR factory.

Covers build_pdr() and build_all_pdrs() with both known and unknown scanners,
verifying decision logic, input_hash computation, evidence_path convention,
and policy_version pass-through.
"""

import hashlib
import json
from datetime import UTC

from sentinel.core.pdr_factory import build_all_pdrs, build_pdr
from sentinel.core.config import ScannerType
from sentinel.models.execution import ExecutionResult
from sentinel.models.pdr import Decision
from sentinel.models.scan_result import ScanResult


def _make_execution(stdout: str = "", stderr: str = "", exit_code: int = 0) -> ExecutionResult:
    """Helper: build an ExecutionResult with a correct output_hash."""
    return ExecutionResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        output_hash=hashlib.sha256(stdout.encode()).hexdigest(),
    )


def _make_scan_result(
    scanner_name: str = "semgrep",
    scanner_type: ScannerType = ScannerType.SAST,
    target: str = ".",
    stdout: str = "",
    exit_code: int = 0,
) -> ScanResult:
    """Helper: build a ScanResult for a given scanner."""
    return ScanResult(
        scanner_name=scanner_name,
        scanner_type=scanner_type,
        command=(scanner_name, target),
        target=target,
        result=_make_execution(stdout=stdout, exit_code=exit_code),
    )


class TestBuildPdr:
    def test_input_hash_is_sha256_of_target(self) -> None:
        target = "myapp:latest"
        sr = _make_scan_result(scanner_name="semgrep", target=target,
                               stdout=json.dumps({"results": []}))
        pdr = build_pdr(sr, "0.1.0")
        expected = hashlib.sha256(target.encode()).hexdigest()
        assert pdr.input_hash == expected

    def test_policy_version_passed_through(self) -> None:
        sr = _make_scan_result(stdout=json.dumps({"results": []}))
        pdr = build_pdr(sr, "1.2.3")
        assert pdr.policy_version == "1.2.3"

    def test_evidence_path_convention(self) -> None:
        sr = _make_scan_result(scanner_name="trivy",
                               stdout=json.dumps({"Results": []}))
        pdr = build_pdr(sr, "0.1.0")
        assert pdr.evidence_path == "raw/trivy-output.json"

    def test_timestamp_is_utc(self) -> None:
        sr = _make_scan_result(stdout=json.dumps({"results": []}))
        pdr = build_pdr(sr, "0.1.0")
        assert pdr.timestamp.tzinfo is UTC

    def test_pass_decision_on_clean_semgrep(self) -> None:
        sr = _make_scan_result(
            scanner_name="semgrep",
            stdout=json.dumps({"results": []}),
            exit_code=0,
        )
        pdr = build_pdr(sr, "0.1.0")
        assert pdr.decision == Decision.PASS

    def test_fail_decision_on_semgrep_findings(self) -> None:
        sr = _make_scan_result(
            scanner_name="semgrep",
            stdout=json.dumps({"results": [{"check_id": "rule1"}]}),
            exit_code=1,
        )
        pdr = build_pdr(sr, "0.1.0")
        assert pdr.decision == Decision.FAIL

    def test_fail_decision_on_semgrep_error(self) -> None:
        # Exit 2 = semgrep config error
        sr = _make_scan_result(scanner_name="semgrep", stdout="", exit_code=2)
        pdr = build_pdr(sr, "0.1.0")
        assert pdr.decision == Decision.FAIL

    def test_pass_decision_on_clean_trivy(self) -> None:
        sr = _make_scan_result(
            scanner_name="trivy",
            scanner_type=ScannerType.SCA,
            stdout=json.dumps({"Results": None}),
            exit_code=0,
        )
        pdr = build_pdr(sr, "0.1.0")
        assert pdr.decision == Decision.PASS

    def test_fail_decision_on_trivy_vulns(self) -> None:
        sr = _make_scan_result(
            scanner_name="trivy",
            scanner_type=ScannerType.SCA,
            stdout=json.dumps({"Results": [{"Vulnerabilities": [{"VulnID": "CVE-1"}]}]}),
            exit_code=1,
        )
        pdr = build_pdr(sr, "0.1.0")
        assert pdr.decision == Decision.FAIL

    def test_pass_decision_on_clean_checkov(self) -> None:
        sr = _make_scan_result(
            scanner_name="checkov",
            scanner_type=ScannerType.IAC,
            stdout=json.dumps({"results": {"failed_checks": []}}),
            exit_code=0,
        )
        pdr = build_pdr(sr, "0.1.0")
        assert pdr.decision == Decision.PASS

    def test_pass_decision_on_clean_syft(self) -> None:
        sr = _make_scan_result(
            scanner_name="syft",
            scanner_type=ScannerType.SBOM,
            stdout=json.dumps({"artifacts": []}),
            exit_code=0,
        )
        pdr = build_pdr(sr, "0.1.0")
        assert pdr.decision == Decision.PASS

    def test_unknown_scanner_produces_fail(self) -> None:
        # Decision #2: unknown scanner → FAIL, not PASS
        sr = _make_scan_result(scanner_name="grype", stdout='{"results": []}')
        pdr = build_pdr(sr, "0.1.0")
        assert pdr.decision == Decision.FAIL

    def test_unknown_scanner_evidence_path_still_set(self) -> None:
        sr = _make_scan_result(scanner_name="grype")
        pdr = build_pdr(sr, "0.1.0")
        assert pdr.evidence_path == "raw/grype-output.json"


class TestBuildAllPdrs:
    def test_returns_one_pdr_per_result(self) -> None:
        results = [
            _make_scan_result("semgrep", stdout=json.dumps({"results": []})),
            _make_scan_result("trivy", ScannerType.SCA,
                              stdout=json.dumps({"Results": []})),
        ]
        pdrs = build_all_pdrs(results, "0.1.0")
        assert len(pdrs) == 2

    def test_order_preserved(self) -> None:
        results = [
            _make_scan_result("semgrep", stdout=json.dumps({"results": []}), exit_code=0),
            _make_scan_result("trivy", ScannerType.SCA,
                              stdout=json.dumps({"Results": [{"Vulnerabilities": [{"v": 1}]}]}),
                              exit_code=1),
        ]
        pdrs = build_all_pdrs(results, "0.1.0")
        assert pdrs[0].decision == Decision.PASS
        assert pdrs[1].decision == Decision.FAIL

    def test_empty_list_returns_empty(self) -> None:
        assert build_all_pdrs([], "0.1.0") == []
