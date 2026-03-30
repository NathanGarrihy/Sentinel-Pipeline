import json
from datetime import UTC, datetime

import pytest

from sentinel.models.execution import ExecutionResult
from sentinel.models.pdr import Decision, PolicyDecisionRecord


class TestExecutionResult:
    def test_frozen(self) -> None:
        result = ExecutionResult(stdout="hello", stderr="", exit_code=0, output_hash="abc123")
        with pytest.raises(AttributeError):
            result.stdout = "changed"  # type: ignore[misc]

    def test_fields(self) -> None:
        result = ExecutionResult(stdout="out", stderr="err", exit_code=1, output_hash="deadbeef")
        assert result.stdout == "out"
        assert result.stderr == "err"
        assert result.exit_code == 1
        assert result.output_hash == "deadbeef"


class TestPolicyDecisionRecord:
    def test_serializes_to_json(self) -> None:
        ts = datetime(2025, 1, 1, tzinfo=UTC)
        pdr = PolicyDecisionRecord(
            input_hash="abc",
            policy_version="1.0.0",
            decision=Decision.PASS,
            evidence_path="raw/test.json",
            timestamp=ts,
        )
        data = json.loads(pdr.model_dump_json())
        assert data["input_hash"] == "abc"
        assert data["policy_version"] == "1.0.0"
        assert data["decision"] == "PASS"
        assert data["evidence_path"] == "raw/test.json"
        assert "timestamp" in data

    def test_frozen(self) -> None:
        pdr = PolicyDecisionRecord(
            input_hash="abc",
            policy_version="1.0.0",
            decision=Decision.FAIL,
            evidence_path="raw/test.json",
            timestamp=datetime.now(UTC),
        )
        with pytest.raises(Exception):  # noqa: B017
            pdr.decision = Decision.PASS  # type: ignore[misc]


class TestDecisionEnum:
    def test_values_are_strings(self) -> None:
        assert str(Decision.PASS) == "PASS"
        assert str(Decision.FAIL) == "FAIL"
        assert str(Decision.WARNING_ACCEPTED) == "WARNING_ACCEPTED"

    def test_json_serialization(self) -> None:
        pdr = PolicyDecisionRecord(
            input_hash="h",
            policy_version="1.0",
            decision=Decision.WARNING_ACCEPTED,
            evidence_path="p",
            timestamp=datetime.now(UTC),
        )
        data = json.loads(pdr.model_dump_json())
        assert data["decision"] == "WARNING_ACCEPTED"
        assert isinstance(data["decision"], str)
