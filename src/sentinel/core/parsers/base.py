"""Base types for scanner output parsers.

Every scanner parser must implement ScannerParser and return a ParsedOutput.
The decision logic in pdr_factory.py depends only on these types — parsers
are interchangeable as long as they satisfy the Protocol.
"""

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ParsedOutput:
    """Structured summary of a scanner's stdout.

    Attributes:
        finding_count: Number of findings, vulnerabilities, or failed checks.
            Zero does not automatically mean PASS — check `is_error` first.
        is_error: True when the tool errored before producing a verdict
            (e.g. crashed, produced no JSON, or returned an unexpected exit
            code). An errored run yields a FAIL PDR regardless of finding_count.
        raw_findings: The parsed list of finding objects from the tool's JSON
            output. Preserved for future bundle evidence. Empty list when
            parsing failed or the tool produced no findings structure.
        parse_error: Human-readable description of why parsing failed.
            None when parsing succeeded.
    """

    finding_count: int
    is_error: bool
    raw_findings: list[dict] = field(default_factory=list)
    parse_error: str | None = None


class ScannerParser(Protocol):
    """Protocol that every scanner parser must satisfy.

    Implementing this Protocol (rather than inheriting from a base class)
    keeps parsers loosely coupled and makes mock injection in tests trivial.
    """

    def parse(self, stdout: str, exit_code: int) -> ParsedOutput:
        """Parse scanner stdout into a structured summary.

        Args:
            stdout:    The raw stdout string captured by the executor.
            exit_code: The process exit code. Parsers may use this to
                distinguish "found issues" (e.g. exit 1) from "errored"
                (e.g. exit 2 for semgrep config errors).

        Returns:
            A ParsedOutput describing what the scanner found or why it failed.
        """
        ...
