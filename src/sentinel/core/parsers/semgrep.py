"""Semgrep output parser.

Semgrep exit code contract:
    0  — no findings
    1  — findings present (not an error — this is a policy verdict)
    2  — fatal error (config error, parse failure, OOM, etc.)
    3  — invalid command-line arguments

Findings live at: data["results"] (list of finding objects).
"""

import json

from sentinel.core.parsers.base import ParsedOutput


class SemgrepParser:
    """Parses `semgrep scan --json` output into a structured summary."""

    def parse(self, stdout: str, exit_code: int) -> ParsedOutput:
        """Parse semgrep JSON output.

        Exit code 2 or 3 is treated as a tool error regardless of stdout
        content — semgrep encountered a fatal condition before completing
        its scan, so no verdict can be drawn.

        Args:
            stdout:    Raw stdout from semgrep.
            exit_code: Semgrep process exit code.

        Returns:
            ParsedOutput with finding_count from data["results"],
            or is_error=True if semgrep errored or output cannot be parsed.
        """
        # Exit codes 2/3 mean semgrep itself failed — not a policy verdict
        if exit_code in (2, 3):
            return ParsedOutput(
                finding_count=0,
                is_error=True,
                parse_error=f"semgrep exited with error code {exit_code}",
            )

        if not stdout.strip():
            return ParsedOutput(
                finding_count=0,
                is_error=True,
                parse_error="semgrep produced no output",
            )

        try:
            data = json.loads(stdout)
            findings: list[dict] = data["results"]
            return ParsedOutput(
                finding_count=len(findings),
                is_error=False,
                raw_findings=findings,
            )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            return ParsedOutput(
                finding_count=0,
                is_error=True,
                parse_error=f"failed to parse semgrep output: {exc}",
            )
