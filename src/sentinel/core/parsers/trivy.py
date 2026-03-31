"""Trivy output parser.

Trivy exit code contract:
    0  — no vulnerabilities found
    1  — vulnerabilities found (policy verdict, not an error)
    2  — trivy itself errored (target not found, registry auth failure, etc.)

Findings live at: data["Results"][*]["Vulnerabilities"] (list per layer/package).
The "Results" key may be null on a clean image — guarded with `or []`.
"""

import json

from sentinel.core.parsers.base import ParsedOutput


class TrivyParser:
    """Parses `trivy image --format json` output into a structured summary."""

    def parse(self, stdout: str, exit_code: int) -> ParsedOutput:
        """Parse trivy JSON output.

        Flattens vulnerabilities across all Results entries. The Results key
        can be null (clean image) or absent (scan error) — both are handled.

        Args:
            stdout:    Raw stdout from trivy.
            exit_code: Trivy process exit code.

        Returns:
            ParsedOutput with total vulnerability count, or is_error=True
            if trivy errored or the output cannot be parsed.
        """
        # Exit code 2 means trivy itself encountered a fatal error
        if exit_code == 2:
            return ParsedOutput(
                finding_count=0,
                is_error=True,
                parse_error="trivy exited with error code 2",
            )

        if not stdout.strip():
            return ParsedOutput(
                finding_count=0,
                is_error=True,
                parse_error="trivy produced no output",
            )

        try:
            data = json.loads(stdout)
            # Results may be null on a clean image — `or []` guards against that
            results: list[dict] = data.get("Results") or []
            vulns: list[dict] = []
            for result in results:
                # Each result entry may or may not have a Vulnerabilities list
                vulns.extend(result.get("Vulnerabilities") or [])
            return ParsedOutput(
                finding_count=len(vulns),
                is_error=False,
                raw_findings=vulns,
            )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            return ParsedOutput(
                finding_count=0,
                is_error=True,
                parse_error=f"failed to parse trivy output: {exc}",
            )
