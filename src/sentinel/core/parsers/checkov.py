"""Checkov output parser.

Checkov exit code contract:
    0  — all checks passed
    1  — one or more checks failed (policy verdict, not an error)

Checkov can emit either a single JSON object or a JSON array (when run
recursively across multiple directories). Both forms are handled.

Findings live at: data["results"]["failed_checks"] in the single-object form,
or flattened across all array entries in the array form.
"""

import json

from sentinel.core.parsers.base import ParsedOutput


class CheckovParser:
    """Parses `checkov --output json` output into a structured summary."""

    def parse(self, stdout: str, exit_code: int) -> ParsedOutput:
        """Parse checkov JSON output.

        Handles both single-object and array output forms. Failed checks
        are extracted from `results.failed_checks` in each object.

        Args:
            stdout:    Raw stdout from checkov.
            exit_code: Checkov process exit code.

        Returns:
            ParsedOutput with count of failed checks, or is_error=True
            if output cannot be parsed.
        """
        if not stdout.strip():
            return ParsedOutput(
                finding_count=0,
                is_error=True,
                parse_error="checkov produced no output",
            )

        try:
            data = json.loads(stdout)

            # Normalise to a list — checkov emits either an object or an array
            entries: list[dict] = data if isinstance(data, list) else [data]

            failed: list[dict] = []
            for entry in entries:
                failed.extend(
                    entry.get("results", {}).get("failed_checks") or []
                )

            return ParsedOutput(
                finding_count=len(failed),
                is_error=False,
                raw_findings=failed,
            )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            return ParsedOutput(
                finding_count=0,
                is_error=True,
                parse_error=f"failed to parse checkov output: {exc}",
            )
