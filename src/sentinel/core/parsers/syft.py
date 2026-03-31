"""Syft output parser.

Syft is an SBOM generator, not a vulnerability or policy checker. It has no
concept of "findings" — success means it produced a valid SBOM; failure means
it could not generate one (target not found, unsupported format, etc.).

Exit code contract:
    0  — SBOM generated successfully
    non-zero — syft encountered an error

The SBOM JSON is not parsed for findings; its presence and size are used as
a liveness check. The raw stdout is preserved in the evidence bundle by Step 3.
"""

import json

from sentinel.core.parsers.base import ParsedOutput


class SyftParser:
    """Parses `syft packages --output json` output into a structured summary."""

    def parse(self, stdout: str, exit_code: int) -> ParsedOutput:
        """Parse syft JSON output.

        Success is defined as: exit code 0 AND stdout contains parseable JSON
        with at least an "artifacts" key. No finding count is meaningful here —
        the PDR decision is driven solely by whether the SBOM was produced.

        Args:
            stdout:    Raw stdout from syft.
            exit_code: Syft process exit code.

        Returns:
            ParsedOutput with finding_count=0 and is_error=False on success,
            or is_error=True if syft errored or produced no valid SBOM JSON.
        """
        if exit_code != 0:
            return ParsedOutput(
                finding_count=0,
                is_error=True,
                parse_error=f"syft exited with code {exit_code}",
            )

        if not stdout.strip():
            return ParsedOutput(
                finding_count=0,
                is_error=True,
                parse_error="syft produced no output",
            )

        try:
            data = json.loads(stdout)
            # Verify the output looks like a syft SBOM — "artifacts" is the
            # canonical top-level key in syft's JSON schema
            if "artifacts" not in data:
                return ParsedOutput(
                    finding_count=0,
                    is_error=True,
                    parse_error="syft output missing expected 'artifacts' key",
                )
            # finding_count stays 0 — SBOMs list packages, not findings
            return ParsedOutput(finding_count=0, is_error=False)
        except (json.JSONDecodeError, TypeError) as exc:
            return ParsedOutput(
                finding_count=0,
                is_error=True,
                parse_error=f"failed to parse syft output: {exc}",
            )
