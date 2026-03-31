from dataclasses import dataclass

from sentinel.core.config import ScannerType
from sentinel.models.execution import ExecutionResult


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The output of running a single scanner tool.

    Handoff type between the orchestrator and the PDR factory.
    Preserves the scanner's identity alongside its raw execution output.

    Attributes:
        scanner_name: Human-readable name from config (e.g. "trivy").
        scanner_type: Category of scan performed (sast, sca, iac, sbom).
        command: The exact command list that was executed — stored for the
            audit trail so the evidence bundle can prove what ran.
        target: The scan target as supplied by the user (directory path or
            image reference). Stored separately from `command` so the PDR
            factory can compute `input_hash` without parsing the command tuple.
        result: Raw execution output from the executor.
    """

    scanner_name: str
    scanner_type: ScannerType
    command: tuple[str, ...]  # exact command that ran — for the audit trail
    target: str               # scan target, stored explicitly for input_hash computation
    result: ExecutionResult
