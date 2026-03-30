from dataclasses import dataclass

from sentinel.core.config import ScannerType
from sentinel.models.execution import ExecutionResult


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The output of running a single scanner tool.

    Handoff type between the orchestrator and the PDR factory.
    Preserves the scanner's identity alongside its raw execution output.
    """

    scanner_name: str
    scanner_type: ScannerType
    command: tuple[str, ...]  # exact command that ran — for the audit trail
    result: ExecutionResult
