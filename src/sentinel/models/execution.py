from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Result of a secure tool execution (Rule A).

    Immutable record containing stdout, stderr, exit code, and SHA-256 hash of stdout.
    stderr is preserved for diagnostics but is not part of the evidence hash.
    """

    stdout: str
    stderr: str
    exit_code: int
    output_hash: str  # SHA-256 hex digest of stdout
