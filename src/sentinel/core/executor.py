import hashlib
import subprocess
from typing import Protocol

from sentinel.models.execution import ExecutionResult


class ExecutorProtocol(Protocol):
    """Protocol for tool executors, enabling mock injection in tests (Rule A)."""

    def execute(self, command: list[str]) -> ExecutionResult: ...


class ToolExecutor:
    """Runs external tools safely. All subprocess usage is isolated here (Rule A)."""

    def execute(self, command: list[str]) -> ExecutionResult:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
        )
        stdout = result.stdout
        output_hash = hashlib.sha256(stdout.encode()).hexdigest()
        return ExecutionResult(
            stdout=stdout,
            exit_code=result.returncode,
            output_hash=output_hash,
        )
