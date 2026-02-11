from datetime import UTC, datetime

import typer
from rich.console import Console

from sentinel.core.executor import ToolExecutor
from sentinel.models.pdr import Decision, PolicyDecisionRecord

console = Console()


def verify_env() -> None:
    """Verify the local environment by running a simple echo and producing a PDR."""
    executor = ToolExecutor()
    result = executor.execute(["echo", "Sentinel Ready"])

    pdr = PolicyDecisionRecord(
        input_hash=result.output_hash,
        policy_version="0.1.0",
        decision=Decision.PASS,
        evidence_path="stdout://verify-env",
        timestamp=datetime.now(UTC),
    )

    console.print_json(pdr.model_dump_json())
    raise typer.Exit(code=0)
