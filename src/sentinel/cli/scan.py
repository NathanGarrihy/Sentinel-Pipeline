from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from sentinel.core.bundler import build_bundle
from sentinel.core.executor import ToolExecutor
from sentinel.core.orchestrator import run_scan
from sentinel.core.pdr_factory import build_all_pdrs
from sentinel.models.pdr import Decision, PolicyDecisionRecord
from sentinel.models.scan_result import ScanResult

console = Console()
err_console = Console(stderr=True)


def _print_summary(results: list[ScanResult], pdrs: list[PolicyDecisionRecord]) -> None:
    """Render a Rich table showing each scanner's verdict and evidence path.

    Args:
        results: ScanResult list from the orchestrator (scanner identity + raw output).
        pdrs:    Corresponding PDR list from the factory (one PDR per result, same order).
    """
    table = Table(title="Policy Decision Summary", show_lines=True)
    table.add_column("Scanner", style="bold")
    table.add_column("Type")
    table.add_column("Decision", justify="center")
    table.add_column("Findings", justify="right")
    table.add_column("Evidence Path", style="dim")

    for r, pdr in zip(results, pdrs):
        decision_style = "green" if pdr.decision == Decision.PASS else "red"
        # finding_count is not on the PDR — use exit code as a proxy for display
        # (detailed finding counts will be surfaced in Step 3 bundle metadata)
        exit_indicator = "0" if r.result.exit_code == 0 else str(r.result.exit_code)
        table.add_row(
            r.scanner_name,
            str(r.scanner_type),
            f"[{decision_style}]{pdr.decision}[/{decision_style}]",
            exit_indicator,
            pdr.evidence_path,
        )

    console.print(table)


def scan(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Scan target: directory path or image reference.")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Destination path for the evidence bundle.")] = Path("evidence.zip"),
    skip_signing: Annotated[bool, typer.Option("--skip-signing", help="Skip cosign signing (bundle is written unsigned).")] = False,
) -> None:
    """Run all configured scanners against TARGET and produce Policy Decision Records."""
    config = ctx.obj["config"]
    executor = ToolExecutor()

    console.print(f"[bold]Sentinel[/bold] scanning target: [cyan]{target}[/cyan]")

    results = run_scan(config, target, executor)

    # Build a PDR for every scan result
    pdrs = build_all_pdrs(results, config.policy_version)

    _print_summary(results, pdrs)

    # Warn on stderr for any scanner that exited non-zero
    for r in results:
        if r.result.exit_code != 0:
            err_console.print(
                f"[yellow]Warning:[/yellow] {r.scanner_name} exited {r.result.exit_code}"
            )
            if r.result.stderr:
                err_console.print(f"  stderr: {r.result.stderr.strip()[:200]}")

    # Build the evidence bundle. The bundle is always written — even when scanners
    # fail — so auditors have a complete record of what ran and what was decided.
    bundle = build_bundle(results, pdrs, config.policy_version, executor, output, skip_signing)

    if bundle.signing_status == "signed":
        console.print(f"[green]Bundle signed and written:[/green] {bundle.path}")
    elif bundle.signing_status == "skipped":
        console.print(f"[yellow]Bundle written (unsigned, --skip-signing):[/yellow] {bundle.path}")
    else:
        err_console.print(f"[red]Bundle written UNSIGNED (signing failed):[/red] {bundle.path}")
        if bundle.signing_error:
            err_console.print(f"  Reason: {bundle.signing_error}")

    # Determine exit code — collect all failure conditions before exiting so the
    # user sees the full picture in one run rather than one error at a time.
    exit_code = 0

    # Fail the process only if a *required* scanner received a FAIL PDR
    required_names = {s.name for s in config.scanners if s.required}
    failed_required = [
        r for r, pdr in zip(results, pdrs)
        if r.scanner_name in required_names and pdr.decision == Decision.FAIL
    ]
    if failed_required:
        names = ", ".join(r.scanner_name for r in failed_required)
        err_console.print(
            f"\n[red]Policy failed.[/red] Required scanner(s) produced FAIL PDR: {names}"
        )
        exit_code = 1

    # An unexpected signing failure (not an intentional --skip-signing) is also fatal
    if bundle.signing_status == "failed":
        exit_code = 1

    raise typer.Exit(code=exit_code)
