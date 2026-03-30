from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from sentinel.core.executor import ToolExecutor
from sentinel.core.orchestrator import run_scan
from sentinel.models.scan_result import ScanResult

console = Console()
err_console = Console(stderr=True)


def _print_summary(results: list[ScanResult]) -> None:
    """Render a Rich table summarising scanner outcomes."""
    table = Table(title="Scan Summary", show_lines=True)
    table.add_column("Scanner", style="bold")
    table.add_column("Type")
    table.add_column("Exit Code", justify="center")
    table.add_column("Output Hash (SHA-256)", style="dim")

    for r in results:
        exit_code = r.result.exit_code
        code_style = "green" if exit_code == 0 else "yellow"
        table.add_row(
            r.scanner_name,
            str(r.scanner_type),
            f"[{code_style}]{exit_code}[/{code_style}]",
            r.result.output_hash[:16] + "...",
        )

    console.print(table)


def scan(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Scan target: directory path or image reference.")],
) -> None:
    """Run all configured scanners against TARGET and collect raw results."""
    config = ctx.obj["config"]
    executor = ToolExecutor()

    console.print(f"[bold]Sentinel[/bold] scanning target: [cyan]{target}[/cyan]")

    results = run_scan(config, target, executor)

    _print_summary(results)

    # Warn on stderr for any scanner that exited non-zero
    for r in results:
        if r.result.exit_code != 0:
            err_console.print(
                f"[yellow]Warning:[/yellow] {r.scanner_name} exited {r.result.exit_code}"
            )
            if r.result.stderr:
                err_console.print(f"  stderr: {r.result.stderr.strip()[:200]}")

    # Fail the process only if a *required* scanner exited non-zero
    required_names = {s.name for s in config.scanners if s.required}
    failed_required = [
        r for r in results
        if r.scanner_name in required_names and r.result.exit_code != 0
    ]

    if failed_required:
        names = ", ".join(r.scanner_name for r in failed_required)
        err_console.print(
            f"\n[red]Scan failed.[/red] Required scanner(s) exited non-zero: {names}"
        )
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)
