"""Scanner orchestration for Sentinel.

Handles target injection and sequential execution of all configured scanners.
Each scanner result is collected regardless of exit code — PASS/FAIL decisions
are deferred to the PDR factory (Rule B). A non-zero exit code means the scanner
found issues, not that the orchestrator should abort.
"""

from sentinel.core.config import SentinelConfig
from sentinel.core.executor import ExecutorProtocol
from sentinel.models.scan_result import ScanResult


def inject_target(command: list[str], target: str) -> list[str]:
    """Replace every `{target}` placeholder in a command list with the given target.

    If no placeholder is present the command is returned unchanged, which allows
    scanners that hard-code their own target to still work without error.

    Args:
        command: The scanner command list from config.
        target:  The scan target supplied by the user (path or image reference).

    Returns:
        A new list with `{target}` replaced in every element that contains it.
    """
    return [element.replace("{target}", target) for element in command]


def run_scan(
    config: SentinelConfig,
    target: str,
    executor: ExecutorProtocol,
) -> list[ScanResult]:
    """Execute every scanner defined in config against the given target.

    Scanners are run sequentially. A non-zero exit code is recorded but does
    not stop execution — all configured scanners always run so that the final
    evidence bundle is complete.

    Args:
        config:   Validated SentinelConfig loaded from sentinel.yaml.
        target:   The scan target (directory path or container image reference).
        executor: Any object satisfying ExecutorProtocol (real or mock).

    Returns:
        A list of ScanResult objects, one per scanner, in config order.
    """
    results: list[ScanResult] = []

    for scanner in config.scanners:
        command = inject_target(scanner.command, target)

        execution_result = executor.execute(command)

        results.append(
            ScanResult(
                scanner_name=scanner.name,
                scanner_type=scanner.type,
                command=tuple(command),
                target=target,
                result=execution_result,
            )
        )

    return results
