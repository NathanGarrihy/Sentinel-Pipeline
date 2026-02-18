"""Pre-flight environment checks for Sentinel.

Verifies that all required external tools are available in $PATH
before any scanning commands are executed.
"""

import shutil
from dataclasses import dataclass, field

from sentinel.core.config import SentinelConfig


@dataclass(frozen=True, slots=True)
class PreflightResult:
    """Result of a pre-flight environment check.

    Attributes:
        passed: True if all required tools were found.
        missing_required: Tool names that are required but not in $PATH.
        missing_optional: Tool names that are optional and not in $PATH.
    """

    passed: bool
    missing_required: tuple[str, ...] = field(default_factory=tuple)
    missing_optional: tuple[str, ...] = field(default_factory=tuple)


def preflight_check(config: SentinelConfig) -> PreflightResult:
    """Check that all tools defined in config are available in $PATH.

    For each scanner, extracts the binary name (first element of command list)
    and checks if it exists using shutil.which(). The signing tool is checked
    the same way.

    Args:
        config: A validated SentinelConfig instance.

    Returns:
        A PreflightResult indicating which tools are present or missing.
    """
    missing_required: list[str] = []
    missing_optional: list[str] = []

    # Check each scanner binary
    for scanner in config.scanners:
        binary = scanner.command[0]
        if shutil.which(binary) is None:
            if scanner.required:
                missing_required.append(binary)
            else:
                missing_optional.append(binary)

    # Check signing tool
    if shutil.which(config.signing.tool) is None:
        if config.signing.required:
            missing_required.append(config.signing.tool)
        else:
            missing_optional.append(config.signing.tool)

    return PreflightResult(
        passed=len(missing_required) == 0,
        missing_required=tuple(missing_required),
        missing_optional=tuple(missing_optional),
    )
