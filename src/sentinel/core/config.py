"""Configuration loader for Sentinel.

Reads sentinel.yaml and validates it into strict Pydantic models.
Every scanner, its command, and signing config are defined here.
"""

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, field_validator
from ruamel.yaml import YAML


class ScannerType(StrEnum):
    """Categories of security scanners Sentinel can orchestrate."""

    SAST = "sast"
    SCA = "sca"
    IAC = "iac"
    SBOM = "sbom"


class ScannerConfig(BaseModel):
    """Definition of a single scanner tool.

    Attributes:
        name: Human-readable identifier (e.g. "semgrep").
        command: The full command as a list of arguments.
        type: What kind of scan this performs (sast, sca, iac, sbom).
        required: If True, pre-flight fails when this tool is missing.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    command: list[str]
    type: ScannerType
    required: bool = True

    @field_validator("command")
    @classmethod
    def command_must_not_be_empty(cls, v: list[str]) -> list[str]:
        """Reject scanner definitions with an empty command list."""
        if not v:
            msg = "Scanner command list must not be empty"
            raise ValueError(msg)
        return v


class SigningConfig(BaseModel):
    """Configuration for the artifact signing tool.

    Attributes:
        tool: Name of the signing binary (e.g. "cosign").
        required: If True, pre-flight fails when the tool is missing.
    """

    model_config = ConfigDict(frozen=True)

    tool: str
    required: bool = True


class SentinelConfig(BaseModel):
    """Root configuration model for Sentinel.

    Parsed from sentinel.yaml. Contains the list of scanners
    to run and the signing tool to use for evidence bundles.

    Attributes:
        version: Config schema version string.
        policy_version: Version of the policy ruleset applied during scanning.
            Recorded in every PDR so auditors can trace decisions back to the
            exact rules in force at the time. Intentionally separate from
            `version` — bumping the config format must not silently alter
            historical PDR policy references.
        scanners: List of scanner tool definitions.
        signing: Signing tool configuration.
    """

    model_config = ConfigDict(frozen=True)

    version: str
    policy_version: str
    scanners: list[ScannerConfig]
    signing: SigningConfig

    @field_validator("scanners")
    @classmethod
    def must_have_at_least_one_scanner(cls, v: list[ScannerConfig]) -> list[ScannerConfig]:
        """Reject configs with zero scanners defined."""
        if not v:
            msg = "At least one scanner must be defined"
            raise ValueError(msg)
        return v


class ConfigNotFoundError(FileNotFoundError):
    """Raised when sentinel.yaml does not exist at the expected path."""


class ConfigParseError(ValueError):
    """Raised when sentinel.yaml contains invalid YAML syntax."""


def load_config(path: Path | str = "sentinel.yaml") -> SentinelConfig:
    """Load and validate Sentinel configuration from a YAML file.

    Args:
        path: Path to the sentinel.yaml file. Defaults to current directory.

    Returns:
        A validated SentinelConfig instance.

    Raises:
        ConfigNotFoundError: If the file does not exist.
        ConfigParseError: If the YAML is malformed.
        pydantic.ValidationError: If the content doesn't match the schema.
    """
    config_path = Path(path)

    if not config_path.exists():
        msg = f"Config file not found: {config_path.resolve()}"
        raise ConfigNotFoundError(msg)

    yaml = YAML(typ="safe")
    try:
        raw = yaml.load(config_path)
    except Exception as e:
        msg = f"Failed to parse {config_path}: {e}"
        raise ConfigParseError(msg) from e

    if raw is None or "sentinel" not in raw:
        msg = f"Config file {config_path} must contain a top-level 'sentinel' key"
        raise ConfigParseError(msg)

    return SentinelConfig(**raw["sentinel"])
