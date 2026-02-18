import pytest
from pydantic import ValidationError

from sentinel.core.config import (
    ConfigNotFoundError,
    ConfigParseError,
    ScannerConfig,
    ScannerType,
    SentinelConfig,
    SigningConfig,
    load_config,
)


def _minimal_yaml(tmp_path, content: str):
    """Helper: write YAML content to a temp file and return its path."""
    f = tmp_path / "sentinel.yaml"
    f.write_text(content)
    return f


class TestScannerConfig:
    def test_valid_scanner(self) -> None:
        s = ScannerConfig(name="trivy", command=["trivy", "image"], type=ScannerType.SCA)
        assert s.name == "trivy"
        assert s.required is True  # default

    def test_empty_command_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            ScannerConfig(name="bad", command=[], type=ScannerType.SAST)

    def test_frozen(self) -> None:
        s = ScannerConfig(name="x", command=["x"], type=ScannerType.SAST)
        with pytest.raises(ValidationError):
            s.name = "y"  # type: ignore[misc]


class TestSentinelConfig:
    def test_empty_scanners_rejected(self) -> None:
        with pytest.raises(ValidationError, match="At least one scanner"):
            SentinelConfig(
                version="1.0",
                scanners=[],
                signing=SigningConfig(tool="cosign"),
            )

    def test_valid_config(self) -> None:
        cfg = SentinelConfig(
            version="1.0",
            scanners=[ScannerConfig(name="s", command=["s"], type=ScannerType.SAST)],
            signing=SigningConfig(tool="cosign"),
        )
        assert len(cfg.scanners) == 1
        assert cfg.signing.tool == "cosign"


class TestLoadConfig:
    def test_file_not_found(self, tmp_path) -> None:
        with pytest.raises(ConfigNotFoundError):
            load_config(tmp_path / "nonexistent.yaml")

    def test_empty_file(self, tmp_path) -> None:
        path = _minimal_yaml(tmp_path, "")
        with pytest.raises(ConfigParseError, match="top-level 'sentinel' key"):
            load_config(path)

    def test_missing_sentinel_key(self, tmp_path) -> None:
        path = _minimal_yaml(tmp_path, "other:\n  foo: bar\n")
        with pytest.raises(ConfigParseError, match="top-level 'sentinel' key"):
            load_config(path)

    def test_invalid_yaml_syntax(self, tmp_path) -> None:
        path = _minimal_yaml(tmp_path, "sentinel:\n  scanners:\n  - name: bad\n    command: [")
        with pytest.raises(ConfigParseError):
            load_config(path)

    def test_valid_file_loads(self, tmp_path) -> None:
        content = """\
sentinel:
  version: "1.0"
  scanners:
    - name: semgrep
      command: ["semgrep", "scan"]
      type: sast
  signing:
    tool: cosign
"""
        path = _minimal_yaml(tmp_path, content)
        cfg = load_config(path)
        assert cfg.version == "1.0"
        assert len(cfg.scanners) == 1
        assert cfg.scanners[0].name == "semgrep"
        assert cfg.signing.tool == "cosign"

    def test_optional_scanner(self, tmp_path) -> None:
        content = """\
sentinel:
  version: "1.0"
  scanners:
    - name: checkov
      command: ["checkov", "-d", "."]
      type: iac
      required: false
  signing:
    tool: cosign
"""
        path = _minimal_yaml(tmp_path, content)
        cfg = load_config(path)
        assert cfg.scanners[0].required is False
