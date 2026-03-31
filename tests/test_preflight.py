from sentinel.core.config import ScannerConfig, ScannerType, SentinelConfig, SigningConfig
from sentinel.core.preflight import preflight_check


def _make_config(scanners=None, signing_tool="cosign", signing_required=True):
    """Helper: build a SentinelConfig with sensible defaults."""
    if scanners is None:
        scanners = [
            ScannerConfig(name="echo", command=["echo"], type=ScannerType.SAST),
        ]
    return SentinelConfig(
        version="1.0",
        policy_version="0.1.0",
        scanners=scanners,
        signing=SigningConfig(tool=signing_tool, required=signing_required),
    )


class TestPreflightCheck:
    def test_passes_when_all_tools_exist(self) -> None:
        # "echo" and "python" should exist on any system
        config = _make_config(
            scanners=[
                ScannerConfig(name="echo", command=["echo"], type=ScannerType.SAST),
            ],
            signing_tool="python",
        )
        result = preflight_check(config)
        assert result.passed is True
        assert result.missing_required == ()
        assert result.missing_optional == ()

    def test_fails_when_required_scanner_missing(self) -> None:
        config = _make_config(
            scanners=[
                ScannerConfig(
                    name="fake",
                    command=["__sentinel_nonexistent_tool__"],
                    type=ScannerType.SAST,
                    required=True,
                ),
            ],
            signing_tool="python",
        )
        result = preflight_check(config)
        assert result.passed is False
        assert "__sentinel_nonexistent_tool__" in result.missing_required

    def test_warns_when_optional_scanner_missing(self) -> None:
        config = _make_config(
            scanners=[
                ScannerConfig(
                    name="fake",
                    command=["__sentinel_nonexistent_tool__"],
                    type=ScannerType.IAC,
                    required=False,
                ),
            ],
            signing_tool="python",
        )
        result = preflight_check(config)
        assert result.passed is True
        assert "__sentinel_nonexistent_tool__" in result.missing_optional

    def test_fails_when_required_signing_tool_missing(self) -> None:
        config = _make_config(
            signing_tool="__sentinel_nonexistent_signer__",
            signing_required=True,
        )
        result = preflight_check(config)
        assert result.passed is False
        assert "__sentinel_nonexistent_signer__" in result.missing_required

    def test_passes_when_optional_signing_tool_missing(self) -> None:
        config = _make_config(
            signing_tool="__sentinel_nonexistent_signer__",
            signing_required=False,
        )
        result = preflight_check(config)
        assert result.passed is True
        assert "__sentinel_nonexistent_signer__" in result.missing_optional

    def test_mixed_required_and_optional(self) -> None:
        config = _make_config(
            scanners=[
                ScannerConfig(
                    name="exists", command=["echo"], type=ScannerType.SAST, required=True
                ),
                ScannerConfig(
                    name="missing_req",
                    command=["__sentinel_missing_req__"],
                    type=ScannerType.SCA,
                    required=True,
                ),
                ScannerConfig(
                    name="missing_opt",
                    command=["__sentinel_missing_opt__"],
                    type=ScannerType.IAC,
                    required=False,
                ),
            ],
            signing_tool="python",
        )
        result = preflight_check(config)
        assert result.passed is False
        assert "__sentinel_missing_req__" in result.missing_required
        assert "__sentinel_missing_opt__" in result.missing_optional
