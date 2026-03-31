"""PDR Factory — converts raw scan results into Policy Decision Records.

This module is the policy enforcement heart of Sentinel. It maps each
ScanResult to a PolicyDecisionRecord by:
  1. Routing the scanner's stdout through the appropriate parser.
  2. Applying the decision rule (exit code + is_error → PASS/FAIL).
  3. Assembling the immutable PDR with its evidence_path reference.

Design decisions recorded in .ai_context.md:
  - Unknown scanner → FAIL PDR (safe by default, forces explicit parser registration).
  - evidence_path convention: "raw/{scanner_name}-output.json".
  - input_hash = SHA256(target_string) for Phase 2. Known limitation: this hashes
    the *identifier* passed to Sentinel, not the artifact content. Upgrade path
    for Phase 3 is to use the digest from syft's SBOM output.
  - Decision.WARNING_ACCEPTED is not generated automatically. It requires a
    human approval workflow deferred to Phase 3/4.
"""

import hashlib
from datetime import UTC, datetime

from sentinel.core.parsers.base import ParsedOutput, ScannerParser
from sentinel.core.parsers.checkov import CheckovParser
from sentinel.core.parsers.semgrep import SemgrepParser
from sentinel.core.parsers.syft import SyftParser
from sentinel.core.parsers.trivy import TrivyParser
from sentinel.models.pdr import Decision, PolicyDecisionRecord
from sentinel.models.scan_result import ScanResult

# Registry mapping scanner names to their parser instances.
# Add an entry here whenever a new scanner is added to sentinel.yaml.
# Absence from this registry is intentionally an error — see _get_parser().
_PARSERS: dict[str, ScannerParser] = {
    "semgrep": SemgrepParser(),
    "trivy": TrivyParser(),
    "checkov": CheckovParser(),
    "syft": SyftParser(),
}


def _get_parser(scanner_name: str) -> ScannerParser | None:
    """Look up the parser for a given scanner name.

    Returns None for unknown scanners. The caller (build_pdr) treats None
    as an error condition — producing a FAIL PDR — so unregistered scanners
    cannot silently pass policy.

    Args:
        scanner_name: The scanner name as defined in sentinel.yaml.

    Returns:
        The registered ScannerParser, or None if not found.
    """
    return _PARSERS.get(scanner_name)


def _make_decision(exit_code: int, parsed: ParsedOutput) -> Decision:
    """Derive a policy decision from exit code and parsed output.

    Rule:
        - Tool errored (is_error=True) → FAIL. The scanner did not complete
          its scan, so no verdict can be trusted.
        - Non-zero exit code → FAIL. The tool ran but found issues.
        - Exit 0, no error → PASS.

    Decision.WARNING_ACCEPTED is not produced here. It requires explicit
    human approval and is deferred to Phase 3.

    Args:
        exit_code: The process exit code from ExecutionResult.
        parsed:    The ParsedOutput from the relevant scanner parser.

    Returns:
        Decision.PASS or Decision.FAIL.
    """
    if parsed.is_error:
        return Decision.FAIL
    if exit_code != 0:
        return Decision.FAIL
    return Decision.PASS


def build_pdr(scan_result: ScanResult, policy_version: str) -> PolicyDecisionRecord:
    """Build a single PolicyDecisionRecord from a scanner's ScanResult.

    Args:
        scan_result:    The ScanResult produced by the orchestrator for one scanner.
        policy_version: The policy ruleset version from SentinelConfig, recorded
                        verbatim in the PDR so auditors can trace the decision.

    Returns:
        An immutable PolicyDecisionRecord.
    """
    # input_hash: SHA256 of the scan target string (Phase 2 limitation — see module docstring)
    input_hash = hashlib.sha256(scan_result.target.encode()).hexdigest()

    parser = _get_parser(scan_result.scanner_name)

    if parser is None:
        # Unknown scanner — safe default is FAIL, not PASS (Decision #2 in .ai_context.md)
        parsed = ParsedOutput(
            finding_count=0,
            is_error=True,
            parse_error=f"no parser registered for scanner: {scan_result.scanner_name!r}",
        )
    else:
        parsed = parser.parse(
            stdout=scan_result.result.stdout,
            exit_code=scan_result.result.exit_code,
        )

    decision = _make_decision(scan_result.result.exit_code, parsed)

    # evidence_path follows the locked convention: raw/{scanner_name}-output.json
    # Step 3 (bundle builder) must write the raw output to this exact path.
    evidence_path = f"raw/{scan_result.scanner_name}-output.json"

    return PolicyDecisionRecord(
        input_hash=input_hash,
        policy_version=policy_version,
        decision=decision,
        evidence_path=evidence_path,
        timestamp=datetime.now(UTC),
    )


def build_all_pdrs(
    scan_results: list[ScanResult],
    policy_version: str,
) -> list[PolicyDecisionRecord]:
    """Build a PDR for every scan result in the list.

    Results and PDRs are in the same order, so callers can zip them together
    to pair scanner names with their verdicts.

    Args:
        scan_results:   All ScanResult objects from run_scan().
        policy_version: Passed through to each build_pdr() call.

    Returns:
        A list of PolicyDecisionRecord objects, one per scan result.
    """
    return [build_pdr(r, policy_version) for r in scan_results]
