"""Evidence bundle builder for Sentinel.

Takes the outputs of the scanner orchestrator and PDR factory and assembles
the tamper-evident evidence.zip bundle defined in Rule C.

Bundle layout:
    /
    ├── manifest.json         # Root of Trust: SHA-256 hashes of all PDR files
    ├── signing_status.json   # "signed" | "failed" | "skipped" + reason
    ├── signature.sig         # Cosign detached signature (present only when signed)
    ├── pdr/                  # Policy Decision Records
    │   └── pdr-{name}.json
    └── raw/                  # Raw scanner stdout (evidence)
        └── {name}-output.json

Design decisions:
    - Manifest hashes PDR files only (Phase 2). Raw output hashes deferred to Phase 3.
    - Signing is keyless (OIDC via cosign). --skip-signing bypasses it cleanly.
    - Signing failure does NOT abort bundle creation — outcome is recorded in
      signing_status.json and the caller receives a non-"signed" BundleResult.
    - Zip is written atomically: staged to .tmp, then Path.replace() to final path.
    - evidence_path convention in PDRs ("raw/{name}-output.json") is set by
      pdr_factory.py and must match the paths written in Stage 1 exactly.
    - PDR filenames use scanner name (not type) to avoid collisions when two
      scanners share the same type (e.g. two SAST tools in one config).
"""

import hashlib
import json
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from sentinel.core.executor import ExecutorProtocol
from sentinel.models.pdr import PolicyDecisionRecord
from sentinel.models.scan_result import ScanResult


@dataclass(frozen=True, slots=True)
class BundleResult:
    """Result of a build_bundle() call.

    Attributes:
        path:           Absolute path to the written evidence.zip.
        signing_status: "signed"  — cosign succeeded; signature.sig is in the zip.
                        "failed"  — cosign ran but returned a non-zero exit code.
                        "skipped" — --skip-signing was passed; cosign was not invoked.
        signing_error:  Human-readable reason for failure. None when signed or skipped.
    """

    path: Path
    signing_status: Literal["signed", "failed", "skipped"]
    signing_error: str | None = None


def build_bundle(
    scan_results: list[ScanResult],
    pdrs: list[PolicyDecisionRecord],
    policy_version: str,
    executor: ExecutorProtocol,
    output_path: Path,
    skip_signing: bool = False,
) -> BundleResult:
    """Assemble a tamper-evident evidence bundle from scanner results and PDRs.

    Stages:
        1. Write raw scanner stdout  → staging/raw/{name}-output.json
        2. Serialize PDRs            → staging/pdr/pdr-{name}.json
        3. Build manifest.json with SHA-256 hashes of PDR files (Root of Trust)
        4. Attempt cosign signing of manifest.json (skipped if skip_signing=True)
        5. Write signing_status.json recording the outcome
        6. Zip staging directory atomically to output_path

    Args:
        scan_results:   One ScanResult per scanner, in config order.
        pdrs:           One PDR per scan result, in the same order.
        policy_version: From SentinelConfig — recorded verbatim in manifest.json.
        executor:       ExecutorProtocol used to invoke cosign (Rule A — no raw subprocess).
        output_path:    Destination path for the evidence.zip file.
        skip_signing:   If True, skip cosign entirely (signing_status = "skipped").

    Returns:
        BundleResult describing the output path and signing outcome.
    """
    with tempfile.TemporaryDirectory() as _staging:
        staging = Path(_staging)
        raw_dir = staging / "raw"
        pdr_dir = staging / "pdr"
        raw_dir.mkdir()
        pdr_dir.mkdir()

        # --- Stage 1: Raw scanner output ---
        # Write stdout verbatim. An empty string produces an empty file, which is
        # intentional — the evidence_path referenced in the PDR must exist in the
        # bundle even when the scanner crashed before producing output.
        for sr in scan_results:
            (raw_dir / f"{sr.scanner_name}-output.json").write_text(
                sr.result.stdout, encoding="utf-8"
            )

        # --- Stage 2: PDR serialization ---
        for sr, pdr in zip(scan_results, pdrs):
            (pdr_dir / f"pdr-{sr.scanner_name}.json").write_text(
                pdr.model_dump_json(indent=2), encoding="utf-8"
            )

        # --- Stage 3: manifest.json (Root of Trust) ---
        # Hashes are computed from bytes on disk (not the in-memory object) so the
        # manifest accurately reflects exactly what will be sealed into the zip.
        pdr_hashes: dict[str, str] = {}
        for sr in scan_results:
            pdr_file = pdr_dir / f"pdr-{sr.scanner_name}.json"
            pdr_hashes[f"pdr/pdr-{sr.scanner_name}.json"] = hashlib.sha256(
                pdr_file.read_bytes()
            ).hexdigest()

        manifest = {
            "policy_version": policy_version,
            "timestamp": datetime.now(UTC).isoformat(),
            "pdrs": pdr_hashes,
        }
        manifest_path = staging / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        # --- Stage 4: Cosign signing ---
        signing_status: Literal["signed", "failed", "skipped"]
        signing_error: str | None = None

        if skip_signing:
            signing_status = "skipped"
        else:
            sig_path = staging / "signature.sig"
            exec_result = executor.execute([
                "cosign", "sign-blob",
                "--output-signature", str(sig_path),
                str(manifest_path),
            ])
            if exec_result.exit_code == 0:
                signing_status = "signed"
            else:
                signing_status = "failed"
                # Prefer stderr for the error message; fall back to the exit code
                # so signing_error is always a non-empty string on failure.
                signing_error = (
                    exec_result.stderr.strip()
                    or f"cosign exited {exec_result.exit_code}"
                )

        # --- Stage 5: signing_status.json ---
        # Always written — auditors need explicit proof of why signature.sig may
        # be absent, and CI tooling can parse this without inspecting exit codes.
        (staging / "signing_status.json").write_text(
            json.dumps({"status": signing_status, "reason": signing_error}, indent=2),
            encoding="utf-8",
        )

        # --- Stage 6: Atomic zip ---
        # Write to .tmp first, then Path.replace() — atomic on POSIX, raises on
        # Windows collision rather than silently producing a partial archive.
        tmp_path = output_path.with_suffix(".tmp")
        with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in sorted(staging.rglob("*")):
                if file.is_file():
                    zf.write(file, arcname=file.relative_to(staging))
        tmp_path.replace(output_path)

    return BundleResult(
        path=output_path,
        signing_status=signing_status,
        signing_error=signing_error,
    )
