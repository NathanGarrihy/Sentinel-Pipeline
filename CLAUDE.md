# CLAUDE.md - Sentinel Project Context

## 1. Project Vision
Sentinel is a **Policy-Enforced Delivery Control Plane**. 
It orchestrates security tools to generate a cryptographically signed **Policy Decision Record (PDR)** that proves a software artifact is compliant.

**Target Audience:** High-Assurance Swiss Industries (FinTech, Pharma, Defense).

## 2. Tech Stack (Strict Version)
- **Language:** Python 3.12+ (Typed, Strict Mode)
- **CLI Framework:** Typer (with `rich` for UI)
- **Configuration:** Pydantic Settings + `sentinel.yaml`
- **Testing:** Pytest + Pytest-Mock
- **Linter:** Ruff (enforce PEP8)

## 3. Architecture Rules (Non-Negotiable)

### Rule A: The "Secure Execution" Contract
* **No Raw Subprocesses:** All external tool execution MUST occur via the `sentinel.core.executor` module.
* **Interface:** The executor must implement a Protocol (Interface) to allow mocking.
* **Result Object:** Every execution returns a strict `ExecutionResult` containing the `stdout`, `exit_code`, and a **SHA256 hash** of the output.

### Rule B: The "Policy Decision Record" (PDR)
Sentinel does not just "scan." It generates PDRs.
* **PDR Definition:** An immutable JSON object containing:
    * `input_hash`: Hash of the artifact scanned.
    * `policy_version`: Version of the OPA/Checkov rules used.
    * `decision`: "PASS" | "FAIL" | "WARNING_ACCEPTED".
    * `evidence_path`: Link to the raw scanner output in the bundle.
    * `timestamp`: UTC execution time.

### Rule C: Evidence Bundle Structure
The `evidence.zip` must follow this structure:

/
├── manifest.json       # Root of Trust (Hashes of all PDRs)
├── pdr/                # Policy Decision Records (The "Legal" verdict)
│   ├── pdr-sast.json
│   └── pdr-sca.json
├── raw/                # Raw tool outputs (The "Evidence")
│   ├── semgrep-output.json
│   └── trivy-output.json
└── signature.pub       # Public key

### Rule D: Configuration
Scanners are defined in sentinel.yaml.

Pre-Flight Check: The CLI must verify trivy, cosign, syft, semgrep, and checkov are in $PATH on startup.# CLAUDE.md - Sentinel Project Context

## 1. Project Vision
Sentinel is a **Policy-Enforced Delivery Control Plane**. 
It orchestrates security tools to generate a cryptographically signed **Policy Decision Record (PDR)** that proves a software artifact is compliant.

**Target Audience:** High-Assurance Swiss Industries (FinTech, Pharma, Defense).

## 2. Tech Stack (Strict Version)
- **Language:** Python 3.12+ (Typed, Strict Mode)
- **CLI Framework:** Typer (with `rich` for UI)
- **Configuration:** Pydantic Settings + `sentinel.yaml`
- **Testing:** Pytest + Pytest-Mock
- **Linter:** Ruff (enforce PEP8)

## 3. Architecture Rules (Non-Negotiable)

### Rule A: The "Secure Execution" Contract
* **No Raw Subprocesses:** All external tool execution MUST occur via the `sentinel.core.executor` module.
* **Interface:** The executor must implement a Protocol (Interface) to allow mocking in tests.
* **Result Object:** Every execution returns a strict `ExecutionResult` containing the `stdout`, `exit_code`, and a **SHA256 hash** of the output.

### Rule B: The "Policy Decision Record" (PDR)
Sentinel does not just "scan." It generates PDRs.
* **PDR Definition:** An immutable JSON object containing:
    * `input_hash`: Hash of the artifact scanned.
    * `policy_version`: Version of the OPA/Checkov rules used.
    * `decision`: "PASS" | "FAIL" | "WARNING_ACCEPTED".
    * `evidence_path`: Link to the raw scanner output in the bundle.
    * `timestamp`: UTC execution time.

### Rule C: Evidence Bundle Structure
The `evidence.zip` must follow this structure:
    /
    ├── manifest.json       # Root of Trust (Hashes of all PDRs)
    ├── pdr/                # Policy Decision Records (The "Legal" verdict)
    │   ├── pdr-sast.json
    │   └── pdr-sca.json
    ├── raw/                # Raw tool outputs (The "Evidence")
    │   ├── semgrep-output.json
    │   └── trivy-output.json
    └── signature.pub       # Public key used to verify this bundle

### Rule D: Configuration
* Scanners are defined in `sentinel.yaml`.
* **Pre-Flight Check:** The CLI must verify `trivy`, `cosign`, `syft`, `semgrep`, and `checkov` are in `$PATH` on startup.

---

## CONTEXT: Sentinel Phase 2 Architecture

# SENTINEL PIPELINE
**Policy-Enforced, Evidence-Producing Software Delivery**

Sentinel is an opinionated delivery control plane designed for environments where proof, governance, and non-repudiation are mandatory requirements.

## The Problem
Modern CI/CD pipelines prioritize velocity over verification. They fail regulated audits because they:
* Run scans without recording the decision rationale.
* Block builds without preserving evidence for auditors.
* Conflate **Execution Authority** (the CI) with **Policy Authority** (the Rules).

## The Solution: PDRs & Gatekeepers
Sentinel enforces policy-driven delivery by strictly separating:
1. **Execution:** CI runners (ephemeral and untrusted).
2. **Policy:** Versioned, immutable rulesets.
3. **Decision:** Signed **Policy Decision Records (PDR)**.
4. **Evidence:** Tamper-evident artifacts.

## The Trust Model
| Domain | Trust Level | Responsibility |
| :--- | :--- | :--- |
| **CI Runner** | Ephemeral | Executes tasks; cannot authorize deployment. |
| **Sentinel Engine** | High Trust | Generates and signs PDRs based on policy. |
| **Artifact Store** | Immutable | Retains evidence bundles. |

## Technical Stack
* **Orchestration:** GitHub Actions
* **Application:** Python (FastAPI) / Docker
* **Infrastructure:** Terraform / LocalStack
* **Security Tools:** Semgrep, Trivy, Syft, Checkov, Cosign