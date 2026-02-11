# 🛡️ SENTINEL PIPELINE
**Policy-Enforced, Evidence-Producing Software Delivery**

Sentinel is an opinionated delivery control plane designed for environments where proof, governance, and non-repudiation are mandatory requirements.

## 🛑 The Problem
Modern CI/CD pipelines prioritize velocity over verification. They fail regulated audits because they:
* Run scans without recording the decision rationale.
* Block builds without preserving evidence for auditors.
* Conflate **Execution Authority** (the CI) with **Policy Authority** (the Rules).

## ✅ The Solution: PDRs & Gatekeepers
Sentinel enforces policy-driven delivery by strictly separating:
1. **Execution:** CI runners (ephemeral and untrusted).
2. **Policy:** Versioned, immutable rulesets.
3. **Decision:** Signed **Policy Decision Records (PDR)**.
4. **Evidence:** Tamper-evident artifacts.

## 🏗️ The Trust Model
| Domain | Trust Level | Responsibility |
| :--- | :--- | :--- |
| **CI Runner** | Ephemeral | Executes tasks; cannot authorize deployment. |
| **Sentinel Engine** | High Trust | Generates and signs PDRs based on policy. |
| **Artifact Store** | Immutable | Retains evidence bundles. |

## 🚀 Technical Stack
* **Orchestration:** GitHub Actions
* **Application:** Python (FastAPI) / Docker
* **Infrastructure:** Terraform / LocalStack
* **Security Tools:** Semgrep, Trivy, Syft, Checkov, Cosign