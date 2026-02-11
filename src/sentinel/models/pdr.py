from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Decision(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING_ACCEPTED = "WARNING_ACCEPTED"


class PolicyDecisionRecord(BaseModel):
    """Immutable Policy Decision Record (Rule B).

    A cryptographically meaningful verdict linking an artifact hash,
    a policy version, and a decision with its evidence.
    """

    model_config = ConfigDict(frozen=True)

    input_hash: str
    policy_version: str
    decision: Decision
    evidence_path: str
    timestamp: datetime  # UTC
