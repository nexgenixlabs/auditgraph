# constants/remediation.py — Remediation Queue SSOT
try:
    from enum import StrEnum
except ImportError:
    from enum import Enum

    class StrEnum(str, Enum):
        """Python 3.9/3.10 backport of StrEnum."""
        pass


class RemediationStatus(StrEnum):
    OPEN        = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED    = "resolved"
    DISMISSED   = "dismissed"


class RemediationSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


VALID_STATUS_TRANSITIONS: dict = {
    RemediationStatus.OPEN:        {RemediationStatus.IN_PROGRESS, RemediationStatus.DISMISSED},
    RemediationStatus.IN_PROGRESS: {RemediationStatus.RESOLVED, RemediationStatus.DISMISSED},
    RemediationStatus.RESOLVED:    {RemediationStatus.OPEN},
    RemediationStatus.DISMISSED:   {RemediationStatus.OPEN},
}
