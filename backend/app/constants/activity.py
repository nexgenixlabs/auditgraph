# constants/activity.py
try:
    from enum import StrEnum
except ImportError:
    from enum import Enum

    class StrEnum(str, Enum):
        """Python 3.9/3.10 backport of StrEnum."""
        pass


class ActivitySource(StrEnum):
    AUDITGRAPH          = "auditgraph"
    AZURE_SIGNIN        = "azure_signin"
    FEDERATED_INFERENCE = "federated_inference"


ACTIVITY_SOURCE_LABELS: dict[ActivitySource, str] = {
    ActivitySource.AUDITGRAPH:          "AuditGraph observed",
    ActivitySource.AZURE_SIGNIN:        "Azure sign-in logs",
    ActivitySource.FEDERATED_INFERENCE: "Inferred from workload configuration",
}
