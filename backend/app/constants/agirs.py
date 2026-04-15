# constants/agirs.py

# Workload identity classification
WORKLOAD_CONFIDENCE_DEFAULT: int = 65   # move here from azure_discovery.py:1687
WORKLOAD_CONFIDENCE_THRESHOLD: int = 60  # the >=60 gate; both must stay in sync

# Rate limiting for destructive endpoints
PURGE_RATE_LIMIT_REQUESTS: int = 3        # tightened from 10 — destructive operation
PURGE_RATE_LIMIT_WINDOW_SECONDS: int = 60
CLEANUP_RATE_LIMIT_REQUESTS: int = 5
CLEANUP_RATE_LIMIT_WINDOW_SECONDS: int = 60
