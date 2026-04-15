"""
Fix Cache — Thread-safe in-memory TTL cache for remediation results.

Follows the MetricsCollector pattern (threading.Lock). No Redis dependency.

Key format:
    ("fixes", org_id, identity_id) — per-identity fixes
    ("org_fixes", org_id)          — org-level recommendations

TTL: 900 seconds (15 min).
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional, Tuple

_lock = threading.Lock()
_store: Dict[Tuple, Dict[str, Any]] = {}

TTL_SECONDS = 900  # 15 minutes


def get(key: tuple) -> Optional[dict]:
    """Return cached value if TTL not expired, else None."""
    with _lock:
        entry = _store.get(key)
        if entry is None:
            return None
        if time.monotonic() - entry["_ts"] > TTL_SECONDS:
            del _store[key]
            return None
        return entry["data"]


def put(key: tuple, data: dict) -> None:
    """Store value with monotonic timestamp."""
    with _lock:
        _store[key] = {"data": data, "_ts": time.monotonic()}


def invalidate(org_id: Optional[int] = None) -> None:
    """Clear entries for a specific org, or all entries if org_id is None."""
    with _lock:
        if org_id is None:
            _store.clear()
        else:
            keys_to_remove = [
                k for k in _store
                if len(k) >= 2 and k[1] == org_id
            ]
            for k in keys_to_remove:
                del _store[k]
