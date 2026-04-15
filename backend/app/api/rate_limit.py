"""
Lightweight in-memory rate limiter for compute-heavy Phase 3 endpoints.

Uses a per-org sliding window. Returns 429 with ``Retry-After`` header
when a caller exceeds the limit.

Usage in a FastAPI route::

    @router.post("/score/recompute")
    async def recompute(
        ...,
        _rl: None = Depends(rate_limit("recompute", max_calls=3, window_seconds=60)),
    ):
        ...
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any, Callable

from fastapi import Depends, HTTPException, Request, status

from app.api.deps import get_current_user  # type: ignore[import-not-found]

logger = logging.getLogger(__name__)

# {bucket_key: [(timestamp, ...)]}
_BUCKETS: dict[str, list[float]] = defaultdict(list)


def rate_limit(
    name: str,
    *,
    max_calls: int = 5,
    window_seconds: int = 60,
) -> Callable[..., Any]:
    """Return a FastAPI ``Depends`` callable that enforces rate limiting.

    Parameters
    ----------
    name:
        Logical bucket name (e.g. ``"recompute"``). Combined with org_id
        to form the rate-limit key.
    max_calls:
        Maximum allowed calls per ``window_seconds``.
    window_seconds:
        Sliding window duration.
    """

    async def _check(
        current_user: Any = Depends(get_current_user),
    ) -> None:
        org_id = getattr(current_user, "organization_id", "unknown")
        key = f"{name}:{org_id}"
        now = time.monotonic()

        # Prune old entries
        cutoff = now - window_seconds
        bucket = _BUCKETS[key]
        _BUCKETS[key] = bucket = [t for t in bucket if t > cutoff]

        if len(bucket) >= max_calls:
            retry_after = int(bucket[0] - cutoff) + 1
            logger.warning(
                "rate_limit: %s exceeded %d/%ds for org %s",
                name, max_calls, window_seconds, org_id,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: max {max_calls} calls per {window_seconds}s",
                headers={"Retry-After": str(retry_after)},
            )

        bucket.append(now)

    return _check
