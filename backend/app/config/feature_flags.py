"""
Feature flags for AuditGraph — controls Phase 2/3 rollout.

All flags default to False. Phase 1 behavior is the baseline.
Set env var to "true" (case-insensitive) to enable.

Read once at import time. Changing env vars at runtime has no
effect without a process restart — this is intentional: it
prevents split-brain where one worker sees a flag enabled and
another does not.
"""

from __future__ import annotations

import os


def _env_flag(name: str, *, default: bool = False) -> bool:
    """Read a boolean flag from the environment.

    Only the literal string ``"true"`` (case-insensitive, trimmed)
    is treated as truthy. Every other value — including ``"1"``,
    ``"yes"``, ``"on"`` — is falsy. This is intentional: we want
    flag activation to require an unambiguous, explicit opt-in.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() == "true"


class FeatureFlags:
    """Module-level constants read at import time.

    Access as class attributes::

        from app.config.feature_flags import FeatureFlags
        if FeatureFlags.USE_BLAST_RADIUS:
            ...

    Tests monkeypatch::

        monkeypatch.setattr(FeatureFlags, "USE_BLAST_RADIUS", True)
    """

    #: Phase 2 graph traversal engine.
    #: Gates: compute_graph(), IdentityRelationships (B11),
    #: LifecycleEngine (B16).
    #: Env: ``USE_GRAPH_ATTACK_PATHS=true``
    USE_GRAPH_ATTACK_PATHS: bool = _env_flag("USE_GRAPH_ATTACK_PATHS")

    #: Phase 2 confidence propagation in risk scoring.
    #: Env: ``USE_CONFIDENCE_PROPAGATION=true``
    USE_CONFIDENCE_PROPAGATION: bool = _env_flag("USE_CONFIDENCE_PROPAGATION")

    #: Phase 2 B15 ActivitySignals (6-signal, replaces simplified B02).
    #: Env: ``USE_FULL_ACTIVITY_SIGNALS=true``
    USE_FULL_ACTIVITY_SIGNALS: bool = _env_flag("USE_FULL_ACTIVITY_SIGNALS")

    #: Phase 3 blast radius engine (:class:`IdentityBlastRadiusEngine`).
    #: Independent of :attr:`USE_GRAPH_ATTACK_PATHS` — can be toggled
    #: separately so staging can validate blast radius without
    #: flipping the whole graph traversal pipeline.
    #: Env: ``USE_BLAST_RADIUS=true``
    USE_BLAST_RADIUS: bool = _env_flag("USE_BLAST_RADIUS")

    #: Phase 3 migration hatch: dual-run legacy + new blast radius
    #: engines and log a comparison line. NEVER enable in
    #: production — this doubles the cost of every blast radius
    #: computation. Staging / canary only.
    #: Env: ``BLAST_RADIUS_DUAL_RUN=true``
    BLAST_RADIUS_DUAL_RUN: bool = _env_flag("BLAST_RADIUS_DUAL_RUN")


def assert_safe_for_production() -> None:
    """Call at app startup. Raise :class:`RuntimeError` if any
    staging-only flag is enabled in a production environment.

    Checks the ``APP_ENV`` environment variable. If it is
    ``"prod"`` or ``"production"`` (case-insensitive) then:

    * :attr:`FeatureFlags.BLAST_RADIUS_DUAL_RUN` must be ``False``.

    Fails fast at startup so a misconfigured prod deploy never
    silently pays the dual-run cost on every identity build.
    """
    env = os.getenv("APP_ENV", "").strip().lower()
    if env in ("prod", "production"):
        if FeatureFlags.BLAST_RADIUS_DUAL_RUN:
            raise RuntimeError(
                "BLAST_RADIUS_DUAL_RUN must not be enabled in production. "
                "This flag is for staging/canary validation only."
            )


__all__ = ["FeatureFlags", "assert_safe_for_production"]
