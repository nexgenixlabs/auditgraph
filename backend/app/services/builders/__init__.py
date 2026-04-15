"""
AuditGraph identity-state builders
==================================

This package groups the focused, independently-testable builders that
compose a full :class:`IdentityState`. The orchestrator lives one
directory up in ``identity_state_engine.py`` — every block-level
builder lives here.

Layout
------
* :mod:`identity_profile_builder` — B01 profile + colocated DB loaders
  for B03 ownership, B05 privilege, and credential rotation status.
* :mod:`activity_builder` — B02 activity (Phase 1); Phase 2 hook for
  the 6-signal B15 activity signals is declared but not implemented.
* :mod:`governance_engine` — B04 pure derivation.
* :mod:`risk_engine` — B06 pure CVSS v3.1-aligned scoring, plus the
  colocated B09 remediation engine.
* :mod:`attack_path_engine` — B08 attack path computation, with a
  Phase 2 hook for graph-traversal upgrades.

Import rules
------------
Nothing in this package may import from
``app.services.identity_state_engine`` — the orchestrator depends on
the builders, not the other way around. Enforcing a one-way arrow
keeps the refactor testable and prevents circular imports.
"""
