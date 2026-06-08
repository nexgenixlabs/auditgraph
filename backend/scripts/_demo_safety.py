"""
Shared safety guard for all demo data seeders.

HARD RULE (per CLAUDE.md): customer tenants are READ-ONLY everywhere.
Only the demo orgs may receive synthetic identity rows.

Allowed demo orgs:
  org=9   — AuditGraph Demo (localhost sandbox)
  org=3   — AuditGraph Demo (cloud-dev — dev.app.auditgraph.ai)
  org=99  — Perf test org (only for perf_seed_at_scale.py; gated separately)

Every seeder script MUST import and call assert_safe_demo_org(org_id)
before any INSERT. The script will sys.exit(1) if the org_id is
outside the allowlist. This protects against:
  - Typos (--org-id 19 vs 9)
  - Copy-paste errors (left over org_id from a previous test)
  - Multi-tenant contamination (writing demo personas into a real
    customer's tenant)

If a new demo org is created (e.g., per-engineer sandbox), add its
ID to ALLOWED_DEMO_ORG_IDS here. Never disable the check.
"""
from __future__ import annotations

import sys

# Canonical demo/test orgs. Adding to this list requires founder approval
# AND a memory entry documenting why.
ALLOWED_DEMO_ORG_IDS = frozenset({
    3,    # AuditGraph Demo — cloud-dev (dev.app.auditgraph.ai)
    9,    # AuditGraph Demo — localhost sandbox
})

# Perf-test org is allowed but only for the perf seeder, not for demo
# persona seeders (those personas would pollute perf timing).
PERF_TEST_ORG_IDS = frozenset({
    99,   # dedicated perf-test org for perf_seed_at_scale.py
})


def assert_safe_demo_org(org_id: int, *, script_name: str | None = None,
                          allow_perf: bool = False) -> None:
    """Abort the script if org_id is not in the demo allowlist.

    Args:
        org_id: target org for the write.
        script_name: optional, included in the error message for context.
        allow_perf: if True, also allow perf-test org IDs (use ONLY in
                    perf_seed_at_scale.py).

    Raises:
        SystemExit(1) if org_id is not allowed.
    """
    allowed = set(ALLOWED_DEMO_ORG_IDS)
    if allow_perf:
        allowed |= PERF_TEST_ORG_IDS

    if org_id in allowed:
        return

    script = script_name or sys.argv[0] if sys.argv else 'this seeder'
    sys.stderr.write(
        f"\n❌ REFUSING to write demo data to org_id={org_id}\n"
        f"   Script: {script}\n"
        f"   Allowed demo orgs: {sorted(allowed)}\n"
        f"\n"
        f"   This guard exists because customer tenants are READ-ONLY everywhere\n"
        f"   (see CLAUDE.md HARD RULE). Demo data written into a customer org\n"
        f"   would permanently damage trust + force a difficult cleanup.\n"
        f"\n"
        f"   If you genuinely want to write here, you're probably in the wrong\n"
        f"   script. Use the customer-onboarding flow instead. If you're sure,\n"
        f"   add {org_id} to ALLOWED_DEMO_ORG_IDS in backend/scripts/_demo_safety.py\n"
        f"   with a comment explaining why (requires founder approval).\n\n"
    )
    sys.exit(1)


def assert_not_customer_org(org_id: int, *, customer_org_ids: set[int],
                             script_name: str | None = None) -> None:
    """Stronger guard for scripts that might legitimately touch multiple orgs.

    Use when the script is allowed to write to ANY org EXCEPT specific
    real-customer orgs. Pass the known customer org IDs in.

    Example:
        # In a script that admins multiple orgs but must never touch the pilot:
        assert_not_customer_org(org_id, customer_org_ids={10, 12, 15})
    """
    if org_id in customer_org_ids:
        sys.stderr.write(
            f"\n❌ REFUSING to write to customer org_id={org_id}\n"
            f"   Script: {script_name or 'unknown'}\n"
            f"   Customer orgs: {sorted(customer_org_ids)} are READ-ONLY.\n\n"
        )
        sys.exit(1)
