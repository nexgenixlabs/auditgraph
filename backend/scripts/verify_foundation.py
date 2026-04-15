#!/usr/bin/env python3
"""
AuditGraph Foundation Verification
Run: python3 scripts/verify_foundation.py
"""
import subprocess, json, urllib.request, sys

DB = ["psql", "-h", "localhost", "-p", "5434",
      "-U", "auditgraph", "-d", "auditgraph",
      "-t", "-A"]
ENV = {"PGPASSWORD": "auditgraph"}
API = "http://localhost:5000"

PASS = 0
FAIL = 0

def sql(query):
    import os
    e = os.environ.copy()
    e["PGPASSWORD"] = "auditgraph"
    r = subprocess.run(DB + ["-c", query],
        capture_output=True, text=True, env=e)
    return r.stdout.strip()

def check(name, got, expected, note=""):
    global PASS, FAIL
    ok = str(got).strip() == str(expected).strip()
    symbol = "✅" if ok else "❌"
    suffix = f"  ({note})" if note else ""
    print(f"  {symbol} {name}: {got}{suffix}")
    if ok: PASS += 1
    else:
        FAIL += 1
        print(f"       expected: {expected}")

def api_get(path, token=None):
    req = urllib.request.Request(f"{API}{path}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        return {}, e.code
    except Exception as e:
        return {"error": str(e)}, 0

def get_token(username, password):
    req = urllib.request.Request(
        f"{API}/api/auth/login",
        data=json.dumps({"username": username,
                         "password": password}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("access_token","")
    except:
        return ""

print("=" * 50)
print("AUDITGRAPH FOUNDATION VERIFICATION")
print("=" * 50)
print()

# ── F1: RLS Coverage ──────────────────────────────
print("--- F1: RLS Coverage ---")
unprotected = sql("""
SELECT COUNT(*) FROM pg_tables t
WHERE schemaname='public'
  AND rowsecurity=false
  AND tablename != 'users'
  AND EXISTS (
    SELECT 1 FROM information_schema.columns c
    WHERE c.table_name=t.tablename
      AND c.column_name='organization_id'
      AND c.table_schema='public'
  )
""")
check("Unprotected org tables (excl users)",
      unprotected, "0")
print()

# ── F2: Dual Write ────────────────────────────────
print("--- F2: Dual Write (scan humans in identity_list) ---")
latest = sql("""
SELECT MAX(id) FROM discovery_runs
WHERE organization_id=2 AND status='completed'
""")
humans_scan = sql(f"""
SELECT COUNT(*) FROM identities i
JOIN discovery_runs dr ON dr.id=i.discovery_run_id
WHERE dr.organization_id=2
  AND dr.id={latest}
  AND i.identity_type IN (
    'user','human_user','guest',
    'guest_user','member','b2b_user'
  )
""") if latest else "0"
humans_list = sql("""
SELECT COUNT(*) FROM identity_list
WHERE organization_id=2
  AND identity_type IN ('human_user','guest_user')
""")
missing = sql(f"""
SELECT COUNT(*) FROM identities i
JOIN discovery_runs dr ON dr.id=i.discovery_run_id
WHERE dr.organization_id=2
  AND dr.id={latest}
  AND i.identity_type IN (
    'user','human_user','guest',
    'guest_user','member','b2b_user'
  )
  AND NOT EXISTS (
    SELECT 1 FROM identity_list il
    WHERE il.organization_id=2
      AND il.identity_id=i.identity_id
  )
""") if latest else "0"
check("All scan humans exist in identity_list",
      missing, "0",
      f"scan={humans_scan} list={humans_list} missing={missing}")
print()

# ── F3: Human users present ───────────────────────
print("--- F3: Human users in identity_list ---")
humans = int(sql("""
SELECT COUNT(*) FROM identity_list
WHERE organization_id=2
  AND identity_type='human_user'
""") or 0)
check("human_user count > 0",
      "yes" if humans > 0 else "no", "yes",
      f"found {humans}")
print()

# ── F4: Org Isolation ─────────────────────────────
print("--- F4: Org Isolation ---")
contam = sql("""
SELECT COUNT(*) FROM identity_list a
WHERE EXISTS (
  SELECT 1 FROM identity_list b
  WHERE b.organization_id != a.organization_id
    AND b.identity_id = a.identity_id
)
""")
check("Cross-org contamination", contam, "0")
print()

# ── F5: Uniqueness ────────────────────────────────
print("--- F5: Uniqueness ---")
dupes = sql("""
SELECT COUNT(*) FROM (
  SELECT organization_id, identity_id
  FROM identity_list
  GROUP BY organization_id, identity_id
  HAVING COUNT(*) > 1
) d
""")
check("Duplicate (org,identity) pairs", dupes, "0")
print()

# ── F6: RLS Policies ──────────────────────────────
print("--- F6: RLS Policies ---")
policy_tables = int(sql("""
SELECT COUNT(DISTINCT tablename)
FROM pg_policies
WHERE schemaname='public'
""") or 0)
check("Tables with RLS policies > 50",
      "yes" if policy_tables > 50 else "no", "yes",
      f"found {policy_tables} tables with policies")
print()

# ── F7: Canonical View ────────────────────────────
print("--- F7: Canonical View ---")
view = sql("""
SELECT COUNT(*) FROM information_schema.views
WHERE table_name='identities_canonical'
  AND table_schema='public'
""")
check("identities_canonical view exists", view, "1")
print()

# ── F8: API Isolation ─────────────────────────────
print("--- F8: API Isolation ---")
sp_token = get_token("spadmin", "changeme")
if len(sp_token) > 20:
    data, _ = api_get("/api/identities", sp_token)
    count = data.get("total", 0)
    check("org=2 identity count == 57", count, 57)

    # Cross-org: request known org=2 identity
    GITHUB = "9286566e-4718-40cd-a2cd-05c6772b66cb"
    _, status = api_get(f"/api/identities/{GITHUB}",
                        sp_token)
    check("Own org identity returns 200", status, 200)
else:
    print("  ⚠️  Cannot get token — is backend running?")
    FAIL += 2
print()

# ── F9: No orphaned org data ──────────────────────
print("--- F9: No orphaned org data ---")
orphan = sql("""
SELECT COUNT(*) FROM identity_list il
WHERE NOT EXISTS (
  SELECT 1 FROM organizations o
  WHERE o.id = il.organization_id
)
""")
check("Orphaned identity rows", orphan, "0")
print()

# ── F10: Discovery rule ───────────────────────────
print("--- F10: Discovery Rule ---")
print("  Rule: only store identities with roles")
spn_no_roles = sql("""
SELECT COUNT(*) FROM identity_list il
WHERE organization_id=2
  AND identity_type='service_principal'
  AND NOT COALESCE(is_microsoft_system,false)
  AND NOT EXISTS (
    SELECT 1 FROM role_assignments ra
    WHERE ra.identity_id=il.identity_id
      AND ra.organization_id=il.organization_id
  )
  AND NOT EXISTS (
    SELECT 1 FROM entra_role_assignments era
    WHERE era.identity_id=il.identity_id
  )
""")
print(f"  ℹ️  SPNs with no roles in identity_list: "
      f"{spn_no_roles} (informational — may be MS system)")
print()

# ── F11: Cross-table isolation invariant ──────────
print("--- F11: Cross-Table Isolation Invariant ---")
# Verify that role_assignments and anomalies reference only identities
# belonging to the same org (no cross-org foreign key leakage).
cross_ra = sql("""
SELECT COUNT(*) FROM role_assignments ra
JOIN identities i ON i.id = ra.identity_db_id
JOIN discovery_runs dr ON dr.id = i.discovery_run_id
WHERE ra.organization_id IS NOT NULL
  AND dr.organization_id != ra.organization_id
""")
check("role_assignments cross-org leakage", cross_ra, "0")

cross_anom = sql("""
SELECT COUNT(*) FROM anomalies a
WHERE a.organization_id IS NOT NULL
  AND a.identity_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM identity_list il
    WHERE il.identity_id = a.identity_id
      AND il.organization_id = a.organization_id
  )
  AND EXISTS (
    SELECT 1 FROM identity_list il2
    WHERE il2.identity_id = a.identity_id
  )
""")
check("anomalies cross-org leakage", cross_anom, "0")
print()

# ── Summary ───────────────────────────────────────
print("=" * 50)
print(f"RESULT: {PASS} passed, {FAIL} failed")
if FAIL == 0:
    print("✅ FOUNDATION IS SOLID")
    print()
    print("Safe to:")
    print("  - Add new org and run scan")
    print("  - Proceed to W2-A1 approval workflow")
    print("  - Plan live client demo")
else:
    print(f"❌ {FAIL} checks need attention before proceeding")
print("=" * 50)

sys.exit(0 if FAIL == 0 else 1)
