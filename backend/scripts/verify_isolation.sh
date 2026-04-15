#!/bin/bash
# AuditGraph Foundation Verification
# Run: bash scripts/verify_isolation.sh

DB="PGPASSWORD=auditgraph psql -h localhost -p 5434 -U auditgraph -d auditgraph"
API="http://localhost:5000"
PASS=0
FAIL=0

check() {
  local name=$1
  local result=$2
  local expected=$3
  if [ "$result" = "$expected" ]; then
    echo "  ✅ $name: $result"
    PASS=$((PASS+1))
  else
    echo "  ❌ $name: got=$result expected=$expected"
    FAIL=$((FAIL+1))
  fi
}

echo "================================================"
echo "AUDITGRAPH FOUNDATION VERIFICATION"
echo "================================================"
echo ""

echo "--- F1: RLS Coverage ---"
UNPROTECTED=$(eval $DB -t -c "
SELECT COUNT(*) FROM pg_tables t
WHERE t.schemaname='public'
  AND t.rowsecurity=false
  AND tablename != 'users'
  AND EXISTS (
    SELECT 1 FROM information_schema.columns c
    WHERE c.table_name=t.tablename
      AND c.column_name='organization_id'
      AND c.table_schema='public'
  );")
check "Unprotected tables (excl users)" \
  "$(echo $UNPROTECTED | tr -d ' ')" "0"

echo ""
echo "--- F2: Dual Write (latest scan vs identity_list) ---"
LATEST_RUN=$(eval $DB -t -c "
SELECT MAX(id) FROM discovery_runs
WHERE organization_id=2 AND status='completed';")
HUMANS_SCAN=$(eval $DB -t -c "
SELECT COUNT(*) FROM identities i
JOIN discovery_runs dr ON dr.id=i.discovery_run_id
WHERE dr.organization_id=2
  AND dr.id=$LATEST_RUN
  AND i.identity_type IN ('user','human_user','guest');")
HUMANS_LIST=$(eval $DB -t -c "
SELECT COUNT(*) FROM identity_list
WHERE organization_id=2
  AND identity_type IN ('human_user','guest_user');")
check "Humans in latest scan" \
  "$(echo $HUMANS_SCAN | tr -d ' ')" \
  "$(echo $HUMANS_LIST | tr -d ' ')"

echo ""
echo "--- F3: Human users in identity_list ---"
HUMANS=$(eval $DB -t -c "
SELECT COUNT(*) FROM identity_list
WHERE organization_id=2
  AND identity_type='human_user';")
check "Human users > 0" \
  "$([ $(echo $HUMANS | tr -d ' ') -gt 0 ] && echo 'yes' || echo 'no')" \
  "yes"

echo ""
echo "--- F4: Org Isolation ---"
CONTAM=$(eval $DB -t -c "
SELECT COUNT(*) FROM identity_list a
WHERE EXISTS (
  SELECT 1 FROM identity_list b
  WHERE b.organization_id != a.organization_id
    AND b.identity_id = a.identity_id
);")
check "Cross-org contamination" \
  "$(echo $CONTAM | tr -d ' ')" "0"

echo ""
echo "--- F5: Uniqueness ---"
DUPES=$(eval $DB -t -c "
SELECT COUNT(*) FROM (
  SELECT organization_id, identity_id, COUNT(*)
  FROM identity_list
  GROUP BY organization_id, identity_id
  HAVING COUNT(*) > 1
) d;")
check "Duplicate (org,identity) pairs" \
  "$(echo $DUPES | tr -d ' ')" "0"

echo ""
echo "--- F6: RLS Policies ---"
POLICIES=$(eval $DB -t -c "
SELECT COUNT(DISTINCT tablename)
FROM pg_policies
WHERE schemaname='public';")
check "Tables with RLS policies > 50" \
  "$([ $(echo $POLICIES | tr -d ' ') -gt 50 ] \
    && echo 'yes' || echo 'no')" "yes"

echo ""
echo "--- F7: Canonical View ---"
VIEW=$(eval $DB -t -c "
SELECT COUNT(*) FROM information_schema.views
WHERE table_name='identities_canonical'
  AND table_schema='public';")
check "identities_canonical view exists" \
  "$(echo $VIEW | tr -d ' ')" "1"

echo ""
echo "--- F8: API Isolation ---"
TOKEN=$(curl -s -X POST $API/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"spadmin","password":"changeme"}' \
  | python3 -c "
import json,sys
try: print(json.load(sys.stdin).get('access_token',''))
except: print('')")

if [ ${#TOKEN} -gt 20 ]; then
  SP_COUNT=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "$API/api/identities" \
    | python3 -c "
import json,sys
try: print(json.load(sys.stdin).get('total',0))
except: print(0)")
  check "org=2 API count == 57" \
    "$SP_COUNT" "57"

  # Cross-org: org=2 user requesting known org=2 UUID
  GITHUB_ID="9286566e-4718-40cd-a2cd-05c6772b66cb"
  CROSS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "$API/api/identities/$GITHUB_ID")
  check "Own org identity accessible (200)" \
    "$CROSS" "200"
else
  echo "  ⚠️  Cannot get token — backend running?"
  FAIL=$((FAIL+1))
fi

echo ""
echo "--- F9: No orphaned org data ---"
ORPHAN=$(eval $DB -t -c "
SELECT COUNT(*) FROM identity_list il
WHERE NOT EXISTS (
  SELECT 1 FROM organizations o
  WHERE o.id = il.organization_id
);")
check "Orphaned identity rows" \
  "$(echo $ORPHAN | tr -d ' ')" "0"

echo ""
echo "================================================"
echo "RESULT: $PASS passed, $FAIL failed"
if [ $FAIL -eq 0 ]; then
  echo "✅ FOUNDATION IS SOLID"
else
  echo "❌ $FAIL checks need attention"
fi
echo "================================================"
