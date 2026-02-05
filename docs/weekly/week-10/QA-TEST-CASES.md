cd ~/projects/auditgraph/docs/weekly/week-10
cat > QA-TEST-CASES.md << 'MARKDOWN'
# Week 10: App Roles Discovery - QA Test Cases

**Feature:** Custom Application Role Assignment Discovery  
**Date:** February 1, 2026  
**Status:** Ready for QA Testing

---

## Test Case 1: Discover App Roles for Service Principal

**Objective:** Verify app roles are discovered when SPN has custom app permissions

**Prerequisites:**
- Service principal exists (spn-test-1)
- Custom application with app role defined (MyApp with "Admin" role)
- spn-test-1 has been assigned "Admin" role in MyApp
- Admin consent has been granted

**Steps:**
1. Run discovery: `curl -X POST http://localhost:5001/api/discovery/trigger`
2. Wait for discovery to complete (~60 seconds)
3. Query database: `SELECT * FROM sp_app_roles WHERE identity_db_id IN (SELECT id FROM identities WHERE display_name = 'spn-test-1')`

**Expected Result:**
- Discovery output shows: `✓ spn-test-1: 1 app role(s)`
- Database contains 1 row with:
  - `resource_display_name = 'MyApp'`
  - `risk_level = 'medium'`
  - `app_role_id` matches the role ID from Azure

**Actual Result:** [To be filled by QA]

**Status:** [ ] Pass [ ] Fail

---

## Test Case 2: No App Roles Found

**Objective:** Verify discovery handles SPNs with no custom app roles

**Prerequisites:**
- Service principal exists (spn-test-2)
- spn-test-2 has NO custom app roles (only Microsoft Graph permissions)

**Steps:**
1. Run discovery
2. Check discovery output

**Expected Result:**
- Discovery output shows: `ℹ️  No custom app role assignments found`
- No errors or exceptions
- Database `sp_app_roles` table has 0 rows for this SPN

**Actual Result:** [To be filled by QA]

**Status:** [ ] Pass [ ] Fail

---

## Test Case 3: Managed Identity with App Roles

**Objective:** Verify managed identities with app roles are discovered

**Prerequisites:**
- User-assigned managed identity exists (uamtest1)
- uamtest1 has custom app role assigned (testapp)
- Admin consent granted

**Steps:**
1. Run discovery
2. Query database for managed identity

**Expected Result:**
- Discovery shows: `✓ uamtest1: 1 app role(s)`
- Database contains app role with correct details
- API endpoint returns app_roles array

**Actual Result:** [To be filled by QA]

**Status:** [ ] Pass [ ] Fail

---

## Test Case 4: Multiple App Roles on Single SPN

**Objective:** Verify SPN with multiple custom app roles

**Prerequisites:**
- Service principal exists (spn-test-multi)
- Assigned to 3 different app roles:
  - App1: "Admin" role
  - App2: "Viewer" role
  - App3: "Editor" role
- All consents granted

**Steps:**
1. Run discovery
2. Query database: `SELECT COUNT(*) FROM sp_app_roles WHERE identity_db_id IN (SELECT id FROM identities WHERE display_name = 'spn-test-multi')`

**Expected Result:**
- Discovery shows: `✓ spn-test-multi: 3 app role(s)`
- Database contains 3 rows
- Each row has different `resource_display_name`
- All have `risk_level` calculated correctly

**Actual Result:** [To be filled by QA]

**Status:** [ ] Pass [ ] Fail

---

## Test Case 5: App Role Without Admin Consent

**Objective:** Verify app roles without admin consent are NOT discovered

**Prerequisites:**
- Service principal exists (spn-test-noconsent)
- App role assigned but admin consent NOT granted

**Steps:**
1. Check Azure Portal shows permission with warning icon
2. Run discovery
3. Query database

**Expected Result:**
- Discovery output shows 0 app roles for this SPN
- Database has no rows for this SPN
- No errors in discovery logs

**Actual Result:** [To be filled by QA]

**Status:** [ ] Pass [ ] Fail

---

## Test Case 6: API Endpoint Returns App Roles

**Objective:** Verify GET /api/identities/{id} includes app_roles

**Prerequisites:**
- spn-test-1 has 1 app role in database
- Backend is running

**Steps:**
1. Get identity_id: `psql ... -c "SELECT identity_id FROM identities WHERE display_name='spn-test-1' LIMIT 1"`
2. Call API: `curl http://localhost:5001/api/identities/{identity_id}`
3. Parse JSON response

**Expected Result:**
```json
{
  "identity": {...},
  "roles": [...],
  "graph_permissions": [...],
  "app_roles": [
    {
      "app_role_id": "...",
      "resource_display_name": "MyApp",
      "risk_level": "medium"
    }
  ]
}
```

**Actual Result:** [To be filled by QA]

**Status:** [ ] Pass [ ] Fail

---

## Test Case 7: Risk Level Calculation

**Objective:** Verify app role risk levels are calculated correctly

**Prerequisites:**
- Create app roles in apps with these names:
  - "Production-Finance-App" → should be HIGH
  - "Dev-Test-App" → should be MEDIUM
  - "MyCustomApp" → should be MEDIUM

**Steps:**
1. Assign SPN to each app role
2. Grant consent
3. Run discovery
4. Query: `SELECT resource_display_name, risk_level FROM sp_app_roles`

**Expected Result:**
- Production-Finance-App → `risk_level = 'high'`
- Dev-Test-App → `risk_level = 'medium'`
- MyCustomApp → `risk_level = 'medium'`

**Actual Result:** [To be filled by QA]

**Status:** [ ] Pass [ ] Fail

---

## Test Case 8: Microsoft Graph Filtered Out

**Objective:** Verify Microsoft Graph permissions are NOT stored in sp_app_roles

**Prerequisites:**
- SPN has both Microsoft Graph permissions AND custom app roles
- Example: User.Read.All (Graph) + testapp (custom)

**Steps:**
1. Run discovery
2. Query: `SELECT * FROM sp_app_roles WHERE resource_display_name = 'Microsoft Graph'`
3. Query: `SELECT * FROM graph_api_permissions WHERE permission_name = 'testapp'`

**Expected Result:**
- sp_app_roles has 0 rows with "Microsoft Graph"
- graph_api_permissions does NOT contain "testapp"
- Custom app roles in sp_app_roles
- Microsoft Graph in graph_api_permissions

**Actual Result:** [To be filled by QA]

**Status:** [ ] Pass [ ] Fail

---

## Test Case 9: Scheduler Integration

**Objective:** Verify app roles are discovered in scheduled runs

**Prerequisites:**
- Scheduler is running (every 6 hours)
- SPN with app role exists

**Steps:**
1. Wait for next scheduled discovery (check with `curl http://localhost:5001/api/scheduler/status`)
2. After run completes, check database
3. Verify app_roles were discovered

**Expected Result:**
- Scheduled discovery includes app roles step
- Database updated with latest app roles
- No manual trigger needed

**Actual Result:** [To be filled by QA]

**Status:** [ ] Pass [ ] Fail

---

## Test Case 10: Database Constraints

**Objective:** Verify database prevents duplicate app role entries

**Prerequisites:**
- SPN with app role exists in database

**Steps:**
1. Run discovery twice in a row
2. Query: `SELECT COUNT(*) FROM sp_app_roles GROUP BY identity_db_id, app_role_id, resource_id HAVING COUNT(*) > 1`

**Expected Result:**
- Query returns 0 rows (no duplicates)
- ON CONFLICT clause updates `discovered_at` timestamp
- Only 1 row per (identity, app_role, resource) combination

**Actual Result:** [To be filled by QA]

**Status:** [ ] Pass [ ] Fail

---

## Performance Test Case

**Objective:** Verify discovery performance with many app roles

**Prerequisites:**
- 50+ service principals in environment
- 10+ have app roles assigned

**Steps:**
1. Run discovery with timing: `time python3 -m tests.test_discovery`
2. Note app roles discovery duration

**Expected Result:**
- App roles discovery completes in < 10 seconds
- Total discovery time increase < 20%
- No timeouts or errors

**Actual Result:** [To be filled by QA]

**Status:** [ ] Pass [ ] Fail

---

## Edge Cases

### Edge Case 1: Empty App Role ID
**Scenario:** App role with null/empty app_role_id  
**Expected:** Skipped gracefully, logged as warning

### Edge Case 2: Very Long Resource Name
**Scenario:** Resource display name > 255 characters  
**Expected:** Stored correctly (TEXT field), no truncation

### Edge Case 3: Special Characters
**Scenario:** App role name with emoji or special chars  
**Expected:** Stored and displayed correctly

---

## Regression Tests

### Regression 1: API Permissions Still Work
**Objective:** Verify Week 9 functionality not broken  
**Steps:** Run discovery, check graph_api_permissions table  
**Expected:** Microsoft Graph permissions still discovered

### Regression 2: Credentials Still Work
**Objective:** Verify Week 5-6 functionality not broken  
**Steps:** Check spn_credentials table after discovery  
**Expected:** Credentials still tracked

---

## Test Environment Setup
```bash
# Create test service principals
az ad sp create-for-rbac --name "spn-qa-test-1"
az ad sp create-for-rbac --name "spn-qa-test-2"

# Create test app with app role
# (Manual step in Azure Portal - create app registration with app role)

# Assign app role to SPN
# (Manual step in Azure Portal - grant permission and consent)

# Run discovery
curl -X POST http://localhost:5001/api/discovery/trigger

# Cleanup after tests
az ad sp delete --id <object-id>
```

---

## Success Criteria

- [ ] All 10 test cases pass
- [ ] Performance test meets requirements
- [ ] No regressions in existing features
- [ ] Edge cases handled gracefully
- [ ] Documentation updated

---

**Prepared by:** Bhupathi  
**Date:** February 1, 2026  
**Review Date:** Week 10 Completion
MARKDOWN

echo "✅ QA test cases created!"