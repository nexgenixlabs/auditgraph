# Self-Signup → Cloud-Connection Flow Audit

**Date**: 2026-06-07
**Trigger**: Pre-pilot ticket #2 — verify the existing self-signup → discovery flow is enterprise-ready
**Scope**: End-to-end from `POST /api/auth/signup` through first discovery scan
**Verdict**: ✅ Technically clean. 4 enterprise-readiness gaps to close before pilot.

---

## 1. The flow today (as built)

| Step | Endpoint | What it does | State |
|---|---|---|---|
| 1 | `POST /api/auth/signup` | Creates `organizations` row + admin `users` row atomically. **Zero demo data seeded.** Returns access + refresh token + verification token. | ✅ Clean |
| 2 | `POST /api/auth/verify-email` | Confirms email via token | ✅ Exists |
| 3 | Customer creates Azure app registration manually in their tenant | (out of platform) | ⚠ No guidance |
| 4 | `POST /api/client/connections/test` | Verifies credentials work | ⚠ No permission-scope verification |
| 5 | `POST /api/client/connections` | Persists cloud connection (encrypts client_secret) | ✅ Cross-org uniqueness check present |
| 6 | Connection creation can auto-discover subscriptions if `status='connected'` | (atomic with step 5) | ✅ Good |
| 7 | `POST /api/runs/trigger` | First discovery scan kicks off | ✅ Exists |

### Existing safety controls (already in place)

- **`_demo_write_guard()`** on mutation handlers — blocks writes against the AuditGraph Demo tenant so a sales viewer can't break the demo
- **`assert_safe_demo_org()`** (new, ticket A today) — blocks seeders from writing demo data to customer orgs
- **Cross-org connector uniqueness check** — prevents same Azure tenant ID from being claimed by two orgs (line 18822 in handlers.py)
- **Entitlement check** (`enforce_subscription_limit`) — caps number of cloud connections per plan
- **Encrypted client_secret** — stored encrypted in JSONB, never returned in API responses
- **Slug collision handling** — automatic suffix if `acme` taken, becomes `acme-1`
- **Atomic signup** — org + user created in one transaction, rolls back together if either fails

This is a strong baseline. No demo data accidentally lands in a new customer's tenant.

---

## 2. The 4 enterprise-readiness gaps

### Gap 1 — No in-product consent-grant guidance (UX)

**Symptom**: After signup the customer's IAM admin needs to manually create an Azure app registration with the right permissions, copy the tenant ID + client ID + secret, and paste them into the AuditGraph connections page. We don't tell them HOW.

**What an enterprise CISO expects**:
1. Click "Connect Azure" in AuditGraph
2. See a 5-step guided walkthrough with the exact permissions to grant
3. Optionally a "consent URL" link that pre-fills the app registration parameters

**Effort to fix**: 2-3 days for a guided wizard. Short-term workaround: a hosted 1-pager at `docs.auditgraph.ai/azure-connection-setup` with the exact steps + screenshots. (~1 day, can ship before first pilot.)

**Recommendation**: ship the 1-pager pre-pilot. Build the in-product wizard post-pilot when you know which steps actually confuse customers.

---

### Gap 2 — No permission-scope verification on connection test

**Symptom**: `POST /api/client/connections/test` verifies credentials work (auth succeeds) but doesn't verify the granted permissions match what AuditGraph actually needs. A customer could grant `Directory.ReadWrite.All` (too much) or `User.Read` (too little) and the test would pass.

**What an enterprise CISO expects**:
- "Your app registration has Directory.Read.All ✅, RoleManagement.Read.Directory ✅, AuditLog.Read.All ✅. **No write permissions detected** — good."
- If too few: red error listing missing permissions
- If too many: yellow warning ("you granted ReadWrite — consider downscoping for least privilege")

**Effort to fix**: 1 day. After authenticating, call `GET https://graph.microsoft.com/v1.0/applications/{appId}?$select=requiredResourceAccess` and parse the granted scopes against an expected set.

**Recommendation**: build this before first pilot. It's a 1-day investment that directly supports the "agentless + read-only" pitch (the system PROVES we're read-only by surfacing the customer's own consent grant).

---

### Gap 3 — No Day-0 onboarding walkthrough UI

**Symptom**: After signup + first discovery, the customer lands on the Executive Posture page with no context. The findings + dollar exposures are powerful but if the CISO is alone they don't know which screen to look at first.

**What an enterprise CISO expects**:
- A welcome banner: "Welcome to AuditGraph. Your first scan completed in 4m 32s. Here's where to start: ..."
- 3 suggested first actions: review the top critical finding, assign owner to the worst orphaned NHI, configure your first SOC integration

**Effort to fix**: 2 days for a guided tour overlay. Shorter-term: a 30-min Day-0 screenshare with founder (per the pilot checklist) covers this.

**Recommendation**: skip the UI build for first pilot — use the Day-0 screenshare. After 3-5 pilots, build the in-product tour informed by what those customers actually asked.

---

### Gap 4 — No automatic post-signup discovery trigger

**Symptom**: After signup + connection creation, the customer must manually click "Run Discovery" to see any data. Until they do, the entire app shows zero state.

**What an enterprise CISO expects**:
- Connection creation completes
- A toast appears: "Discovery started, ~3-5 minutes for your tenant. We'll email you when it's done."
- They get an email + the dashboard auto-refreshes when ready

**Effort to fix**: 4 hours. Connection creation handler already supports auto-discovery when `status='connected'` (line 18856 in handlers.py); needs to ALWAYS trigger when a connection is added (not just when caller passed `status='connected'`). Plus a frontend toast.

**Recommendation**: ship before first pilot. Eliminates "why does my dashboard show zero?" support tickets.

---

## 3. Recommended pre-pilot fixes (prioritized)

| # | Gap | Effort | Why prioritize |
|---|---|---|---|
| 1 | **1-pager at docs.auditgraph.ai/azure-connection-setup** | 1 day | Customer's IAM admin has to do this; we need to tell them how |
| 2 | **Permission-scope verification in connection test** | 1 day | Directly supports the "agentless + read-only" pitch by proving it from their data |
| 3 | **Auto-trigger discovery after first connection** | 4 hours | Eliminates "where's my data?" friction |
| 4 | **Day-0 welcome banner with 3 next actions** | 4 hours | Soft version: skip and use Day-0 founder screenshare for first 3 pilots |

**Total: ~2.5 days of engineering work to close all four.**

Alternative: ship #1 + #2 + #3 (~2 days), use Day-0 founder screenshare in lieu of #4 until 3+ pilots are landed.

---

## 4. What does NOT need fixing

The audit also confirmed the boring-but-critical parts of the flow are already done:

- ✅ Signup is atomic + idempotent on email collision
- ✅ Password hashing (bcrypt with configurable rounds)
- ✅ JWT tokens issued correctly with org context
- ✅ Email verification flow exists
- ✅ Slug collision handling
- ✅ Cross-org connector uniqueness (one Azure tenant ID can't be claimed by two orgs)
- ✅ client_secret encrypted at rest
- ✅ `_demo_write_guard()` prevents mutations on the AuditGraph Demo tenant
- ✅ Subscription/connection entitlement enforcement
- ✅ Auto subscription discovery on successful connection

**Verdict**: the platform's signup → discovery plumbing is enterprise-grade. The 4 gaps are UX polish + safety improvements, not architectural problems.

---

## 5. Recommended pilot Day 0 flow (with current platform)

Since the 4 gaps are UX/safety not architectural, the pilot can proceed today using a screenshare-assisted Day 0:

1. **Pre-meeting** — send the customer the 1-pager (or a doc draft)
2. **Day 0, 30 min** — screenshare with founder + customer's IAM admin
3. Customer signs up at `dev.app.auditgraph.ai` (uses real email, real org name)
4. Founder walks them through Azure app registration (use a shared screen, customer's tenant)
5. Customer grants the read-only permissions; founder reads them back to confirm scope
6. Customer pastes tenant ID + client ID + secret into AuditGraph connections page
7. Founder clicks "Run Discovery"; ~3-5 min wait
8. Once complete, founder walks through Executive Posture + 3 top findings together
9. Get customer reaction; capture for case study notes
10. End of meeting: customer has a populated dashboard, knows where the value is

**No code changes required for first pilot.** The 4 gaps above are improvements to remove the founder from the loop on pilots 4+.

---

## 6. Sign-off checklist for B (this audit)

- [x] Signup handler reviewed — no demo data seeded ✅
- [x] Connection creation handler reviewed — cross-org uniqueness + entitlement check ✅
- [x] Encryption verified — client_secret stored encrypted in JSONB ✅
- [x] 4 enterprise-readiness gaps identified + effort sized
- [x] Recommended pre-pilot fix list (2-3 days)
- [x] Recommended pilot Day 0 flow that works WITHOUT closing the gaps first

---

## Bottom line

**The signup → discovery flow is technically ready for first pilot.** Close gaps 1-3 (2 days work) if you want hands-off pilot onboarding; otherwise the screenshare-assisted Day 0 works fine for pilots 1-3. Either path supports a clean first impression.
