# AuditGraph - Hosting & Domain Strategy

**Status:** Planning (Implementation in Week 10)  
**Owner:** Platform Admin  
**Last Updated:** January 27, 2026

---

## 🎯 OVERVIEW

This document defines AuditGraph's hosting, domain, and multi-tenant strategy for production deployment.

**Current State:** Running on `localhost:3000` (dev environment)  
**Target State:** Subdomain-based multi-tenancy with global CDN

---

## 🌐 DOMAIN STRATEGY

### **Domain Ownership**
- **Domain:** `auditgraph.ai`
- **Registrar:** GoDaddy (or current registrar)
- **DNS Provider:** Cloudflare (already active)

### **Subdomain Structure**

#### **Environments:**
```
auditgraph.ai           → Marketing site (public)
dev.auditgraph.ai       → Development environment (internal)
demo.auditgraph.ai      → Demo environment (prospects)
```

#### **Customer Tenants:**
```
acme-health.auditgraph.ai   → Customer: Acme Health
ibm.auditgraph.ai           → Customer: IBM
wipro.auditgraph.ai         → Customer: Wipro
```

### **Tenant Naming Rules**
✅ **Allowed:**
- Lowercase letters: `a-z`
- Numbers: `0-9`
- Hyphens: `-` (not at start/end)
- Examples: `acme-health`, `ibm-healthcare`, `wipro-us`

❌ **Reserved Names:**
- `www`, `api`, `dev`, `demo`, `staging`, `admin`, `support`, `status`
- `app`, `auth`, `assets`, `cdn`, `blog`, `docs`

---

## 🏗️ HOSTING ARCHITECTURE

### **Recommended Stack:**

```
Frontend:  Cloudflare Pages
Backend:   Azure Container Apps (or App Service)
Database:  Azure PostgreSQL Flexible Server
CDN:       Cloudflare (built-in)
DNS:       Cloudflare
SSL:       Cloudflare (wildcard cert)
CI/CD:     GitHub Actions
```

### **Why Cloudflare Pages?**
✅ **Advantages:**
- Native GitHub integration (zero config CI/CD)
- Automatic HTTPS with wildcard cert (`*.auditgraph.ai`)
- Global CDN (300+ locations)
- Free for most use cases
- Instant deploys (push to GitHub → live in 30 seconds)
- Preview environments per PR

✅ **Perfect for:**
- React SPA / Next.js static
- Multi-tenant frontend routing
- Fast global performance

❌ **Not for:**
- Backend APIs (use Azure for this)
- Database hosting
- Long-running processes

### **Alternative: GoDaddy Hosting?**
❌ **Not recommended because:**
- Manual deployments (FTP/SSH)
- Poor wildcard subdomain support
- SSL certificate complexity
- Not designed for SaaS multi-tenancy
- Slower than modern CDN solutions

**Verdict:** Keep GoDaddy for domain registration only, use Cloudflare for hosting.

---

## 🔐 SSL/TLS STRATEGY

### **Wildcard Certificate:**
```
*.auditgraph.ai  → Covers all subdomains
```

**Managed by:** Cloudflare (automatic renewal)

**Benefits:**
- One cert covers: `dev`, `demo`, `acme-health`, `ibm`, etc.
- No need to issue cert per customer
- Zero maintenance

### **Nested Subdomains (Future):**
If you ever need `client.org.auditgraph.ai`:
- Requires second wildcard: `*.org.auditgraph.ai`
- **Recommendation:** Avoid. Stick to `client.auditgraph.ai` (simpler)

---

## 🛣️ DNS CONFIGURATION

### **Cloudflare DNS Records:**

```
Type    Name    Target                      Proxy
----    ----    ------                      -----
CNAME   dev     pages.cloudflare.com        ON
CNAME   demo    pages.cloudflare.com        ON
CNAME   *       pages.cloudflare.com        ON
CNAME   api     auditgraph-api.azurecontainerapps.io   ON
```

**Why explicit `dev` and `demo`?**
- Exact match takes priority over wildcard
- Allows different security rules per environment
- Easier to change targets later (e.g., `dev` → different backend)

**Why wildcard `*`?**
- Automatically routes all customer subdomains
- No need to create DNS record per customer
- App validates tenant existence (not DNS)

---

## 🏢 MULTI-TENANT ROUTING

### **How Tenant Resolution Works:**

**1. Request arrives:**
```
Host: acme-health.auditgraph.ai
```

**2. Cloudflare routes to frontend**

**3. Frontend extracts tenant:**
```javascript
const hostname = window.location.hostname;  // acme-health.auditgraph.ai
const parts = hostname.split('.');
const tenant = parts[0];  // "acme-health"
```

**4. Frontend validates tenant:**
```javascript
if (RESERVED_NAMES.includes(tenant)) {
  // Redirect to marketing
}

// Lookup tenant in backend
const response = await fetch(`/api/tenants/${tenant}`);
if (!response.ok) {
  // Show "Tenant not found"
}
```

**5. Load tenant-specific data:**
```javascript
// All API calls include tenant context
const identities = await fetch(`/api/identities?tenant=${tenant}`);
```

---

## 🔒 SECURITY & ISOLATION

### **Environment Access Control:**

**dev.auditgraph.ai:**
- IP allowlist (office IPs only)
- Basic auth or SSO required
- Not publicly accessible

**demo.auditgraph.ai:**
- Public access (for prospects)
- Rate limited
- Sanitized demo data only
- Separate database from production

**Customer tenants:**
- SSO authentication (Azure AD, Okta)
- Per-tenant database isolation
- Encrypted at rest
- Audit logs per tenant

### **Tenant Isolation Models:**

**Option A: Database per Tenant (Most Secure)**
```
acme-health → db-acme-health
ibm         → db-ibm
wipro       → db-wipro
```
✅ Complete data isolation  
❌ Higher operational cost

**Option B: Schema per Tenant**
```
Single DB, multiple schemas:
- schema_acme-health
- schema_ibm
- schema_wipro
```
✅ Good isolation, easier ops  
⚠️ Shared DB resources

**Option C: Row-Level Security (Easiest)**
```
Single DB, single schema:
- All tables have tenant_id column
- RLS policies enforce access
```
✅ Simplest to manage  
⚠️ Weaker isolation

**Recommendation for MVP:** Start with Option C (RLS), migrate to Option B when needed.

---

## 🚀 CI/CD PIPELINE

### **GitHub Branch Strategy:**

```
main    → Production (app.auditgraph.ai later)
dev     → dev.auditgraph.ai
demo    → demo.auditgraph.ai
```

### **Deployment Flow:**

**Frontend (Cloudflare Pages):**
```
1. Push to dev branch
2. Cloudflare auto-builds
3. Deploys to dev.auditgraph.ai
4. ~30 seconds total
```

**Backend (Azure Container Apps):**
```
1. Push to dev branch
2. GitHub Actions triggers
3. Build Docker image
4. Push to Azure Container Registry
5. Deploy to Container App
6. ~3-5 minutes total
```

### **GitHub Actions Workflow (Backend):**
```yaml
name: Deploy Backend to Dev

on:
  push:
    branches: [dev]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Login to Azure
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      - name: Build and deploy
        run: |
          az containerapp up \
            --name auditgraph-api-dev \
            --resource-group auditgraph-dev-rg \
            --source .
```

---

## 📊 ENVIRONMENT CONFIGURATION

### **Environment Variables:**

**dev.auditgraph.ai:**
```
ENVIRONMENT=dev
DB_HOST=auditgraph-db-dev.postgres.database.azure.com
DB_NAME=auditgraph_dev
AZURE_TENANT_ID=<dev-tenant>
LOG_LEVEL=debug
```

**demo.auditgraph.ai:**
```
ENVIRONMENT=demo
DB_HOST=auditgraph-db-demo.postgres.database.azure.com
DB_NAME=auditgraph_demo
AZURE_TENANT_ID=<demo-tenant>
LOG_LEVEL=info
```

**Production:**
```
ENVIRONMENT=production
DB_HOST=auditgraph-db-prod.postgres.database.azure.com
DB_NAME=auditgraph_prod
AZURE_TENANT_ID=<customer-tenant>
LOG_LEVEL=warning
```

---

## 💰 COST ESTIMATES

### **Cloudflare Pages:**
- Free tier: 500 builds/month, unlimited bandwidth
- Pro ($20/month): More builds, analytics
- **Recommendation:** Start free

### **Azure Container Apps:**
- Dev: ~$30/month (0.5 vCPU, 1GB RAM)
- Demo: ~$30/month
- Prod: ~$100/month (scaling enabled)

### **Azure PostgreSQL:**
- Dev: ~$50/month (Burstable B1ms)
- Demo: ~$50/month
- Prod: ~$200/month (General Purpose D2s)

### **Cloudflare DNS + CDN:**
- Free (sufficient for MVP)
- Pro ($20/month): WAF, advanced rules

**Total Monthly Cost (Dev + Demo):**
- ~$160/month (before customers)

---

## 📅 IMPLEMENTATION TIMELINE

### **Week 10: Initial Setup**
- Day 1: Cloudflare Pages setup
- Day 2: GitHub integration + CI/CD
- Day 3: dev.auditgraph.ai live
- Day 4: demo.auditgraph.ai live
- Day 5: Testing + validation

### **Week 11: Production Prep**
- Customer subdomain routing
- SSO integration
- Tenant isolation
- Monitoring & alerts

---

## 🧪 TESTING STRATEGY

### **Before Going Live:**

**DNS Testing:**
```bash
# Test dev subdomain
curl https://dev.auditgraph.ai

# Test wildcard
curl https://test-tenant.auditgraph.ai
```

**SSL Testing:**
```bash
# Verify cert
openssl s_client -connect dev.auditgraph.ai:443 -servername dev.auditgraph.ai

# Check expiry
echo | openssl s_client -connect dev.auditgraph.ai:443 2>/dev/null | openssl x509 -noout -dates
```

**Tenant Routing:**
```bash
# Test tenant extraction
curl -H "Host: acme-health.auditgraph.ai" https://auditgraph.ai/api/tenant
# Should return: {"tenant": "acme-health"}
```

---

## 🚨 SECURITY CHECKLIST

**Before deploying to production:**

- [ ] HTTPS enforced (no HTTP)
- [ ] Wildcard cert installed
- [ ] Rate limiting configured
- [ ] WAF rules active (Cloudflare)
- [ ] IP allowlist for dev environment
- [ ] Reserved subdomains blocked in code
- [ ] Tenant validation in place
- [ ] Database backups configured
- [ ] Secrets in Key Vault (not env files)
- [ ] Logging & monitoring enabled
- [ ] DDoS protection active

---

## 🔮 FUTURE ENHANCEMENTS

### **Phase 2 (Post-MVP):**
- Custom domains: `security.client.com` → CNAME to `client.auditgraph.ai`
- Multi-region deployment (US, EU for data residency)
- GraphQL API for frontend
- WebSocket support for real-time updates

### **Phase 3 (Scale):**
- Kubernetes (AKS) for backend
- Redis for session management
- Elasticsearch for log aggregation
- Datadog for monitoring

---

## 📚 REFERENCES

**Cloudflare Pages:**
- Docs: https://developers.cloudflare.com/pages
- GitHub integration: https://developers.cloudflare.com/pages/platform/git-integration

**Azure Container Apps:**
- Docs: https://learn.microsoft.com/en-us/azure/container-apps
- Multi-tenancy: https://learn.microsoft.com/en-us/azure/architecture/guide/multitenant

**SaaS Multi-Tenancy Patterns:**
- AWS: https://docs.aws.amazon.com/wellarchitected/latest/saas-lens
- Microsoft: https://learn.microsoft.com/en-us/azure/architecture/guide/multitenant

---

## ✅ DECISION LOG

| Date | Decision | Rationale |
|------|----------|-----------|
| Jan 27, 2026 | Use Cloudflare Pages for frontend | Simple, fast, free, wildcard SSL |
| Jan 27, 2026 | Subdomain-based tenancy | Industry standard, clean URLs |
| Jan 27, 2026 | Defer hosting to Week 10 | Features > infrastructure at MVP stage |
| Jan 27, 2026 | No GoDaddy hosting | Not designed for SaaS apps |

---

**Status:** Ready for implementation in Week 10  
**Next Review:** Week 9 (before implementation)

---

*This strategy ensures AuditGraph scales from MVP to enterprise without architectural rework.*