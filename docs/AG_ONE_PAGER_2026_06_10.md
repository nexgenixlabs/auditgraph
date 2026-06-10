# AuditGraph — One-Pager

**Identity Security Graph for Human, Non-Human, and AI Identities.**
Agentless. Read-only. Architecture-derived.

---

## The problem

Every Fortune 500 today has:
- **Millions** of human permissions sprawling across cloud + SaaS
- **Tens of thousands** of non-human identities (service principals, managed identities, workloads, CI/CD identities, automation accounts)
- **Hundreds** of AI agents calling models from inside their tenant

**Nobody has a unified graph of all three.**

SailPoint stops at humans. CIEM stops at roles. Astrix / Entro / Oasis stop at NHIs. AI security tools stop at runtime. Each tool covers one tier; none of them connects the chain that matters: *who is reaching what data through which identity?*

When the breach happens, the incident response question is always the same:

> *"What's the chain from the compromised credential to the data we lost?"*

That chain spans humans, non-humans, AI agents, models, and datasets. **That's the chain AuditGraph computes.**

---

## What we built

A single graph that surfaces:

```
Human → Service Principal → Managed Identity → AI Agent → Model → Classified Data
```

Every edge is a verified RBAC / OIDC trust / data-classification relationship — derived from your tenant's architecture, **without any write access, agent installation, or runtime telemetry.**

### Four product surfaces

| Surface | What it answers |
|---|---|
| **Identity** (Human / NHI / AI) | Who exists, who owns them, what role they hold, when was it last used |
| **Graph Intelligence** | The unified graph. Identity Exposure Graph (the patent claim). Access Graph. |
| **Exposure Management** | Attack paths, blast radius, data reachability — universal, not AI-only |
| **Governance & Compliance** | Ownership Center, access reviews, PIM overprivilege, NIST/CIS/ISO evidence |

---

## Why we win

### 1. The Unified Identity Graph is the patent

```
Most products see:   User → Role → Resource
AuditGraph sees:     Human → SPN → MI → AI Agent → Model → Dataset
```

No competitor surfaces the full chain in one graph today. Patent provisional filed 2026-06-09.

### 2. Architecture-derived means agentless + write-free

70% of cloud tenants don't turn on the logs CIEM / AI security tools depend on. AuditGraph reads what's already there: role assignments, federated identity credentials, Cognitive Services accounts, RBAC scopes, OAuth consents. **Read-only by design.** No customer ever has to grant write access. No agent ever runs inside their tenant.

### 3. CI/CD → SPN → Data chain is detectable

A new class of risk signals catches the "GitHub Actions OIDC subject too permissive" / "Terraform Cloud workspace identity holds Subscription Owner" patterns that every CISO is asking about but no existing product flags. CVSS-aligned scoring, NIST-mapped, MITRE-mapped.

### 4. Scope-aware engines, not duplicated code

One Trust engine (9 dimensions) powers Human / NHI / AI Trust scoring via a single `?type=` parameter. One Lifecycle engine powers Human / NHI / AI JML. One Attack Paths engine recognises CI/CD, NHI, AI, and human source types. **Zero feature duplication, three first-class views.**

---

## Pricing model

Per monitored subscription, today. Per monitored identity, after first signed pilot.

| Plan | What you get |
|---|---|
| **Free** | 500 identities, 2 subscriptions, community support, no expiry |
| **Trial** | Unlimited identities, unlimited subscriptions, full platform, 30 days, no credit card |
| **Pilot** | Custom — per signed pilot contract |
| **Enterprise** | Per-subscription rate ($69/mo today) or per-identity-monitored (priced after first customer logo) |

---

## What we DON'T claim

Honesty is a differentiator. Today AuditGraph:

- **Azure-only.** AWS extension Q4 2026. GCP H1 2027. Multi-cloud in collateral = liar's poker; we don't play.
- **No runtime telemetry.** We surface posture from architecture. Runtime AI prompt injection detection is partner-integrated (Lakera, NeMo, Bedrock Guardrails, Azure Content Filter).
- **Read-only.** We never write to your tenant. If you want a remediation applied, AuditGraph emits the Azure CLI snippet — you run it.

---

## Proof points the demo always shows

1. **Open `/whats-new`** — every patent-track moat in one page
2. **Click `/unified-graph`** — the unified Human → NHI → AI → Model → Data chain
3. **Click `/nhi`** — the SailPoint-killer numbers screen for NHIs
4. **Click `/attack-paths?source_type=cicd`** — the GitHub Actions → SPN → Storage → PHI chain
5. **Click `/identity-trust?type=nhi`** — 9-dim NHI Trust Score
6. **Open Argus** (front-and-center on every page) — natural-language Q&A across the entire graph

---

## The one sentence

> **AuditGraph is the Identity Security Graph platform that unifies human, non-human, and AI identities into a single graph and continuously measures exposure, trust, ownership, and attack paths across the enterprise — agentless, read-only, architecture-derived.**

That sentence does not exist for any other product in the market today.

---

*Last updated: 2026-06-10. Provisional patent claim filed 2026-06-09. Customer pilots Azure-only through Q4 2026.*
