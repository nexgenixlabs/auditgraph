# AuditGraph — 30-Second Demo Script

For the rep / SE running a live screenshare. **30 seconds, four clicks, one headline.**

---

## The setup (5 seconds)

> *"Most identity products see User → Role → Resource. We see Human → Service Principal → Managed Identity → AI Agent → Model → Classified Data — all in one graph, all derived from architecture, with zero write access. Let me show you."*

→ Land on **Executive Posture** (the `/` home page).

The Unified Identity Graph promo banner is right under the Argus card. Click it.

---

## Click 1 — The patent moat (8 seconds)

`/unified-graph`

> *"This is the patent claim. Five tiers. Real counts from your tenant. No competitor surfaces this end-to-end today — SailPoint stops at humans, Astrix stops at NHIs, AI security tools stop at runtime. We bridge them all."*

Point at:
- "The Moat" callout box (Human → SPN → MI → AI → Model → Dataset)
- The tier ladder showing real numbers
- The "+N edges into the tier below" connector chips

---

## Click 2 — The SailPoint-killer (8 seconds)

Click the **"NHI subgraph"** chip in the drill-in row.

`/nhi`

> *"Every non-human identity in their tenant in one pane. Service principals, managed identities, workloads, CI/CD federated identities, AI agents — five types, hygiene gaps in the second row. This is the screen the CISO actually opens."*

Point at:
- The total NHI counter at the top
- The "By type" cards (SPNs / MIs / Workloads / AI Agents)
- The red "Hygiene gaps" row (Unowned / Dormant / Critical / Expired secrets / Federated only)

---

## Click 3 — The CI/CD chain (7 seconds)

From the NHI Inventory drill-in row, click **"Attack Paths →"**.

`/attack-paths?source_type=cicd`

> *"This is the chain every customer asks about. GitHub Actions or Terraform Cloud workspace authenticates to a service principal, which has Storage Owner, which can reach PHI. We're the only product that traces this end-to-end from the OIDC subject claim all the way to the data classification."*

Point at:
- The CI/CD source filter chip lit up
- The source_entity_type column showing managed_identity_user / service_principal
- The path chain visualization

---

## Click 4 — Argus (2 seconds)

Click **Argus** in the top bar.

> *"And if the auditor asks a question we haven't built a screen for, Argus answers it from the graph. Natural language, citations, evidence chain. Cross-cutting across human, NHI, AI, and workload."*

Type into the search bar: *"Which AI agents can reach PHI?"*

---

## The close (0 seconds remaining; one breath)

> *"Identity Security Graph for Human, Non-Human, and AI Identities. Agentless. Read-only. Architecture-derived. That's the entire pitch. Want to walk through the trial?"*

---

## What NOT to do in 30 seconds

- **Don't open Settings.** Setup is irrelevant to the wow.
- **Don't show the wizard.** Wizard is for the trial flow, not the demo.
- **Don't open Compliance Posture.** It's a polish surface, not the moat.
- **Don't say "AI security tool."** We are not. The brand sentence is "Identity Security Graph."
- **Don't promise multi-cloud** in the live demo. Azure today. AWS Q4 2026.

---

## Backup answers for the obvious questions

**"How is this different from Microsoft Entra ID Governance?"**
> *Microsoft has the identities; we have the graph that crosses them. Entra Governance is per-identity-type and per-feature. AuditGraph is the chain across types.*

**"How is this different from Astrix / Entro / Oasis (NHI security)?"**
> *They cover NHIs only and require write access for full functionality. We cover Human + NHI + AI in one graph and are 100% read-only.*

**"Do you support AWS?"**
> *Today, Azure only with depth. AWS extension Q4 2026. Multi-cloud collateral that promises everything ships nothing on time; we don't play that game.*

**"How do you handle Day-0 in an empty tenant?"**
> *Wizard collects credentials, runs first scan in ~12 minutes for ~3000 identities, surfaces the first finding inline on the scan completion modal. We don't return empty 404s on fresh tenants — every endpoint handles the no-data state explicitly with empty arrays + actionable copy.*

**"What's your patent claim?"**
> *Provisional filed 2026-06-09. A method for computing an identity-to-data exposure graph by joining role assignments across Entra Directory Roles, Azure RBAC, Microsoft Graph API permissions, OAuth consent grants, federated identity credentials, and AI model deployments — without write access, agent, or runtime telemetry.*

---

*Memorize the four clicks. Practice the 30 seconds out loud. The rep who can do this in one breath is the rep who closes the deal.*
