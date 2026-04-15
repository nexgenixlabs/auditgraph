# AuditGraph AI Agent Governance — Pilot Demo Script

**Duration:** 20 minutes
**Audience:** CISO / VP of Security / Security Operations Lead
**Environment:** Test tenant with 4 AI agent identities (including 1 orphaned)

---

## Minute 0-2: Context Setting

**[Slide or conversation — no screen share yet]**

> "How many AI agents has your team deployed in the last year?"
>
> "Do you know which Service Principals they're running under?"
>
> "Every Copilot Studio bot, every LangChain agent, every Power Automate flow that calls Azure OpenAI — they all run under a Service Principal. When the project wraps up, does anyone revoke the SPN?"

**[Open AuditGraph dashboard — show existing AGIRS score and identity counts]**

> "This is your current identity posture. You're tracking [X] identities across [Y] subscriptions. But there's a category we haven't looked at yet."

---

## Minute 2-6: Discovery

**[Click the "AI Agents" filter pill in the Identity Explorer]**

> "AuditGraph automatically detected 4 AI agent identities in your tenant. No manual tagging — the classifier uses display name patterns, known app IDs, and API permission signals."

**[Show the agent list sorted by AGIRS score descending]**

> "Each agent gets the same risk scoring as any other identity. Platform detection tells you it's a Copilot Studio bot, or a LangChain app, or an Azure OpenAI service."
>
> "Notice this one — AGIRS 89. Let's look at why."

---

## Minute 6-10: Orphan Finding

**[Click the orphaned agent (OldBot-RetiredJan2026) to open the detail drawer]**

> "This agent was decommissioned 60 days ago. The team that built it moved on. But its Service Principal is still live in your Entra ID."

**[Point to the AI Agent Risk section in the drawer]**

> "Platform: Copilot Studio. Days inactive: 60. And here's the critical finding — IASM-AG-001: Orphaned AI Agent SPN."
>
> "It has Owner access on your production resource group. A +15 penalty has been applied to its AGIRS score."

**[Show the alert that fired — notification or email]**

> "When we detected this, your security team got an alert — in-app notification, Slack, and email. No one had to go looking for it."

---

## Minute 10-16: Blast Radius

**[Open the identity graph — click the orphaned agent node (gray/amber)]**

> "This is the AI agent in your identity graph. Gray means orphaned. If an attacker finds this SPN credential — and in a supply chain attack, they will — here's what they can reach."

**[Show the blast radius summary panel]**

> "If compromised, the attacker gains access to:"
> - "2 subscriptions"
> - "4 resource groups"
> - "1 Key Vault — that's your production secrets"
> - "3 storage accounts"

**[If delegation exists, show it]**

> "And this agent delegates to Agent B. So the combined blast radius includes everything Agent B can access too."

> "One retired chatbot. This is your blast radius."

---

## Minute 16-18: CISO Tile

**[Navigate to Executive Summary dashboard]**

> "Your CISO sees this every morning. The AI Agent Risk tile shows:"
> - "Total: 4 agent identities"
> - "Average AGIRS: ~82"
> - "Critical orphans: 1"
> - "Highest risk: OldBot-RetiredJan2026"

> "This is the conversation she needs to have with the board. Not 'we think we have some AI agents.' It's 'we have 4 agents, 1 is orphaned with production Owner access, and here's the blast radius.'"

---

## Minute 18-20: Close

> "This runs automatically every night. No manual audit. No spreadsheet."
>
> "Every new AI agent your team deploys — AuditGraph finds it within 24 hours. If they decommission it without cleaning up the SPN, you get an alert."
>
> "The feature flag controls everything. Turn it off and your dashboard looks exactly the same as before. Turn it on and you have full AI agent governance."

**[Pause for questions]**

> "What we just showed you in 20 minutes would take a security team 2-3 weeks to audit manually. And they'd have to do it again every quarter."

---

## Key Talking Points (for Q&A)

| Question | Answer |
|----------|--------|
| How does classification work? | 3-stage: known app IDs (1.0 confidence), display name regex patterns (0.6-0.95), API permission signals. Hot-reloadable pattern library. |
| What's the false positive rate? | <5% in testing. `possible_ai_agent` threshold at 0.6, `ai_agent` at 0.8. Manual reclassification available. |
| Does this work with AWS/GCP? | Azure production today. AWS and GCP stubs ready for multi-cloud expansion. |
| What about agent-to-agent chains? | Detected via requiredResourceAccess cross-references. Admin can also declare manual delegation edges. Combined blast radius is computed automatically. |
| Performance at scale? | Sub-3-second traversal tested at 1000 identity nodes. Partial indexes on agent_identity_type. |
| Can we disable it? | `FEATURE_AI_AGENT_GOVERNANCE=false` — entire module becomes invisible. Zero impact on existing features. |

---

## Pre-Demo Checklist

- [ ] Test tenant has 4 AI agent identities seeded
- [ ] OldBot-RetiredJan2026 has IASM-AG-001 finding active
- [ ] Blast radius data computed for all agents
- [ ] CISO dashboard tile showing correct numbers
- [ ] Email/Slack alert visible for orphan detection
- [ ] Feature flag set to `true` in test environment
