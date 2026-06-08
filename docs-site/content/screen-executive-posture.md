# Screen Walkthrough — Executive Posture

**Route**: `/` · **Section**: Command Center · **Audience**: CISOs, CIOs, board members

## What this screen answers

> *"What is my identity security posture right now, in business-impact terms a board would understand?"*

This is the landing page. The audience is executive, not architect. Every number on this screen is paired with a sentence explaining what it means in business terms.

## What you see on screen

### Posture Hero (top section)

A narrative card stating your current posture in plain English:

> *"Your identity environment has exploitable gaps. 12 dormant privileged accounts still retain admin access. Removing them eliminates most misuse risk."*

The verdict comes from a 4-tier system: **secure / has exploitable gaps / actively exposed / faces imminent breach risk**. The verdict drives the color (green/amber/orange/red).

Below the verdict: the top 2 risk drivers with action hints (*"Assigning owners restores accountability"*).

### Business Impact section

This is where the CISO question lands. Three nested cards:

1. **Headline** — total estimated breach exposure org-wide. e.g., `$81.6M mid-band ($48.96M – $100.4M)`.
2. **AI-reachable** — subset reachable by AI agents specifically. The AI-ISPM blast radius.
3. **NHI-reachable** — subset reachable by any non-human identity (SPNs + MIs + AI).

Next to each headline: a small **ⓘ Methodology** button. Click it to see exactly how the dollar amount was derived (record count × IBM 2023 cost factor). The CISO question — *"how did you arrive at the number?"* — is answered in one click.

See [Breach Cost Methodology](#breach-cost-methodology) for the full derivation.

### Identity Composition

Shows the breakdown of identities by category:

- Human users (typically smallest count)
- Service principals
- Managed identities (system + user-assigned)
- AI agents (subset of SPNs/MIs that are AI-classified)

This signals identity sprawl. Boards intuitively understand "we have 40× more NHIs than humans" as a control problem.

### Blast Radius section

Top risk drivers expanded with counts and one-click drilldown:

- N unowned NHIs (click → Ownership Center)
- N dormant privileged accounts (click → Risk Monitoring filtered)
- N ghost identities (disabled accounts still holding live access)
- N AI agents with no human owner (click → AI Inventory filtered)

Each driver has a one-sentence business-impact framing.

### AI Identity Risk Card

AI-specific subsection:

- N AI agents with no human owner
- N AI agents at critical/high risk
- N AI-privileged humans (humans who configure AI systems)

Click any to drill into AI Inventory with the appropriate filter.

### Active Threats section

If any partner-detection signals (Lakera, Bedrock, Azure Content Filter) are active in last 24h, they appear here. Otherwise: *"No active threats detected (or no threat connectors wired)."*

### Activity & Drift section

Recent changes that affect posture:

- Drift events (e.g., a previously-owned identity became unowned)
- Anomalies (e.g., a normally-quiet agent had a surge in activity)

Click to open the relevant detail.

### Connected App Risk

For tenants using third-party SaaS via Microsoft Entra Enterprise Apps — shows apps with risky scopes (full directory access, mail-send, etc.).

### Data Integrity Footer

Quiet line at the bottom: *"Data as of <timestamp>. Snapshot #<id>."* Boards trust numbers more when freshness is shown.

## How this differs from Risk Monitoring

Executive Posture is *what posture is* (high-level, board-ready, business-impact framing).

Risk Monitoring is *what happened* (operational, SOC/IAM-ops audience, change-event framing).

The same underlying data, different summarization and audience.

## Common questions

**Q: The headline says $81.6M. How was that calculated?**
Click the ⓘ Methodology button. Full derivation: 173,432 classified records × industry cost factors from IBM Cost of a Data Breach 2023. See [Breach Cost Methodology](#breach-cost-methodology).

**Q: Why don't I see compliance scoring on this page?**
Compliance is a separate audience (auditors), and lives in Governance & Assurance. Mixing compliance with risk on the same page diluted both for early customers. Now they're separate.

**Q: Can I customize this page?**
Yes — the layout supports widget reordering and selective enable/disable per tenant. Most customers keep the default order.

**Q: Is this the page I show my board?**
Yes — designed for it. Take a screenshot directly. The Business Impact section is the "money slide."

## What to do next

1. Read the posture verdict. If it's *exploitable gaps* or worse, look at the top drivers.
2. Click the top driver to drill into the specific remediation queue.
3. Take a screenshot for the next board pack.
4. After remediation (next sprint), re-check — the verdict should improve.

## Related screens

- [Board Scorecard](#screen-board-scorecard) — even more compressed for CEO/CFO/audit committee
- [Breach Cost Methodology](#breach-cost-methodology) — where the $ comes from
- Risk Monitoring — operational view of what happened
