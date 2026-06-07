# Screen Walkthrough — Ownership Center

**Route**: `/ownership` · **Section**: Identity Security · **Audience**: Identity governance leads, security architects, GRC

## What this screen answers

> *"Which non-human identities have no human owner — and what's my workflow to assign them?"*

Ownership Center is the governance hook. Most enterprises start with 90-99% of NHIs unowned. Unowned NHIs are the #1 indicator that an incident response will stall (nobody to call, nobody authorized to revoke). This screen lists the unowned identities risk-sorted, and provides a one-click assign-owner workflow with re-certification scheduling.

## What you see on screen

### Top — headline card

Either red (problems) or green (clear), framed as a sentence:

> *"132 of 133 non-human identities have no human owner (99% unowned)."*

The numerator is `total_nhi - active_assignments`. This is the metric a board member or auditor will ask about first.

### Summary strip (4 cards)

| Card | What |
|---|---|
| Owned NHIs | Active assignments count + percentage |
| Unowned NHIs | Count + percentage |
| Expiring 30 days | Assignments with `expires_at` within 30 days (re-cert needed) |
| Active exceptions | Assignments in `exception` status (e.g., owner unavailable, under review) |

### Tabs: Unowned | Assigned

#### Unowned tab

The triage queue. Sorted by risk DESC (critical agents at top). Per-row:

- Identity name + identity_id
- Identity category (Service Principal / Managed Identity (system) / Managed Identity (user))
- AI badge (if classified as AI agent)
- Risk dot + score
- **Assign owner** button (right side)

#### Assigned tab

The current assignment registry. Per-row:

- Identity name
- Owner name + email
- Delegate (optional)
- Status (active / pending_review / exception / revoked)
- Expires at

### Assign owner modal

Click Assign owner on any unowned identity → modal opens:

- Owner name (required) — primary accountable human
- Owner email (optional but recommended for notifications)
- Delegate name (optional) — secondary contact when the primary owner is unavailable
- Reason for this assignment (free text)
- Re-cert by date — defaults to 6 months from today

Click *Assign*. The current assignment (if any) is revoked (status moves to `revoked` for audit trail) and a new `active` row is inserted. This revoke-and-reinsert pattern preserves the full history of who owned this identity over time.

## The assignment lifecycle

```
                          ┌────────────────┐
                          │      none      │ <- never assigned
                          └────────┬───────┘
                                   │ assign_owner()
                                   ▼
   re-cert needed   ┌────────────────────────────────┐
       ┌───────────▶│           active              │
       │           └────────┬───────────────────────┘
       │                    │
       │                    │ owner unavailable / contested
       │                    ▼
       │           ┌────────────────────┐
       │           │     exception      │
       │           └────────┬───────────┘
       │                    │ resolved
       │                    ▼
       │      ┌─── revoke_and_reassign() ────┐
       │      ▼                              │
       │ ┌──────────┐                        │
       │ │ revoked  │   <- audit trail row   │
       │ └──────────┘                        │
       │                                     │
       └─── new active row inserted ─────────┘
```

Every transition preserves the prior row (with new status); never deleted. This produces a complete audit trail.

## How risk ordering works

Unowned identities are sorted by:

1. `risk_level` ASC (`critical` first, then `high`, `medium`, `low`)
2. `risk_score` DESC (highest within each level)

This produces the optimal triage order: the most dangerous unowned identity at the top.

## The certification workflow (Sprint 4)

Beyond assign-owner, the full SailPoint-grade workflow includes:

- **Campaigns** — schedule a quarterly re-certification batch. The Ownership Center queues every assignment expiring in the campaign window. Each assignment goes to its owner with a one-click "Confirm / Delegate / Revoke" action.
- **Manager approval** — for high-risk identities, assignments require an additional approval from the owner's manager (looked up via HR system).
- **Exception requests** — when an identity can't be owned (e.g., a Microsoft-built-in system identity), file an exception with justification. Exceptions have an expiration date and re-emerge for review.

The schema for campaigns and exceptions is already in place (`nhi_certification_campaigns`, `nhi_certification_items`). The UI for campaign builder is on the Sprint 4 roadmap.

## Common questions

**Q: What counts as "ownership"?**
A named human who: (a) understands what the NHI does, (b) accepts responsibility for its privileges, (c) is reachable for incident response or change approval. Ownership is documented in `nhi_ownership_assignments` rather than relying on cloud-provider tags (which are mutable and often incorrect).

**Q: We have an `owner` tag on every Azure resource. Doesn't that already cover it?**
Tags are unreliable for governance because: (a) they can be modified by anyone with write access, (b) they don't preserve history, (c) they don't have re-certification or expiration semantics, (d) they're not enforced consistently. Ownership Center maintains the authoritative record with audit trail.

**Q: What about humans? Do they need owners?**
Humans are typically owned by their manager (per HR), not by themselves. Ownership Center can be extended to humans (e.g., for contractor identities), but the typical use case is NHIs only.

**Q: How does this interact with Identity Trust?**
The Ownership dimension of the 9-dim Trust Score is exactly what this screen manages. When you assign an owner here, the affected agent's Trust Score recomputes on the next snapshot and the Ownership dimension flips from FAIL to PASS.

## What to do next

1. Look at the headline. If it's 95%+ unowned, that's your starting state — totally normal.
2. Sort by risk (default). Pick the top 5 critical unowned agents.
3. Assign owners for each (use the same person if appropriate, or distribute by responsibility).
4. Move down the list. Aim for 80% owned within the first month.
5. Schedule a 90-day re-cert cadence so assignments don't go stale.

## Related screens

- [Identity Trust](#screen-identity-trust) — Ownership dimension drives part of the Trust Score
- [AI Inventory](#screen-ai-inventory) — see ownership status per agent in context
