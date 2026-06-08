# Screen Walkthrough — AI Model Registry

**Route**: `/ai-runtime/model-registry` · **Section**: AI Security · **Audience**: AI governance leads, security architects, compliance teams

## What this screen answers

> *"Which AI models are deployed in my tenant, who approved them, and which ones are still unvetted?"*

The Model Registry is the system of record for AI model approvals. Every model deployment AuditGraph discovers gets a status — unverified, pending review, approved, rejected, or revoked. The screen shows the full inventory and supports the approval workflow.

## What you see on screen

### Top — summary card

A single sentence: *"N of M deployments use unapproved models."* This is the headline you put in front of an auditor.

### Filter chips

- Status: all · unverified · pending_review · approved · rejected · revoked
- Classification: baseline · medium · high · custom · finetune

Filters compose (e.g., `pending_review` + `finetune` = "which fine-tuned models are waiting for review?").

### Body — model table

Rows are unique `(model_name, model_format, model_version)` tuples. Columns:

| Column | Source | Use |
|---|---|---|
| Model | model_name + format + version | Identification |
| Classification | classifier output | Risk hint (baseline OpenAI vs custom fine-tune) |
| Deployments | count of agents using this model | Blast radius if revoked |
| Status | enum | Approval state |
| Reviewed by | user | Audit trail |
| Reviewed at | timestamp | Audit trail |

Click any row to open the **Review Modal**.

### Review Modal

For an `unverified` model: shows *Submit for Review*. The first reviewer (admin / security_admin / auditor) enters their reasoning and the model moves to `pending_review`.

For a `pending_review` model: shows *Approve* / *Reject* with a reason field. Decision is recorded; the model moves to `approved` or `rejected`. Once recorded, the decision is immutable (you can revoke later but not silently edit history).

For an `approved` model: shows *Revoke* with a reason. Revoking sets status to `revoked` and triggers an alert on any deployment still using it.

## Classification logic

When a model is discovered, the classifier assigns one of five classifications:

| Class | Heuristic |
|---|---|
| `baseline` | Recognized vendor model with no suffix (e.g., `gpt-4o`, `claude-3-5-sonnet`) |
| `medium` | Pinned version of a vendor model (e.g., `gpt-4o-2024-08-06`) |
| `high` | Preview or non-GA model (e.g., `gpt-4o-preview`) |
| `custom` | Customer-built model not from a known vendor |
| `finetune` | Fine-tuned variant (matches patterns like `-ft-`, `:ft:`, `custom-corp`) |

The classifier is deterministic — same name always gets same class. Operators can override via a per-tenant rule.

## Approval workflow

A typical organization's workflow:

1. **Discovery** — every snapshot scans deployed models. New models land as `unverified`.
2. **Triage** — an AI governance team member submits each new model for review with their assessment.
3. **Review** — a senior reviewer approves or rejects with reasoning.
4. **Production** — approved models are deployable. Findings catalog flags any deployment of an `unverified` or `rejected` model as a HIGH severity issue.
5. **Revocation** — if a model is found to have policy violations (e.g., training data provenance issue), revoke it. The Findings catalog then flags every active deployment.

The approval state is enforced at the platform level via the **Findings catalog** detector `ai_unapproved_model_in_use` — every active deployment of a non-approved model becomes a HIGH finding requiring triage.

## What gets discovered

The discovery pipeline detects models from:

- **Azure OpenAI deployments** — `Microsoft.CognitiveServices/accounts/deployments`
- **Azure AI Foundry / AI Studio** — registered models
- **AWS Bedrock** — `foundationModels` + `customModels`
- **GitHub Copilot / Copilot Studio** — declared models
- **Customer declarations** — for self-hosted models (e.g., a LLaMA running in your AKS cluster), declare via the API

Each discovered model row carries source attribution so auditors can trace where it came from.

## Common questions

**Q: How do I bulk-approve a set of baseline OpenAI models?**
The platform doesn't bulk-approve — each model gets an individual decision for audit trail integrity. But classifications can auto-suggest decisions (e.g., the UI defaults `baseline` to "approve" when you open the review modal — you still confirm).

**Q: Can I import a list of pre-approved models?**
Yes — there's an API endpoint that accepts a CSV of (model_name, format, version, status). Useful when onboarding a tenant that already has its own approval list.

**Q: What's the difference between rejected and revoked?**
Rejected = a model that was never deployed (decision happened during review). Revoked = a model that was previously approved but is now disallowed. Revocation triggers active-deployment findings; rejection does not.

**Q: Does this integrate with my MLOps platform?**
There's a generic webhook for model status changes. Customers wire this to their MLOps platform to gate deployment (e.g., the deployment pipeline checks `GET /api/ai-security/model-registry/<name>/<version>` and refuses to deploy if status ≠ approved).

## What to do next

1. Filter to `unverified`. Triage the queue. Submit each model with your assessment.
2. Review the `pending_review` queue. Approve or reject with reasoning.
3. Subscribe (via webhook) to the Model Registry events so your MLOps gate is in sync.
4. Schedule a quarterly recertification — set `expires_at` on approved models so they re-enter review automatically.

## Related screens

- [AI Findings](#screen-ai-findings) — `ai_unapproved_model_in_use` detector lives here
- [AI Supply Chain](#screen-ai-supply-chain) — fine-tuned models appear here too with their dependency tree
