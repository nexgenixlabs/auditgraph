/**
 * AI Governance — pillar placeholder. Will surface policies, exceptions,
 * approval workflows, and compliance reporting for AI agents.
 */
import React from 'react';
import ComingSoonPage from '../components/ComingSoonPage';

export default function AIGovernance() {
  return (
    <ComingSoonPage
      pillar="AI Governance"
      tagline="Policies, exceptions, and audit-grade evidence for every AI agent in your tenant."
      overview="AI Governance is the policy and compliance layer above the rest of AuditGraph's AI Security pillars. It lets you encode rules like 'AI agents cannot hold Owner roles' or 'every Copilot Studio agent must have a human owner', surfaces violations against those rules, manages approved exceptions, and produces evidence packs for auditors. Today AuditGraph shows you what exists; AI Governance will tell you whether it's allowed to exist."
      capabilities={[
        { title: 'AI policy library', description: 'Pre-built and customizable rules — no Owner role on AI identities, mandatory ownership, mandatory telemetry, scoped credentials only.' },
        { title: 'Violation tracking', description: 'Continuous evaluation of every AI agent against active policies; violations flagged with severity and remediation steps.' },
        { title: 'Exception workflow', description: 'Risk-accepted exceptions with expiration, approver, and justification — fully audit-trailed.' },
        { title: 'Compliance evidence packs', description: 'One-click PDF / CSV export of AI inventory, access, attack paths, and policy compliance — ready for SOC 2, ISO, FedRAMP auditors.' },
        { title: 'Posture trending', description: 'Track AI risk posture over time; show executive-friendly improvement charts.' },
      ]}
      targetWindow="MVP-3"
      roadmapRef="Phase 6 — AI Telemetry & Governance"
    />
  );
}
