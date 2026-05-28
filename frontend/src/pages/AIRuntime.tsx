/**
 * AI Runtime — pillar placeholder. Will surface where AI workloads execute
 * (AKS pods, inference containers, GPU node pools) and whether they're observable.
 */
import React from 'react';
import ComingSoonPage from '../components/ComingSoonPage';

export default function AIRuntime() {
  return (
    <ComingSoonPage
      pillar="AI Runtime"
      tagline="Where AI workloads execute and whether they are observable."
      overview="AI Runtime maps the infrastructure layer your AI agents actually run on — AKS namespaces, inference containers, GPU node pools, App Service plans, and Function App scopes — and correlates them with the managed identities, secrets, and network policies that govern them. Today AuditGraph tells you which AI identity exists; AI Runtime will tell you where it executes, what's mounted into it, and whether its telemetry is reaching your SIEM."
      capabilities={[
        { title: 'AKS workload-identity discovery', description: 'Pod → ServiceAccount → managed identity → cloud RBAC chain, surfaced for every namespace running AI containers.' },
        { title: 'Inference container inventory', description: 'Detect Azure OpenAI, Foundry, and self-hosted inference endpoints; flag privileged or unrestricted ones.' },
        { title: 'GPU workload mapping', description: 'Identify GPU-backed nodes and the workloads / identities scheduled onto them.' },
        { title: 'Telemetry coverage check', description: 'For each AI workload, confirm whether diagnostic logs and metrics are reaching Log Analytics / SIEM.' },
        { title: 'Runtime security findings', description: 'Privileged containers, unrestricted egress, missing network policy, mounted secrets, exposed APIs.' },
      ]}
      targetWindow="MVP-2 (next sprint)"
      roadmapRef="Phase 3 — AI Runtime Security"
    />
  );
}
