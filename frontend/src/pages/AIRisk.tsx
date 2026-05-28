/**
 * AI Risk — pillar placeholder. Will surface AI-aware attack paths and
 * prompt-injection / tool-abuse exposure scenarios.
 */
import React from 'react';
import ComingSoonPage from '../components/ComingSoonPage';

export default function AIRisk() {
  return (
    <ComingSoonPage
      pillar="AI Risk"
      tagline="How an attacker could exploit your AI footprint — modeled, ranked, simulated."
      overview="AI Risk extends AuditGraph's existing attack-path engine with AI-specific scenarios: secret exposure via an over-privileged Copilot, data exfiltration through an LLM-powered tool, prompt injection that triggers an automation run, and runtime escape from an inference container into the cloud control plane. Today AuditGraph models traditional privilege escalation paths; AI Risk will model the new classes of exploit that LLM-driven agents introduce."
      capabilities={[
        { title: 'AI-aware attack path classes', description: 'AI_SECRET_EXPOSURE, AI_DATA_EXFILTRATION, AI_TOOL_ABUSE, AI_RUNTIME_ESCAPE — added to the existing attack-paths engine.' },
        { title: 'Prompt-injection exposure scoring', description: 'For each AI agent, score the blast radius if its prompts were attacker-controlled, based on tools and data it can reach.' },
        { title: 'Attack simulation for AI scenarios', description: 'Dry-run "what if this Copilot were compromised" and see exactly which secrets, data, and downstream resources would be reachable.' },
        { title: 'Cross-cloud AI attack paths', description: 'Model paths that span Entra → Azure → on-prem via AI agents acting as bridges.' },
        { title: 'Findings tied to MITRE ATT&CK for AI', description: 'Every AI risk maps to one or more MITRE ATLAS techniques for defensible reporting.' },
      ]}
      targetWindow="MVP-3"
      roadmapRef="Phase 5 — AI Attack Path Intelligence"
    />
  );
}
