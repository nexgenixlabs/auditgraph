"""AG-180/181/182: AI Identity Attack Graph engines (Tier 2 + Tier 3).

This package contains the per-AI-agent reasoning engines that turn the
identity graph into the four CISO claims:
  - data reachability (Tier 2A) — which classifications can this agent reach
  - lifecycle drift (Tier 2C) — what changed in this agent's posture
  - behavior baseline (Tier 3A) — what is this agent normally doing

Each engine reads from the agent_classifications + role_assignments graph
and writes into its dedicated persisted table. All engines respect the
no-log-dependency moat: derive from architecture, not telemetry — except
the activity timeline engine, which ingests Azure Monitor metrics when
available and degrades to architecture-only when not.
"""
