/**
 * AI Access — pillar entry point for "what can each AI touch?"
 *
 * Currently a thin rebrand wrapper over AIPermissions. Future tabs will host
 * AI Data Access and AI Tool Execution views (Phase 4 / MVP-2).
 */
import React from 'react';
import AIPermissions from './AIPermissions';

export default function AIAccess() {
  return (
    <div className="space-y-4">
      <div className="px-1">
        <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>AI Access</h1>
        <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
          What each AI agent can touch — permissions, data reachability, tool execution.
        </p>
      </div>
      <AIPermissions />
    </div>
  );
}
