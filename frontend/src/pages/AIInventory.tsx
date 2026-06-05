/**
 * AI Inventory — pillar entry point for "who/what AI exists in my environment?"
 *
 * Combines two existing views into one pillar with sub-tabs:
 *   - Graph   → AIIdentityGraph (visual)
 *   - Agents  → AIAgentsStandalone (table + stats)
 *
 * Replaces the prior standalone /ai-identity-graph and /ai-agents routes
 * (those are now legacy redirects in App.tsx).
 */
import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import AIIdentityGraph from './AIIdentityGraph';
import AIAgentsStandalone from './AIAgentsStandalone';

type TabKey = 'graph' | 'agents';

const TABS: Array<{ key: TabKey; label: string; description: string }> = [
  { key: 'graph',  label: 'Graph',  description: 'Visual relationship map of AI identities and what they touch' },
  { key: 'agents', label: 'Agents', description: 'Full table of AI agent identities with risk scoring' },
];

export default function AIInventory() {
  const { tab } = useParams<{ tab?: string }>();
  const navigate = useNavigate();
  const activeTab: TabKey = (tab === 'agents' ? 'agents' : 'graph');
  const activeMeta = TABS.find(t => t.key === activeTab)!;

  return (
    <div className="space-y-4">
      {/* Pillar header */}
      <div className="px-1">
        <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>AI Inventory</h1>
        <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
          Who and what AI exists in your environment — discovery + relationships.
        </p>
      </div>

      {/* Tab strip */}
      <div className="flex items-end border-b" style={{ borderColor: 'var(--border-default)' }}>
        <div className="flex gap-1">
          {TABS.map(t => {
            const active = t.key === activeTab;
            return (
              <button
                key={t.key}
                onClick={() => navigate(`/ai-inventory/${t.key}`, { replace: true })}
                className="px-4 py-2.5 text-xs font-semibold transition border-b-2"
                style={{
                  color: active ? 'var(--text-primary)' : 'var(--text-tertiary)',
                  borderBottomColor: active ? '#24A2A1' : 'transparent',
                  backgroundColor: active ? 'var(--bg-hover)' : 'transparent',
                }}
              >
                {t.label}
              </button>
            );
          })}
        </div>
        <div className="ml-auto px-2 pb-2 text-[11px]" style={{ color: 'var(--text-tertiary)' }}>
          {activeMeta.description}
        </div>
      </div>

      {/* Active view */}
      <div>
        {activeTab === 'graph'  && <AIIdentityGraph />}
        {activeTab === 'agents' && <AIAgentsStandalone />}
      </div>
    </div>
  );
}
