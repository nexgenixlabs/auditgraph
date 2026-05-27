/**
 * AIAgentsStandalone — Standalone AI Agents page accessible from AI Security nav section.
 *
 * Same data as the AI Agents tab in Identity Explorer, but full-page with
 * additional stats from /api/ai-security/stats.
 */
import React, { useState, useEffect } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { formatPlatform } from '../constants/aiRisk';
import AIAgents from './AIAgents';

interface AIStats {
  total_ai_agents: number;
  total_ai_privileged_humans: number;
  risk_distribution: Record<string, number>;
  platform_distribution: Record<string, number>;
  top_risk_agents: Array<{
    identity_id: string;
    display_name: string;
    risk_score: number;
    risk_level: string;
    detected_platform: string;
  }>;
  avg_risk_score: number;
  avg_risk_severity: string;
}

export default function AIAgentsStandalone() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [stats, setStats] = useState<AIStats | null>(null);

  useEffect(() => {
    fetch(withConnection('/api/ai-security/stats'))
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setStats(d); })
      .catch(() => {});
  }, [withConnection, selectedConnectionId]);

  return (
    <div>
      {/* Stats banner */}
      {stats && (
        <div className="px-6 pt-6 max-w-[1600px] mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-2">
            {/* Platform distribution */}
            {Object.entries(stats.platform_distribution).slice(0, 4).map(([platform, count]) => (
              <div key={platform} className="rounded-lg border p-3" style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-subtle)' }}>
                <p className="text-[10px] text-slate-500">{formatPlatform(platform)}</p>
                <p className="text-lg font-bold text-white mt-0.5">{count}</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {/* Reuse full AIAgents component */}
      <AIAgents />
    </div>
  );
}
