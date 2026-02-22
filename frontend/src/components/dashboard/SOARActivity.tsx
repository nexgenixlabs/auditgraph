import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../../contexts/ConnectionContext';

interface SoarAction {
  id: number;
  playbook_name: string;
  action_type: string;
  integration: string;
  status: string;
  identity_id: string | null;
  created_at: string | null;
}

interface SoarStats {
  total: number;
  success_count: number;
  failed_count: number;
  recent_24h: number;
  success_rate: number;
}

const INTEGRATION_BADGES: Record<string, { label: string; color: string; bg: string }> = {
  slack: { label: 'Slack', color: 'text-purple-700', bg: 'bg-purple-50' },
  teams: { label: 'Teams', color: 'text-blue-700', bg: 'bg-blue-50' },
  pagerduty: { label: 'PagerDuty', color: 'text-green-700', bg: 'bg-green-50' },
  servicenow: { label: 'ServiceNow', color: 'text-teal-700', bg: 'bg-teal-50' },
  jira: { label: 'Jira', color: 'text-indigo-700', bg: 'bg-indigo-50' },
  custom_webhook: { label: 'Webhook', color: 'text-orange-700', bg: 'bg-orange-50' },
  internal: { label: 'Internal', color: 'text-gray-700', bg: 'bg-gray-100' },
};

const STATUS_DOT: Record<string, string> = {
  success: 'bg-green-500',
  failed: 'bg-red-500',
  executing: 'bg-yellow-500 animate-pulse',
  pending: 'bg-gray-400',
};

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default function SOARActivity() {
  const navigate = useNavigate();
  const { withConnection, selectedConnectionId } = useConnection();
  const [actions, setActions] = useState<SoarAction[]>([]);
  const [stats, setStats] = useState<SoarStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [actionsRes, statsRes] = await Promise.all([
          fetch(withConnection('/api/soar/actions?limit=6')),
          fetch(withConnection('/api/soar/actions/stats')),
        ]);
        if (actionsRes.ok) {
          const d = await actionsRes.json();
          setActions(d.actions || []);
        }
        if (statsRes.ok) {
          setStats(await statsRes.json());
        }
      } catch { /* ignore */ }
      finally { setLoading(false); }
    }
    load();
  }, [selectedConnectionId]);

  if (loading) {
    return (
      <div className="bg-white border rounded-xl p-5 animate-pulse">
        <div className="h-4 bg-gray-200 rounded w-32 mb-3" />
        <div className="space-y-2">
          <div className="h-3 bg-gray-100 rounded w-full" />
          <div className="h-3 bg-gray-100 rounded w-3/4" />
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white border rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-gray-900">SOAR Activity</h3>
        {stats && (
          <div className="flex items-center gap-2 text-[10px]">
            <button onClick={() => navigate('/settings#soar')} className="px-1.5 py-0.5 rounded bg-green-50 text-green-700 font-medium hover:bg-green-100 transition cursor-pointer">
              {stats.success_count} ok
            </button>
            {stats.failed_count > 0 && (
              <button onClick={() => navigate('/settings#soar')} className="px-1.5 py-0.5 rounded bg-red-50 text-red-700 font-medium hover:bg-red-100 transition cursor-pointer">
                {stats.failed_count} fail
              </button>
            )}
            <button onClick={() => navigate('/activity?type=soar')} className="text-gray-400 hover:text-gray-600 transition cursor-pointer">{stats.recent_24h} / 24h</button>
          </div>
        )}
      </div>

      {actions.length === 0 ? (
        <div className="text-xs text-gray-400 text-center py-4">
          No SOAR actions yet. Configure playbooks in Settings.
        </div>
      ) : (
        <div className="space-y-2">
          {actions.map(a => {
            const badge = INTEGRATION_BADGES[a.integration] || INTEGRATION_BADGES.internal;
            return (
              <div key={a.id} onClick={() => a.identity_id ? navigate(`/identities/${a.identity_id}`) : navigate('/activity?type=soar')} className="flex items-center gap-2 text-xs cursor-pointer hover:bg-gray-50 rounded -mx-1 px-1 transition">
                <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${STATUS_DOT[a.status] || 'bg-gray-400'}`} />
                <span className={`px-1.5 py-0.5 rounded font-medium flex-shrink-0 ${badge.bg} ${badge.color}`}>
                  {badge.label}
                </span>
                <span className="text-gray-700 truncate flex-1">{a.playbook_name || 'Unknown'}</span>
                <span className="text-gray-400 flex-shrink-0">
                  {a.created_at ? timeAgo(a.created_at) : '-'}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
