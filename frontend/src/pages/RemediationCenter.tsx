import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { shouldShowRemediation } from '../utils/displayHelpers';
import { SnapshotContextHeader } from '../components/ui/SnapshotContextHeader';

// ─── Theme constants ───
const R = {
  surface: 'var(--bg-secondary)',
  surfaceBorder: 'var(--border-default)',
  text: 'var(--text-primary)',
  textSecondary: 'var(--text-secondary)',
  textMuted: 'var(--text-tertiary)',
  accent: '#8B5CF6',
  status: {
    new: '#FF6D00', planned: '#42A5F5', in_progress: '#FFB300',
    verified: '#4ADE80', closed: '#94A3B8',
  } as Record<string, string>,
  priority: { critical: '#FF1744', high: '#FF6D00', medium: '#FFB300', low: '#4ADE80' } as Record<string, string>,
};

interface RemediationAction {
  id: number;
  title: string;
  description: string;
  risk_reduction: number;
  affected_count: number;
  blast_radius: string;
  automation_ready: boolean;
  confidence: number;
  status: string;
  priority: string;
  identity_id?: string;
  identity_name?: string;
  playbook_id?: number;
  playbook_name?: string;
  created_at?: string;
}

interface RemediationStats {
  open: number;
  critical: number;
  in_progress: number;
  completed_this_week: number;
}

interface PlaybookRef {
  id: number;
  name: string;
  trigger_type: string;
  enabled: boolean;
}

const STATUS_OPTIONS = ['all', 'new', 'planned', 'in_progress', 'verified', 'closed'];
const PRIORITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low'];

export default function RemediationCenter() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { withConnection } = useConnection();

  const [stats, setStats] = useState<RemediationStats>({ open: 0, critical: 0, in_progress: 0, completed_this_week: 0 });
  const [actions, setActions] = useState<RemediationAction[]>([]);
  const [playbooks, setPlaybooks] = useState<PlaybookRef[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || 'all');
  const [priorityFilter, setPriorityFilter] = useState(searchParams.get('priority') || 'all');
  const [selectedAction, setSelectedAction] = useState<RemediationAction | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [soarRes, playbookRes] = await Promise.all([
        fetch(withConnection('/api/soar/actions/stats')),
        fetch(withConnection('/api/soar/playbooks')),
      ]);
      const soarStats = soarRes.ok ? await soarRes.json() : {};
      const pbData = playbookRes.ok ? await playbookRes.json() : {};

      // Derive stats from SOAR actions — API returns flat counts, not nested by_status
      setStats({
        open: soarStats.total || 0,
        critical: soarStats.failed_count || 0,
        in_progress: soarStats.pending_count || 0,
        completed_this_week: soarStats.success_count || 0,
      });

      setPlaybooks((pbData.playbooks || []).map((p: any) => ({
        id: p.id, name: p.name, trigger_type: p.trigger_type, enabled: p.enabled,
      })));

      // Fetch actions list
      const actionsRes = await fetch(withConnection('/api/soar/actions?limit=100'));
      if (actionsRes.ok) {
        const ad = await actionsRes.json();
        setActions((ad.actions || []).map((a: any, idx: number) => ({
          id: a.id || idx,
          title: a.action_type || 'Remediation Action',
          description: a.details || '',
          risk_reduction: a.risk_reduction || 0,
          affected_count: a.affected_count || 1,
          blast_radius: a.blast_radius || 'unknown',
          automation_ready: a.automation_ready ?? false,
          confidence: a.confidence || 0,
          status: a.status || 'new',
          priority: a.priority || 'medium',
          identity_id: a.identity_id,
          identity_name: a.identity_name,
          playbook_id: a.playbook_id,
          playbook_name: a.playbook_name,
          created_at: a.created_at,
        })));
      }
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  }, [withConnection]);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Sync filter from URL
  useEffect(() => {
    const s = searchParams.get('status');
    if (s && STATUS_OPTIONS.includes(s)) setStatusFilter(s);
  }, [searchParams]);

  const filtered = actions.filter(a => {
    // Hide items with 0% confidence AND 0 risk reduction
    if (!shouldShowRemediation({ confidence: a.confidence, riskReduction: a.risk_reduction })) return false;
    if (statusFilter !== 'all' && a.status !== statusFilter) return false;
    if (priorityFilter !== 'all' && a.priority !== priorityFilter) return false;
    return true;
  });

  const summaryCards: { label: string; value: number; color: string; filterVal: string }[] = [
    { label: 'Open Remediations', value: stats.open, color: '#42A5F5', filterVal: 'new' },
    { label: 'Critical Priority', value: stats.critical, color: '#FF1744', filterVal: 'critical' },
    { label: 'In Progress', value: stats.in_progress, color: '#FFB300', filterVal: 'in_progress' },
    { label: 'Completed This Week', value: stats.completed_this_week, color: '#4ADE80', filterVal: 'closed' },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-4">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold" style={{ color: R.text }}>Remediation Center</h2>
        <p className="text-sm mt-1" style={{ color: R.textSecondary }}>
          Prioritized remediation actions with risk reduction scoring and automation readiness
        </p>
        <SnapshotContextHeader />
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {summaryCards.map(card => (
          <button
            key={card.label}
            onClick={() => setStatusFilter(card.filterVal)}
            className="rounded-xl border p-5 text-left transition hover:shadow-md cursor-pointer"
            style={{ backgroundColor: R.surface, borderColor: R.surfaceBorder }}
          >
            <p className="text-xs font-medium uppercase tracking-wider" style={{ color: R.textMuted }}>
              {card.label}
            </p>
            <p className="text-3xl font-bold mt-2" style={{ color: card.color }}>
              {loading ? '—' : card.value.toLocaleString()}
            </p>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-medium" style={{ color: R.textMuted }}>Status:</span>
          {STATUS_OPTIONS.map(s => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                statusFilter === s
                  ? 'text-white'
                  : 'border text-gray-600 dark:text-slate-300 hover:bg-gray-100 dark:hover:bg-slate-800'
              }`}
              style={statusFilter === s ? {
                backgroundColor: s === 'all' ? '#64748B' : (R.status[s] || '#64748B'),
              } : { borderColor: R.surfaceBorder }}
            >
              {s === 'all' ? 'All' : s.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-medium" style={{ color: R.textMuted }}>Priority:</span>
          {PRIORITY_OPTIONS.map(p => (
            <button
              key={p}
              onClick={() => setPriorityFilter(p)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                priorityFilter === p
                  ? 'text-white'
                  : 'border text-gray-600 dark:text-slate-300 hover:bg-gray-100 dark:hover:bg-slate-800'
              }`}
              style={priorityFilter === p ? {
                backgroundColor: p === 'all' ? '#64748B' : (R.priority[p] || '#64748B'),
              } : { borderColor: R.surfaceBorder }}
            >
              {p === 'all' ? 'All' : p.charAt(0).toUpperCase() + p.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Main content: table + optional detail panel */}
      <div className="flex gap-4">
        {/* Table */}
        <div className={`flex-1 min-w-0 rounded-xl border overflow-hidden ${selectedAction ? 'max-w-[calc(100%-420px)]' : ''}`}
          style={{ backgroundColor: R.surface, borderColor: R.surfaceBorder }}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b" style={{ borderColor: R.surfaceBorder }}>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Action</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Risk Reduction</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Affected</th>
                  <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Blast Radius</th>
                  <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Automation</th>
                  <th className="px-4 py-3 text-right text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Confidence</th>
                  <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider" style={{ color: R.textMuted }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={7} className="px-4 py-12 text-center" style={{ color: R.textMuted }}>
                    <div className="animate-spin h-6 w-6 border-2 border-blue-600 border-t-transparent rounded-full mx-auto" />
                  </td></tr>
                ) : filtered.length === 0 ? (
                  <tr><td colSpan={7} className="px-4 py-12 text-center" style={{ color: R.textMuted }}>No remediation actions found</td></tr>
                ) : filtered.map(a => (
                  <tr
                    key={a.id}
                    onClick={() => setSelectedAction(a)}
                    className="border-b cursor-pointer transition-colors hover:bg-gray-50 dark:hover:bg-slate-800/50"
                    style={{ borderColor: R.surfaceBorder }}
                  >
                    <td className="px-4 py-3">
                      <div className="font-medium" style={{ color: R.text }}>{a.title}</div>
                      {a.identity_name && (
                        <div className="text-xs mt-0.5" style={{ color: R.textMuted }}>{a.identity_name}</div>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right font-mono font-bold" style={{ color: '#4ADE80' }}>
                      +{a.risk_reduction} pts
                    </td>
                    <td className="px-4 py-3 text-right font-mono" style={{ color: R.text }}>
                      {a.affected_count}
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className="px-2 py-0.5 rounded-full text-xs font-medium" style={{
                        backgroundColor: a.blast_radius === 'high' ? 'rgba(255,23,68,0.12)' : a.blast_radius === 'medium' ? 'rgba(255,179,0,0.12)' : 'rgba(74,222,128,0.12)',
                        color: a.blast_radius === 'high' ? '#FF1744' : a.blast_radius === 'medium' ? '#FFB300' : '#4ADE80',
                      }}>
                        {a.blast_radius}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      {a.automation_ready ? (
                        <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">Ready</span>
                      ) : (
                        <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-500 dark:bg-slate-700 dark:text-slate-400">Manual</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right font-mono" style={{ color: a.confidence === 0 ? 'var(--text-muted)' : a.confidence >= 80 ? '#4ADE80' : a.confidence >= 60 ? '#FFB300' : '#FF6D00' }}>
                      {a.confidence}%
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className="px-2 py-0.5 rounded-full text-xs font-medium" style={{
                        backgroundColor: `${R.status[a.status] || '#64748B'}20`,
                        color: R.status[a.status] || '#64748B',
                      }}>
                        {a.status.replace('_', ' ')}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detail Panel */}
        {selectedAction && (
          <div className="w-[400px] flex-shrink-0 rounded-xl border overflow-y-auto" style={{
            backgroundColor: R.surface, borderColor: R.surfaceBorder, maxHeight: 'calc(100vh - 240px)',
          }}>
            <div className="p-5 space-y-5">
              {/* Header */}
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="font-bold text-lg" style={{ color: R.text }}>{selectedAction.title}</h3>
                  {selectedAction.playbook_name && (
                    <p className="text-xs mt-1" style={{ color: R.textMuted }}>Playbook: {selectedAction.playbook_name}</p>
                  )}
                </div>
                <button onClick={() => setSelectedAction(null)} className="p-1 rounded hover:bg-gray-100 dark:hover:bg-slate-800">
                  <svg className="w-4 h-4" style={{ color: R.textMuted }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              {/* Description */}
              {selectedAction.description && (
                <p className="text-sm" style={{ color: R.textSecondary }}>{selectedAction.description}</p>
              )}

              {/* Metrics */}
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg p-3 border" style={{ borderColor: R.surfaceBorder }}>
                  <p className="text-[10px] uppercase tracking-wider" style={{ color: R.textMuted }}>Risk Reduction</p>
                  <p className="text-xl font-bold" style={{ color: '#4ADE80' }}>+{selectedAction.risk_reduction} pts</p>
                </div>
                <div className="rounded-lg p-3 border" style={{ borderColor: R.surfaceBorder }}>
                  <p className="text-[10px] uppercase tracking-wider" style={{ color: R.textMuted }}>Confidence</p>
                  <p className="text-xl font-bold" style={{ color: selectedAction.confidence >= 80 ? '#4ADE80' : '#FFB300' }}>{selectedAction.confidence}%</p>
                </div>
                <div className="rounded-lg p-3 border" style={{ borderColor: R.surfaceBorder }}>
                  <p className="text-[10px] uppercase tracking-wider" style={{ color: R.textMuted }}>Affected</p>
                  <p className="text-xl font-bold" style={{ color: R.text }}>{selectedAction.affected_count}</p>
                </div>
                <div className="rounded-lg p-3 border" style={{ borderColor: R.surfaceBorder }}>
                  <p className="text-[10px] uppercase tracking-wider" style={{ color: R.textMuted }}>Status</p>
                  <p className="text-sm font-bold" style={{ color: R.status[selectedAction.status] || '#64748B' }}>
                    {selectedAction.status.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())}
                  </p>
                </div>
              </div>

              {/* Identity link */}
              {selectedAction.identity_id && (
                <button
                  onClick={() => navigate(`/identities/${selectedAction.identity_id}`)}
                  className="w-full px-4 py-2.5 rounded-lg border text-sm font-medium transition hover:shadow-sm"
                  style={{ borderColor: R.surfaceBorder, color: R.accent }}
                >
                  View Identity Detail
                </button>
              )}

              {/* Action buttons */}
              <div className="flex gap-2">
                <button
                  className="flex-1 px-4 py-2 rounded-lg text-xs font-medium text-white transition"
                  style={{ backgroundColor: R.accent }}
                >
                  Create Ticket
                </button>
                <button
                  className="flex-1 px-4 py-2 rounded-lg text-xs font-medium border transition hover:bg-gray-50 dark:hover:bg-slate-800"
                  style={{ borderColor: R.surfaceBorder, color: R.text }}
                >
                  Preview Changes
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Playbooks reference */}
      {playbooks.length > 0 && (
        <div className="rounded-xl border p-5" style={{ backgroundColor: R.surface, borderColor: R.surfaceBorder }}>
          <h3 className="text-sm font-semibold mb-3" style={{ color: R.text }}>Available Playbooks</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {playbooks.map(pb => (
              <div key={pb.id} className="rounded-lg border px-4 py-3 flex items-center justify-between" style={{ borderColor: R.surfaceBorder }}>
                <div>
                  <p className="text-sm font-medium" style={{ color: R.text }}>{pb.name}</p>
                  <p className="text-xs" style={{ color: R.textMuted }}>{pb.trigger_type}</p>
                </div>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${
                  pb.enabled ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300' : 'bg-gray-100 text-gray-500 dark:bg-slate-700 dark:text-slate-400'
                }`}>
                  {pb.enabled ? 'Active' : 'Disabled'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
