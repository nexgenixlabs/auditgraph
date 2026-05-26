import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';

interface RiskFinding {
  id: string;
  severity: string;
  rule_name: string;
  rule_key: string;
  rule_type: string;
  identity_id: string | null;
  identity_name: string | null;
  resource_id: string | null;
  metadata: Record<string, unknown>;
  status: string;
  detected_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
}

interface Stats {
  total: number;
  open: number;
  by_severity: Record<string, number>;
  by_rule_type: Record<string, number>;
}

interface FindingGroup {
  category: string;
  label: string;
  severity: string;
  items: RiskFinding[];
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
  info: 'bg-slate-500/20 text-slate-400 border border-slate-500/30',
};

const STATUS_BADGE: Record<string, string> = {
  open: 'bg-red-500/20 text-red-400 border border-red-500/30',
  acknowledged: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  resolved: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
};

const SEVERITY_ORDER: Record<string, number> = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

const CATEGORY_LABELS: Record<string, string> = {
  high_privilege_identity: 'High Privilege Identity',
  disabled_account_active_role: 'Ghost Identity with Active Roles',
  orphaned_spn: 'Orphaned Service Principal',
  dormant_privileged: 'Dormant Privileged Account',
  over_privileged: 'Over-Privileged Identity',
  expired_credential: 'Expired Credential',
  zombie_identity: 'Zombie Persona',
  privilege_escalation: 'Privilege Escalation Risk',
  nhi_security: 'Non-Human Identity Risk',
  dormant_identity: 'Dormant Identity',
  excessive_permissions: 'Excessive Permissions',
  credential_risk: 'Credential Risk',
};

function getCategoryLabel(ruleType: string, ruleName: string): string {
  return CATEGORY_LABELS[ruleType] || ruleName || ruleType || 'Security Finding';
}

/* ── Exposure type tabs (merged from Identity Exposures) ──────────── */

const EXPOSURE_TABS: Array<{ key: string; label: string; ruleTypes?: string[] }> = [
  { key: '', label: 'All' },
  { key: 'dormant', label: 'Dormant', ruleTypes: ['dormant_privileged_identity'] },
  { key: 'credentials', label: 'Credentials', ruleTypes: ['user_without_mfa', 'expired_credential', 'credential_risk'] },
  { key: 'external', label: 'External', ruleTypes: ['guest_admin', 'external_privileged'] },
  { key: 'unowned', label: 'Unowned', ruleTypes: ['spn_without_owner'] },
  { key: 'orphaned', label: 'Orphaned', ruleTypes: ['disabled_account_active_role'] },
  { key: 'unused', label: 'Unused', ruleTypes: ['unused_service_principal'] },
];

const SecurityFindings: React.FC = () => {
  const [searchParams] = useSearchParams();
  const { withConnection, selectedConnectionId } = useConnection();
  const { activeOrgId } = useAuth();
  const [findings, setFindings] = useState<RiskFinding[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState(searchParams.get('severity') || '');
  const [statusFilter, setStatusFilter] = useState('');
  const [groupByRule, setGroupByRule] = useState(true);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [exposureTab, setExposureTab] = useState('');

  const fetchFindings = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (severityFilter) params.set('severity', severityFilter);
      if (statusFilter) params.set('status', statusFilter);
      const res = await fetch(withConnection(`/api/security/findings?${params.toString()}`));
      if (res.ok) {
        const data = await res.json();
        setFindings(data.findings || []);
        setStats(data.stats || null);
      }
    } catch (err) {
      console.error('Failed to fetch risk findings:', err);
    } finally {
      setLoading(false);
    }
  }, [severityFilter, statusFilter, withConnection, selectedConnectionId, activeOrgId]);

  useEffect(() => { fetchFindings(); }, [fetchFindings]);

  // Auto-expand critical groups on first load
  useEffect(() => {
    if (findings.length > 0 && expandedGroups.size === 0) {
      const critGroups = new Set<string>();
      for (const f of findings) {
        if (f.severity === 'critical') critGroups.add(f.rule_type || f.rule_name);
      }
      setExpandedGroups(critGroups);
    }
  }, [findings]); // eslint-disable-line react-hooks/exhaustive-deps

  // Filter findings by selected exposure tab
  const filteredFindings = useMemo(() => {
    if (!exposureTab) return findings;
    const tab = EXPOSURE_TABS.find(t => t.key === exposureTab);
    if (!tab || !tab.ruleTypes) return findings;
    return findings.filter(f => tab.ruleTypes!.includes(f.rule_type));
  }, [findings, exposureTab]);

  // Compute counts per exposure tab
  const exposureTabCounts = useMemo(() => {
    const counts: Record<string, number> = { '': findings.length };
    for (const tab of EXPOSURE_TABS) {
      if (tab.key && tab.ruleTypes) {
        counts[tab.key] = findings.filter(f => tab.ruleTypes!.includes(f.rule_type)).length;
      }
    }
    return counts;
  }, [findings]);

  const grouped = useMemo((): FindingGroup[] => {
    const map: Record<string, FindingGroup> = {};
    for (const f of filteredFindings) {
      const key = f.rule_type || f.rule_name;
      if (!map[key]) {
        map[key] = {
          category: key,
          label: getCategoryLabel(f.rule_type, f.rule_name),
          severity: f.severity,
          items: [],
        };
      }
      map[key].items.push(f);
      // Use the highest severity in the group
      if ((SEVERITY_ORDER[f.severity] || 5) < (SEVERITY_ORDER[map[key].severity] || 5)) {
        map[key].severity = f.severity;
      }
    }
    return Object.values(map).sort((a, b) =>
      (SEVERITY_ORDER[a.severity] || 5) - (SEVERITY_ORDER[b.severity] || 5)
    );
  }, [findings]);

  const toggleGroup = (category: string) => {
    setExpandedGroups(prev => {
      const next = new Set(prev);
      if (next.has(category)) next.delete(category);
      else next.add(category);
      return next;
    });
  };

  const handleAction = async (findingId: string, action: 'acknowledge' | 'resolve') => {
    try {
      const res = await fetch(withConnection(`/api/security/findings/${findingId}/${action}`), { method: 'POST' });
      if (res.ok) fetchFindings();
    } catch (err) {
      console.error(`Failed to ${action} finding:`, err);
    }
  };

  const renderFindingRow = (f: RiskFinding) => (
    <tr key={f.id} className="hover:bg-slate-700/20">
      <td className="px-4 py-3">
        <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_BADGE[f.severity] || ''}`}>
          {f.severity}
        </span>
      </td>
      <td className="px-4 py-3">
        <div className="text-white font-medium">{f.rule_name}</div>
        <div className="text-slate-400 text-xs">{(f.metadata as Record<string, string>)?.reason || ''}</div>
        {!!(f.metadata as Record<string, unknown>)?.escalation_path && (
          <div className="mt-1 flex items-center gap-1 text-xs text-purple-400">
            <span>Path:</span>
            {((f.metadata as Record<string, unknown>).escalation_path as string[]).map((step, i, arr) => (
              <span key={i}>
                <span className="text-purple-300">{step}</span>
                {i < arr.length - 1 && <span className="text-slate-500 mx-0.5">&rarr;</span>}
              </span>
            ))}
          </div>
        )}
      </td>
      <td className="px-4 py-3 text-xs">
        {f.identity_id ? (
          <Link
            to={`/identities/${f.identity_id}`}
            className="text-blue-400 hover:text-blue-300 hover:underline font-medium"
          >
            {f.identity_name || f.identity_id}
          </Link>
        ) : (
          <span className="text-slate-500">-</span>
        )}
        {f.identity_id && f.identity_name && (
          <div className="text-slate-500 text-[10px] font-mono mt-0.5">
            {f.identity_id.substring(0, 8)}...
            <button
              onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(f.identity_id!); }}
              className="ml-1 opacity-50 hover:opacity-100"
              title="Copy full ID"
            >
              &#9112;
            </button>
          </div>
        )}
      </td>
      <td className="px-4 py-3">
        <span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_BADGE[f.status] || ''}`}>
          {f.status}
        </span>
      </td>
      <td className="px-4 py-3 text-slate-400 text-xs">
        {f.detected_at ? new Date(f.detected_at).toLocaleDateString() : '-'}
      </td>
      <td className="px-4 py-3">
        {f.status === 'open' && (
          <div className="flex gap-2">
            <button
              onClick={() => handleAction(f.id, 'acknowledge')}
              className="px-2 py-1 text-xs bg-yellow-500/20 text-yellow-400 rounded hover:bg-yellow-500/30"
            >
              Ack
            </button>
            <button
              onClick={() => handleAction(f.id, 'resolve')}
              className="px-2 py-1 text-xs bg-emerald-500/20 text-emerald-400 rounded hover:bg-emerald-500/30"
            >
              Resolve
            </button>
          </div>
        )}
        {f.status === 'acknowledged' && (
          <button
            onClick={() => handleAction(f.id, 'resolve')}
            className="px-2 py-1 text-xs bg-emerald-500/20 text-emerald-400 rounded hover:bg-emerald-500/30"
          >
            Resolve
          </button>
        )}
      </td>
    </tr>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Security Findings</h1>
        <p className="text-sm text-slate-400 mt-1">Rules-based risk detections from continuous discovery</p>
      </div>

      {/* Stat Cards */}
      {!!stats && (
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <div className="text-xs text-slate-400 uppercase tracking-wider">Total</div>
            <div className="text-2xl font-bold text-white mt-1">{stats.total}</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <div className="text-xs text-slate-400 uppercase tracking-wider">Open</div>
            <div className="text-2xl font-bold text-red-400 mt-1">{stats.open}</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <div className="text-xs text-slate-400 uppercase tracking-wider">Critical</div>
            <div className="text-2xl font-bold text-red-500 mt-1">{stats.by_severity?.critical || 0}</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <div className="text-xs text-slate-400 uppercase tracking-wider">High</div>
            <div className="text-2xl font-bold text-orange-400 mt-1">{stats.by_severity?.high || 0}</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-3 items-center">
        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value)}
          className="bg-slate-800 border border-slate-700 text-white text-sm rounded-lg px-3 py-2"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="bg-slate-800 border border-slate-700 text-white text-sm rounded-lg px-3 py-2"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
        </select>
        <button
          onClick={() => setGroupByRule(v => !v)}
          className={`px-3 py-2 text-xs font-medium rounded-lg border transition-colors ${
            groupByRule
              ? 'bg-blue-500/20 text-blue-400 border-blue-500/30'
              : 'bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700'
          }`}
        >
          Group by Rule
        </button>
      </div>

      {/* Exposure Type Tabs */}
      <div className="flex gap-1.5 flex-wrap">
        {EXPOSURE_TABS.map(tab => {
          const count = exposureTabCounts[tab.key] ?? 0;
          const isActive = exposureTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => setExposureTab(tab.key)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
                isActive
                  ? 'bg-blue-500/20 text-blue-400 border-blue-500/30'
                  : 'bg-slate-800/50 text-slate-400 border-slate-700/50 hover:bg-slate-700/50 hover:text-slate-300'
              }`}
            >
              {tab.label}
              <span className={`ml-1.5 font-mono ${isActive ? 'text-blue-400' : 'text-slate-500'}`}>
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Content */}
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-slate-400">Loading...</div>
        ) : filteredFindings.length === 0 ? (
          <div className="p-8 text-center text-slate-400">No findings match the current filters</div>
        ) : groupByRule ? (
          /* Grouped view */
          <div className="divide-y divide-slate-700/50">
            {grouped.map(group => (
              <div key={group.category}>
                <button
                  onClick={() => toggleGroup(group.category)}
                  className="w-full flex items-center justify-between px-4 py-3 hover:bg-slate-700/20 transition-colors text-left"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-slate-400 text-xs w-4">
                      {expandedGroups.has(group.category) ? '▼' : '▶'}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_BADGE[group.severity] || ''}`}>
                      {group.severity}
                    </span>
                    <span className="text-white font-medium text-sm">{group.label}</span>
                  </div>
                  <span className="text-slate-400 text-xs font-mono">
                    {group.items.length} {group.items.length === 1 ? 'finding' : 'findings'}
                  </span>
                </button>
                {expandedGroups.has(group.category) && (
                  <table className="w-full text-sm text-left">
                    <thead className="bg-slate-900/30 text-slate-500 uppercase text-xs tracking-wider">
                      <tr>
                        <th className="px-4 py-2">Severity</th>
                        <th className="px-4 py-2">Rule</th>
                        <th className="px-4 py-2">Identity</th>
                        <th className="px-4 py-2">Status</th>
                        <th className="px-4 py-2">Detected</th>
                        <th className="px-4 py-2">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/30">
                      {group.items.map(renderFindingRow)}
                    </tbody>
                  </table>
                )}
              </div>
            ))}
          </div>
        ) : (
          /* Flat table view */
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-900/50 text-slate-400 uppercase text-xs tracking-wider">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Rule</th>
                <th className="px-4 py-3">Identity</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Detected</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {filteredFindings.map(renderFindingRow)}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default SecurityFindings;
