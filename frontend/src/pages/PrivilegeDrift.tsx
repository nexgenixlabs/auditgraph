import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useConnection } from '../contexts/ConnectionContext';
import { CLOUD_BADGE, safeLower } from '../constants/metrics';

interface DriftChange {
  identity_id: number;
  identity_name: string;
  identity_category: string;
  cloud: string;
  change_type: string;
  previous_role: string | null;
  current_role: string | null;
  is_privileged: boolean;
  severity: string;
  risk_level: string;
  timestamp: string | null;
  drift_classification: 'privilege_drift' | 'normal_drift';
}

interface DriftStats {
  role_added: number;
  role_removed: number;
  identity_added: number;
  identity_removed: number;
  risk_score_change: number;
  privileged_changes: number;
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  low: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
  info: 'bg-slate-700/50 text-slate-400 border border-slate-600/30',
};

const SEVERITY_COLORS: Record<string, { bg: string; bar: string; text: string }> = {
  critical: { bg: 'bg-red-500/20', bar: 'bg-red-500', text: 'text-red-400' },
  high:     { bg: 'bg-orange-500/20', bar: 'bg-orange-500', text: 'text-orange-400' },
  medium:   { bg: 'bg-yellow-500/20', bar: 'bg-yellow-500', text: 'text-yellow-400' },
  low:      { bg: 'bg-emerald-500/20', bar: 'bg-emerald-500', text: 'text-emerald-400' },
};

const CHANGE_CONFIG: Record<string, { label: string; icon: string; color: string }> = {
  role_added:         { label: 'Added',     icon: 'M12 6v6m0 0v6m0-6h6m-6 0H6', color: 'text-red-400' },
  role_removed:       { label: 'Removed',   icon: 'M20 12H4', color: 'text-emerald-400' },
  identity_added:     { label: 'New ID',    icon: 'M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z', color: 'text-blue-400' },
  identity_removed:   { label: 'Removed ID', icon: 'M13 7a4 4 0 11-8 0 4 4 0 018 0zM9 14a6 6 0 00-6 6v1h12v-1a6 6 0 00-6-6zM21 12h-6', color: 'text-slate-400' },
  risk_score_change:  { label: 'Risk Δ',    icon: 'M13 7h8m0 0v8m0-8l-8 8-4-4-6 6', color: 'text-orange-400' },
};

/** Derive a human-readable classification from change data */
function getDriftClassification(c: DriftChange): { label: string; severity: string } {
  const role = (c.current_role || c.previous_role || '').toLowerCase();
  if (c.change_type === 'role_added') {
    if (role.includes('owner') || role.includes('global admin')) return { label: 'Owner role added', severity: 'critical' };
    if (role.includes('contributor')) return { label: 'Contributor role added', severity: 'high' };
    if (c.is_privileged) return { label: 'Privileged access change', severity: 'medium' };
    if (role.includes('reader')) return { label: 'Reader role change', severity: 'low' };
    return { label: 'Role assigned', severity: c.severity || 'medium' };
  }
  if (c.change_type === 'role_removed') return { label: 'Role removed', severity: 'low' };
  if (c.change_type === 'identity_added') return { label: 'New identity provisioned', severity: c.severity || 'medium' };
  if (c.change_type === 'identity_removed') return { label: 'Identity deprovisioned', severity: 'low' };
  if (c.change_type === 'risk_score_change') return { label: 'Risk score changed', severity: c.severity || 'medium' };
  return { label: c.change_type, severity: c.severity || 'info' };
}

export default function PrivilegeDrift() {
  const navigate = useNavigate();
  const { activeOrgId } = useAuth();
  const { withConnection, selectedConnectionId } = useConnection();
  const [changes, setChanges] = useState<DriftChange[]>([]);
  const [stats, setStats] = useState<DriftStats | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [severityClassFilter, setSeverityClassFilter] = useState('');
  const [showAll, setShowAll] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (typeFilter) params.set('change_type', typeFilter);
      params.set('limit', '200');
      const res = await fetch(withConnection(`/api/privilege-drift?${params}`));
      if (res.ok) {
        const data = await res.json();
        setChanges(data.changes || []);
        setStats(data.stats || null);
        setTotal(data.total || 0);
        setMessage(data.message || '');
      }
    } catch { /* ignore */ }
    setLoading(false);
  }, [typeFilter, activeOrgId, withConnection, selectedConnectionId]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const privilegedCount = stats?.privileged_changes ?? 0;
  const baseChanges = showAll ? changes : changes.filter(c => c.drift_classification === 'privilege_drift');

  const displayedChanges = useMemo(() => {
    if (!severityClassFilter) return baseChanges;
    return baseChanges.filter(c => getDriftClassification(c).severity === severityClassFilter);
  }, [baseChanges, severityClassFilter]);

  const severityClassCounts = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const c of baseChanges) {
      const cls = getDriftClassification(c);
      if (cls.severity in counts) counts[cls.severity]++;
    }
    return counts;
  }, [baseChanges]);

  const totalClassified = Object.values(severityClassCounts).reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-4">
      {/* Header row: title + alert inline */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Privilege Drift</h1>
          <p className="text-xs text-slate-400 mt-0.5">Risky privilege escalations</p>
        </div>
        {privilegedCount > 0 && (
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/30">
            <svg className="w-4 h-4 text-red-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <span className="text-xs font-semibold text-red-400">
              {privilegedCount} privileged change{privilegedCount !== 1 ? 's' : ''}
            </span>
          </div>
        )}
      </div>

      {/* Stat cards row + filter toggle — compact single line */}
      <div className="flex items-center gap-2">
        {Object.entries(CHANGE_CONFIG).map(([key, cfg]) => {
          const count = stats?.[key as keyof DriftStats] ?? 0;
          return (
            <button
              key={key}
              onClick={() => setTypeFilter(typeFilter === key ? '' : key)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-lg border text-left transition ${
                typeFilter === key
                  ? 'border-indigo-500/50 bg-indigo-500/10 ring-1 ring-indigo-500/30'
                  : 'border-slate-700/50 bg-slate-800/50 hover:bg-slate-700/30'
              }`}
            >
              <svg className={`w-3.5 h-3.5 ${cfg.color}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={cfg.icon} />
              </svg>
              <span className="text-sm font-bold text-white">{count}</span>
              <span className="text-[10px] text-slate-400">{cfg.label}</span>
            </button>
          );
        })}
        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={() => setShowAll(!showAll)}
            className={`px-2.5 py-1.5 rounded-lg text-[10px] font-medium transition ${
              showAll
                ? 'bg-slate-700/50 text-slate-300 border border-slate-600/30'
                : 'bg-red-500/10 text-red-400 border border-red-500/30'
            }`}
          >
            {showAll ? 'All' : 'Escalations'}
          </button>
          <span className="text-[10px] text-slate-500">{displayedChanges.length}/{changes.length}</span>
        </div>
      </div>

      {/* Horizontal severity bar — compact inline */}
      {baseChanges.length > 0 && totalClassified > 0 && (
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-3">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-xs font-semibold text-white">Severity</span>
            {severityClassFilter && (
              <button onClick={() => setSeverityClassFilter('')} className="text-[10px] text-slate-500 hover:text-slate-300">
                Clear filter
              </button>
            )}
          </div>
          {/* Segmented bar */}
          <div className="flex h-2.5 rounded-full overflow-hidden mb-2">
            {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
              const pct = totalClassified > 0 ? (severityClassCounts[sev] / totalClassified) * 100 : 0;
              if (pct === 0) return null;
              return (
                <button
                  key={sev}
                  onClick={() => setSeverityClassFilter(severityClassFilter === sev ? '' : sev)}
                  className={`${SEVERITY_COLORS[sev].bar} transition-all ${
                    severityClassFilter && severityClassFilter !== sev ? 'opacity-30' : 'opacity-100'
                  }`}
                  style={{ width: `${pct}%` }}
                  title={`${sev}: ${severityClassCounts[sev]}`}
                />
              );
            })}
          </div>
          {/* Legend row */}
          <div className="flex items-center gap-4">
            {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
              const count = severityClassCounts[sev];
              if (count === 0) return null;
              return (
                <button
                  key={sev}
                  onClick={() => setSeverityClassFilter(severityClassFilter === sev ? '' : sev)}
                  className={`flex items-center gap-1.5 transition ${
                    severityClassFilter && severityClassFilter !== sev ? 'opacity-40' : ''
                  }`}
                >
                  <span className={`w-2 h-2 rounded-full ${SEVERITY_COLORS[sev].bar}`} />
                  <span className={`text-[10px] font-medium ${SEVERITY_COLORS[sev].text}`}>
                    {sev.charAt(0).toUpperCase() + sev.slice(1)}
                  </span>
                  <span className="text-[10px] text-slate-500">{count}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Table */}
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-10 text-center text-slate-400">Comparing snapshots...</div>
        ) : message ? (
          <div className="p-10 text-center">
            <svg className="w-8 h-8 text-slate-600 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div className="text-sm font-semibold text-slate-400">{message}</div>
          </div>
        ) : displayedChanges.length === 0 ? (
          <div className="p-10 text-center">
            <svg className="w-8 h-8 text-emerald-400 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <div className="text-sm font-semibold text-emerald-400">No Privilege Drift Detected</div>
            <div className="text-xs text-slate-500 mt-1">No role changes between the latest snapshots.</div>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-900/50 border-b border-slate-700/50 text-left text-[10px] text-slate-400 uppercase tracking-wider">
              <tr>
                <th className="px-3 py-2">Identity</th>
                <th className="px-3 py-2">Cloud</th>
                <th className="px-3 py-2">Change</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Classification</th>
                <th className="px-3 py-2">Previous</th>
                <th className="px-3 py-2">Current</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {displayedChanges.map((c, i) => {
                const cls = getDriftClassification(c);
                return (
                  <tr key={`${c.identity_id}-${c.change_type}-${i}`} className="hover:bg-slate-700/20">
                    <td className="px-3 py-2">
                      <button
                        onClick={() => navigate(`/identities/${c.identity_id}`)}
                        className="text-blue-400 hover:underline font-medium text-xs text-left"
                      >
                        {c.identity_name}
                      </button>
                      <div className="text-[9px] text-slate-500">{c.identity_category}</div>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase ${CLOUD_BADGE[safeLower(c.cloud)] || CLOUD_BADGE.azure}`}>
                        {c.cloud}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1">
                        <span className="text-[11px] font-medium text-slate-300">
                          {CHANGE_CONFIG[c.change_type]?.label || c.change_type}
                        </span>
                        {c.drift_classification === 'privilege_drift' ? (
                          <span className="px-1 py-px rounded text-[8px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">ESC</span>
                        ) : (
                          <span className="px-1 py-px rounded text-[8px] font-bold bg-slate-700/50 text-slate-500 border border-slate-600/30">NRM</span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase ${SEVERITY_BADGE[c.severity] || 'bg-slate-700/50 text-slate-400'}`}>
                        {c.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1.5">
                        <span className={`w-1.5 h-1.5 rounded-full ${SEVERITY_COLORS[cls.severity]?.bar || 'bg-slate-500'}`} />
                        <span className="text-[11px] text-slate-300">{cls.label}</span>
                      </div>
                    </td>
                    <td className="px-3 py-2 text-[11px] text-slate-400 max-w-[160px] truncate" title={c.previous_role || '\u2014'}>
                      {c.previous_role || '\u2014'}
                    </td>
                    <td className="px-3 py-2 text-[11px] text-slate-400 max-w-[160px] truncate" title={c.current_role || '\u2014'}>
                      {c.current_role || '\u2014'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="text-[10px] text-slate-500 text-right">{total} total changes</div>
    </div>
  );
}
