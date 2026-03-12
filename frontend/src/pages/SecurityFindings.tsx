import React, { useEffect, useState, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

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

const SecurityFindings: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [findings, setFindings] = useState<RiskFinding[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState(searchParams.get('severity') || '');
  const [statusFilter, setStatusFilter] = useState('');

  const fetchFindings = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (severityFilter) params.set('severity', severityFilter);
      if (statusFilter) params.set('status', statusFilter);
      const res = await fetch(`/api/security/findings?${params.toString()}`);
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
  }, [severityFilter, statusFilter]);

  useEffect(() => { fetchFindings(); }, [fetchFindings]);

  const handleAction = async (findingId: string, action: 'acknowledge' | 'resolve') => {
    try {
      const res = await fetch(`/api/security/findings/${findingId}/${action}`, { method: 'POST' });
      if (res.ok) fetchFindings();
    } catch (err) {
      console.error(`Failed to ${action} finding:`, err);
    }
  };

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
      <div className="flex gap-3">
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
      </div>

      {/* Table */}
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-slate-400">Loading...</div>
        ) : findings.length === 0 ? (
          <div className="p-8 text-center text-slate-400">No findings match the current filters</div>
        ) : (
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-900/50 text-slate-400 uppercase text-xs tracking-wider">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">Rule</th>
                <th className="px-4 py-3">Identity</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Detected</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {findings.map(f => (
                <tr key={f.id} className="hover:bg-slate-700/20">
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEVERITY_BADGE[f.severity] || ''}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {(f.metadata as Record<string, string>)?.finding_category === 'privilege_escalation' ? (
                      <span className="px-2 py-0.5 rounded text-xs font-medium bg-purple-500/20 text-purple-400 border border-purple-500/30">
                        Privilege Escalation
                      </span>
                    ) : (f.metadata as Record<string, string>)?.finding_category === 'nhi_security' ? (
                      <span className="px-2 py-0.5 rounded text-xs font-medium bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                        Non-Human Identity
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-xs font-medium bg-slate-500/20 text-slate-400 border border-slate-500/30">
                        {f.rule_type || 'risk'}
                      </span>
                    )}
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
                          Acknowledge
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
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default SecurityFindings;
