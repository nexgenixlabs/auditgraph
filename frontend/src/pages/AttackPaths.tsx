import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';

interface AttackPath {
  id: number;
  source_entity_name: string;
  source_entity_id: string;
  source_entity_type: string;
  path_type: string;
  severity: string;
  risk_score: number;
  description: string;
  narrative: string;
  impact: string;
  path_length: number;
  affected_resource_count: number;
  first_detected_at: string;
  last_detected_at: string;
  occurrence_count: number;
  target_resource_id: string;
  target_resource_type: string;
}

interface SurfaceSummary {
  total_paths: number;
  critical_paths: number;
  high_paths: number;
  subscription_scope_paths: number;
  keyvault_exposure_paths: number;
}

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border border-blue-500/30',
};

const TYPE_LABELS: Record<string, string> = {
  PRIVILEGE_ESCALATION: 'Privilege Escalation',
  KEYVAULT_SECRET_ACCESS: 'Key Vault Access',
  SPN_SECRET_EXPOSURE: 'Secret Exposure',
  ROLE_CHAINING: 'Role Chaining',
  direct_escalation: 'Direct Escalation',
  lateral_movement: 'Lateral Movement',
  sensitive_data_exposure: 'Data Exposure',
  cross_tenant_risk: 'Cross-Tenant',
  privilege_accumulation: 'Privilege Accumulation',
};

export default function AttackPaths() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { withConnection } = useConnection();

  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [summary, setSummary] = useState<SurfaceSummary | null>(null);
  const [loading, setLoading] = useState(true);

  const [sevFilter, setSevFilter] = useState(searchParams.get('severity') || '');
  const [typeFilter, setTypeFilter] = useState(searchParams.get('path_type') || '');
  const [sortCol, setSortCol] = useState<string>('risk_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (sevFilter) params.set('severity', sevFilter);
    if (typeFilter) params.set('path_type', typeFilter);
    params.set('limit', '100');

    const qs = withConnection(params.toString());

    Promise.all([
      fetch(`/api/attack-paths?${qs}`).then(r => r.ok ? r.json() : { paths: [] }),
      fetch(`/api/dashboard/attack-surface?${withConnection('')}`).then(r => r.ok ? r.json() : null),
    ]).then(([listData, surfaceData]) => {
      setPaths(listData.paths || []);
      setSummary(surfaceData);
    }).finally(() => setLoading(false));
  }, [sevFilter, typeFilter, withConnection]);

  useEffect(() => {
    const p = new URLSearchParams();
    if (sevFilter) p.set('severity', sevFilter);
    if (typeFilter) p.set('path_type', typeFilter);
    setSearchParams(p, { replace: true });
  }, [sevFilter, typeFilter, setSearchParams]);

  const sorted = useMemo(() => {
    const copy = [...paths];
    const sevOrder: Record<string, number> = { critical: 1, high: 2, medium: 3, low: 4 };
    copy.sort((a, b) => {
      let cmp = 0;
      if (sortCol === 'risk_score') cmp = a.risk_score - b.risk_score;
      else if (sortCol === 'severity') cmp = (sevOrder[a.severity] || 5) - (sevOrder[b.severity] || 5);
      else if (sortCol === 'source_entity_name') cmp = (a.source_entity_name || '').localeCompare(b.source_entity_name || '');
      else if (sortCol === 'path_type') cmp = (a.path_type || '').localeCompare(b.path_type || '');
      else if (sortCol === 'affected_resource_count') cmp = a.affected_resource_count - b.affected_resource_count;
      return sortDir === 'desc' ? -cmp : cmp;
    });
    return copy;
  }, [paths, sortCol, sortDir]);

  const toggleSort = (col: string) => {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('desc'); }
  };

  // Derive unique path types for the filter dropdown
  const pathTypes = useMemo(() => {
    const types = new Set(paths.map(p => p.path_type));
    return Array.from(types).sort();
  }, [paths]);

  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      <div className="mb-6">
        <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Attack Paths</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          Privilege escalation and lateral movement paths discovered via BFS graph analysis.
        </p>
      </div>

      {/* Summary Chips */}
      {summary && (
        <div className="flex flex-wrap gap-3 mb-5">
          <Chip label="Total Paths" value={summary.total_paths} color="#64748b" />
          <Chip label="Critical" value={summary.critical_paths} color="#ef4444" />
          <Chip label="High" value={summary.high_paths} color="#f97316" />
          <Chip label="Lateral Movement" value={summary.subscription_scope_paths} color="#8b5cf6" />
          <Chip label="Data Exposure" value={summary.keyvault_exposure_paths} color="#0891b2" />
        </div>
      )}

      {/* Filter Bar */}
      <div className="flex flex-wrap gap-3 mb-4">
        <FilterSelect label="Severity" value={sevFilter} onChange={setSevFilter}
          options={[{ value: '', label: 'All Severities' }, { value: 'critical', label: 'Critical' }, { value: 'high', label: 'High' }, { value: 'medium', label: 'Medium' }, { value: 'low', label: 'Low' }]} />
        <FilterSelect label="Type" value={typeFilter} onChange={setTypeFilter}
          options={[{ value: '', label: 'All Types' }, ...pathTypes.map(t => ({ value: t, label: TYPE_LABELS[t] || t }))]} />
        {(sevFilter || typeFilter) && (
          <button onClick={() => { setSevFilter(''); setTypeFilter(''); }}
            className="text-xs px-3 py-1.5 rounded-lg border transition-colors"
            style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }}>
            Clear Filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
        {loading ? (
          <div className="flex items-center justify-center py-16">
            <div className="animate-spin h-6 w-6 border-2 border-blue-600 border-t-transparent rounded-full" />
          </div>
        ) : sorted.length === 0 ? (
          <div className="text-center py-16 text-sm" style={{ color: 'var(--text-secondary)' }}>
            No attack paths found{sevFilter || typeFilter ? ' matching filters' : ''}.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left" style={{ borderColor: 'var(--border-default)' }}>
                <Th label="Identity" col="source_entity_name" sortCol={sortCol} sortDir={sortDir} onSort={toggleSort} />
                <Th label="Type" col="path_type" sortCol={sortCol} sortDir={sortDir} onSort={toggleSort} />
                <Th label="Severity" col="severity" sortCol={sortCol} sortDir={sortDir} onSort={toggleSort} />
                <Th label="Score" col="risk_score" sortCol={sortCol} sortDir={sortDir} onSort={toggleSort} />
                <Th label="Impact" col="affected_resource_count" sortCol={sortCol} sortDir={sortDir} onSort={toggleSort} />
                <th className="px-4 py-3 font-medium text-xs" style={{ color: 'var(--text-tertiary)' }}>Description</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map(p => (
                <tr key={p.id}
                  onClick={() => navigate(`/attack-paths/${p.id}`)}
                  className="border-b cursor-pointer transition-colors hover:bg-[var(--bg-elevated)]"
                  style={{ borderColor: 'var(--border-subtle)' }}>
                  <td className="px-4 py-3">
                    <div className="font-medium" style={{ color: 'var(--text-primary)' }}>{p.source_entity_name || 'Unknown'}</div>
                    <div className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>{p.source_entity_type}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
                      {TYPE_LABELS[p.path_type] || p.path_type}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEV_BADGE[p.severity] || 'bg-gray-500/15 text-gray-400'}`}>
                      {p.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs" style={{ color: 'var(--text-primary)' }}>{p.risk_score}</td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
                      {p.affected_resource_count > 0 ? `${p.affected_resource_count} resources` : '-'}
                    </span>
                  </td>
                  <td className="px-4 py-3 max-w-[300px]">
                    <div className="text-xs truncate" style={{ color: 'var(--text-secondary)' }} title={p.description}>
                      {p.description}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="mt-3 text-xs" style={{ color: 'var(--text-tertiary)' }}>
        Showing {sorted.length} path{sorted.length !== 1 ? 's' : ''}
      </div>
    </div>
  );
}

// ── Shared sub-components ────────────────────────────────────────

function Chip({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex items-center gap-2 px-3 py-2 rounded-lg border" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
      <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{label}</span>
      <span className="text-sm font-semibold font-mono" style={{ color: 'var(--text-primary)' }}>{value}</span>
    </div>
  );
}

function FilterSelect({ label, value, onChange, options }: {
  label: string; value: string; onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)}
      className="text-xs px-3 py-1.5 rounded-lg border appearance-none pr-7"
      style={{ color: 'var(--text-primary)', borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}
      title={label}>
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
}

function Th({ label, col, sortCol, sortDir, onSort }: {
  label: string; col: string; sortCol: string; sortDir: string; onSort: (c: string) => void;
}) {
  return (
    <th className="px-4 py-3 font-medium text-xs cursor-pointer select-none"
      style={{ color: 'var(--text-tertiary)' }}
      onClick={() => onSort(col)}>
      {label}{sortCol === col ? (sortDir === 'desc' ? ' \u2193' : ' \u2191') : ''}
    </th>
  );
}
