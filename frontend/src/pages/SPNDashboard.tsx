import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import { RISK_BADGE, safeLower } from '../constants/metrics';
import { downloadCSV, exportFilename } from '../utils/exportUtils';
import { generateSPNReport } from '../utils/spnPdfGenerator';

// ─── Types ────────────────────────────────────────────────────────

interface SPNRow {
  identity_id: string;
  display_name: string;
  identity_type: string;
  identity_category: string;
  risk_level: string;
  risk_score: number;
  credential_count: number;
  credential_risk: string;
  next_expiry: string | null;
  activity_status: string;
  created_datetime: string | null;
  last_sign_in: string | null;
  rbac_role_count: number;
  entra_role_count: number;
  role_count: number;
  owner_display_name: string | null;
  owner_count: number;
  enabled: boolean;
  blast_radius: string;
  critical_roles: string[];
  privilege_tier: number;
  api_permission_count: number;
  app_role_count: number;
  app_id?: string;
}

interface SPNStats {
  total: number;
  custom: number;
  microsoft: number;
  critical: number;
  high_risk: number;
  expired_credentials: number;
  expiring_soon: number;
  no_credentials: number;
  by_risk: Record<string, number>;
  by_category: Record<string, number>;
  by_activity: Record<string, number>;
  by_blast_radius: Record<string, number>;
}

interface SPNDetail {
  identity: Record<string, unknown>;
  roles: Array<Record<string, unknown>>;
  entra_roles: Array<Record<string, unknown>>;
  credentials: Array<Record<string, unknown>>;
  permissions: Array<Record<string, unknown>>;
  owners: Array<Record<string, unknown>>;
  blast_radius: string;
  critical_roles: string[];
  risk_summary: string[];
  recommendations: Array<{ priority: string; action: string; reason: string }>;
  attacker_narrative: string[];
  auditor_questions: string[];
}

type SortField = 'risk_score' | 'display_name' | 'credential_risk' | 'next_expiry' | 'activity_status' | 'blast_radius';

const BLAST_ORDER: Record<string, number> = { high: 3, medium: 2, low: 1, none: 0 };

const BLAST_BADGE: Record<string, string> = {
  high: 'bg-red-100 text-red-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
  none: 'bg-gray-100 text-gray-500',
};

const CRED_RISK_BADGE: Record<string, string> = {
  expired: 'bg-red-100 text-red-700',
  expiring_soon: 'bg-yellow-100 text-yellow-700',
  healthy: 'bg-green-100 text-green-700',
  unknown: 'bg-gray-100 text-gray-500',
};

const ACTIVITY_BADGE: Record<string, string> = {
  active: 'bg-green-100 text-green-700',
  inactive: 'bg-yellow-100 text-yellow-700',
  stale: 'bg-orange-100 text-orange-700',
  never_used: 'bg-red-100 text-red-700',
  recently_created: 'bg-blue-100 text-blue-700',
  unknown: 'bg-gray-100 text-gray-500',
};

const PRIORITY_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  info: 'bg-blue-100 text-blue-600 border-blue-200',
};

// ─── Small Components ─────────────────────────────────────────────

function StatCard({ label, value, color, subtitle, onClick, active }: {
  label: string; value: number; color: string; subtitle?: string; onClick?: () => void; active?: boolean;
}) {
  const colorMap: Record<string, string> = {
    blue: 'bg-blue-50 border-blue-200 text-blue-700',
    red: 'bg-red-50 border-red-200 text-red-700',
    orange: 'bg-orange-50 border-orange-200 text-orange-700',
    yellow: 'bg-yellow-50 border-yellow-200 text-yellow-700',
    green: 'bg-green-50 border-green-200 text-green-700',
    purple: 'bg-purple-50 border-purple-200 text-purple-700',
    gray: 'bg-gray-50 border-gray-200 text-gray-600',
  };
  return (
    <div
      onClick={onClick}
      className={`border rounded-lg p-3 ${colorMap[color] || colorMap.blue} ${onClick ? 'cursor-pointer hover:shadow-sm transition-shadow' : ''} ${active ? 'ring-2 ring-blue-500 ring-offset-1' : ''}`}
    >
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs font-medium opacity-80">{label}</div>
      {subtitle && <div className="text-[10px] opacity-60 mt-0.5">{subtitle}</div>}
    </div>
  );
}

function SortHeader({ label, field, currentField, currentDir, onSort }: {
  label: string; field: SortField; currentField: SortField; currentDir: 'asc' | 'desc'; onSort: (f: SortField) => void;
}) {
  const isActive = currentField === field;
  return (
    <th className="px-3 py-2.5 cursor-pointer select-none hover:bg-gray-100 whitespace-nowrap text-xs" onClick={() => onSort(field)}>
      <div className="flex items-center gap-0.5">
        <span>{label}</span>
        <span className={`text-[10px] ${isActive ? 'text-blue-600' : 'text-gray-400'}`}>
          {isActive ? (currentDir === 'asc' ? '▲' : '▼') : '↕'}
        </span>
      </div>
    </th>
  );
}

function daysUntil(iso: string | null): string {
  if (!iso) return '—';
  const d = Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);
  if (d < 0) return `${Math.abs(d)}d ago`;
  if (d === 0) return 'Today';
  return `${d}d`;
}

// ─── Drill-Down Panel ─────────────────────────────────────────────

function SPNDrillDown({ detail, onClose }: { detail: SPNDetail; onClose: () => void }) {
  const identity = detail.identity;
  const name = (identity.display_name as string) || 'Unknown';

  return (
    <div className="fixed inset-y-0 right-0 w-[480px] bg-white shadow-2xl border-l border-gray-200 z-50 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-gray-200 bg-gray-50 flex items-center justify-between shrink-0">
        <div>
          <h2 className="text-base font-bold text-gray-900 truncate max-w-[320px]" title={name}>{name}</h2>
          <div className="flex items-center gap-2 mt-1">
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[safeLower(identity.risk_level as string)] || 'bg-gray-100 text-gray-600'}`}>
              {(identity.risk_level as string) || 'info'}
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${BLAST_BADGE[detail.blast_radius] || BLAST_BADGE.none}`}>
              Blast: {detail.blast_radius}
            </span>
          </div>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-lg font-bold">x</button>
      </div>

      {/* Scrollable content */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Risk Summary */}
        <section>
          <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">Risk Summary</h3>
          <div className="bg-red-50 border border-red-200 rounded-lg p-3 space-y-1">
            {detail.risk_summary.map((point, i) => (
              <div key={i} className="flex items-start gap-2 text-xs text-red-800">
                <span className="mt-0.5 shrink-0">!</span>
                <span>{point}</span>
              </div>
            ))}
          </div>
        </section>

        {/* Identity Info */}
        <section>
          <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">Identity Details</h3>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
            <span className="text-gray-500">Category</span>
            <span className="font-medium">{(identity.identity_category as string) || '—'}</span>
            <span className="text-gray-500">App ID</span>
            <span className="font-mono text-[10px] break-all">{(identity.app_id as string) || '—'}</span>
            <span className="text-gray-500">Object ID</span>
            <span className="font-mono text-[10px] break-all">{(identity.object_id as string) || '—'}</span>
            <span className="text-gray-500">Created</span>
            <span>{identity.created_datetime ? new Date(identity.created_datetime as string).toLocaleDateString() : '—'}</span>
            <span className="text-gray-500">Enabled</span>
            <span>{identity.enabled ? 'Yes' : 'No'}</span>
            <span className="text-gray-500">Activity</span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${ACTIVITY_BADGE[safeLower(identity.activity_status as string)] || ACTIVITY_BADGE.unknown}`}>
              {(identity.activity_status as string) || 'unknown'}
            </span>
          </div>
        </section>

        {/* Credentials */}
        <section>
          <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
            Credentials ({detail.credentials.length})
          </h3>
          {detail.credentials.length === 0 ? (
            <p className="text-xs text-gray-400 italic">No credentials discovered</p>
          ) : (
            <div className="space-y-2">
              {detail.credentials.map((c, i) => {
                const endDate = c.end_datetime as string | null;
                const isExpired = endDate ? new Date(endDate) < new Date() : false;
                return (
                  <div key={i} className={`border rounded-md p-2.5 text-xs ${isExpired ? 'border-red-200 bg-red-50/50' : 'border-gray-200'}`}>
                    <>
                      <div className="flex items-center justify-between">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          (c.credential_type as string) === 'secret' ? 'bg-orange-100 text-orange-700' :
                          (c.credential_type as string) === 'certificate' ? 'bg-blue-100 text-blue-700' :
                          'bg-green-100 text-green-700'
                        }`}>{(c.credential_type as string) || '?'}</span>
                        <span className={`text-[10px] font-semibold ${isExpired ? 'text-red-600' : 'text-gray-500'}`}>
                          {endDate ? (isExpired ? 'EXPIRED' : `Expires ${daysUntil(endDate)}`) : 'No expiry'}
                        </span>
                      </div>
                      {!!c.display_name && <div className="text-gray-600 mt-1 truncate">{c.display_name as string}</div>}
                      <div className="text-[10px] text-gray-400 mt-0.5 font-mono truncate">
                        Key: {((c.key_id as string) || '').slice(0, 16)}...
                      </div>
                    </>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* Azure RBAC Roles */}
        {detail.roles.length > 0 && (
          <section>
            <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
              Azure RBAC Roles ({detail.roles.length})
            </h3>
            <div className="space-y-1">
              {detail.roles.map((r, i) => (
                <div key={i} className="flex items-center justify-between text-xs border border-gray-100 rounded p-2">
                  <>
                    <div>
                      <span className="font-medium text-gray-900">{r.role_name as string}</span>
                      <div className="text-[10px] text-gray-400 truncate max-w-[280px]" title={r.scope as string}>
                        {r.scope_type as string}: {r.scope as string}
                      </div>
                    </div>
                    {!!r.risk_level && (
                      <span className={`px-1 py-0.5 rounded text-[9px] font-semibold uppercase ${RISK_BADGE[safeLower(r.risk_level as string)] || ''}`}>
                        {r.risk_level as string}
                      </span>
                    )}
                  </>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Entra Roles */}
        {detail.entra_roles.length > 0 && (
          <section>
            <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
              Entra Directory Roles ({detail.entra_roles.length})
            </h3>
            <div className="space-y-1">
              {detail.entra_roles.map((r, i) => (
                <div key={i} className="flex items-center justify-between text-xs border border-gray-100 rounded p-2">
                  <>
                    <span className="font-medium text-gray-900">{r.role_name as string}</span>
                    {!!r.risk_level && (
                      <span className={`px-1 py-0.5 rounded text-[9px] font-semibold uppercase ${RISK_BADGE[safeLower(r.risk_level as string)] || ''}`}>
                        {r.risk_level as string}
                      </span>
                    )}
                  </>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Owners */}
        <section>
          <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">
            Owners ({detail.owners.length})
          </h3>
          {detail.owners.length === 0 ? (
            <p className="text-xs text-orange-600 italic">No registered owner — accountability gap</p>
          ) : (
            <div className="space-y-1">
              {detail.owners.map((o, i) => (
                <div key={i} className="text-xs border border-gray-100 rounded p-2">
                  <>
                    <span className="font-medium">{o.owner_display_name as string}</span>
                    {!!o.owner_upn && <span className="text-gray-400 ml-2 text-[10px]">{o.owner_upn as string}</span>}
                  </>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* What Attackers Could Do */}
        {detail.attacker_narrative.length > 0 && (
          <section>
            <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">What Attackers Could Do</h3>
            <div className="bg-gray-900 rounded-lg p-3 space-y-1.5">
              {detail.attacker_narrative.map((point, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-gray-200">
                  <span className="text-red-400 mt-0.5 shrink-0">&#9658;</span>
                  <span>{point}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* What Auditors Will Question */}
        {detail.auditor_questions.length > 0 && (
          <section>
            <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">What Auditors Will Question</h3>
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 space-y-1.5">
              {detail.auditor_questions.map((q, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-blue-800">
                  <span className="text-blue-500 mt-0.5 shrink-0">?</span>
                  <span>{q}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Recommendations */}
        <section>
          <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">Recommendations</h3>
          <div className="space-y-2">
            {detail.recommendations.map((rec, i) => (
              <div key={i} className={`border rounded-lg p-3 ${PRIORITY_BADGE[rec.priority] || PRIORITY_BADGE.info}`}>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-bold uppercase">{rec.priority}</span>
                  <span className="text-xs font-medium">{rec.action}</span>
                </div>
                <p className="text-[10px] mt-1 opacity-70">{rec.reason}</p>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Footer */}
      <div className="px-5 py-3 border-t border-gray-200 bg-gray-50 shrink-0">
        <button
          onClick={() => window.open(`/identities/${identity.identity_id as string}`, '_blank')}
          className="w-full text-xs text-center py-2 px-3 bg-blue-600 text-white rounded-md hover:bg-blue-700 font-medium"
        >
          Open Full Identity Detail
        </button>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────

export default function SPNDashboard() {
  const location = useLocation();

  const [stats, setStats] = useState<SPNStats | null>(null);
  const [spns, setSpns] = useState<SPNRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [initialized, setInitialized] = useState(false);

  // Filters
  const [riskFilter, setRiskFilter] = useState('');
  const [blastFilter, setBlastFilter] = useState('');
  const [credFilter, setCredFilter] = useState('');
  const [activityFilter, setActivityFilter] = useState('');
  const [search, setSearch] = useState('');
  const [hideMicrosoft, setHideMicrosoft] = useState(true);
  const [sortField, setSortField] = useState<SortField>('risk_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  // Drill-down
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<SPNDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Sync from URL
  useEffect(() => {
    const p = new URLSearchParams(location.search);
    if (p.get('risk')) setRiskFilter(p.get('risk') || '');
    if (p.get('blast')) setBlastFilter(p.get('blast') || '');
    if (p.get('cred')) setCredFilter(p.get('cred') || '');
    if (p.get('activity')) setActivityFilter(p.get('activity') || '');
    if (p.get('search')) setSearch(p.get('search') || '');
    setInitialized(true);
  }, [location.search]);

  // Fetch stats
  useEffect(() => {
    if (!initialized) return;
    fetch('/api/spns/stats')
      .then(r => r.json())
      .then(setStats)
      .catch(() => {});
  }, [initialized]);

  // Fetch SPN list
  useEffect(() => {
    if (!initialized) return;
    setLoading(true);
    const abort = new AbortController();
    const params = new URLSearchParams();
    params.set('limit', '500');
    params.set('hide_microsoft', hideMicrosoft ? 'true' : 'false');
    if (riskFilter) params.set('risk_level', riskFilter);
    if (blastFilter) params.set('blast_radius', blastFilter);
    if (credFilter) params.set('credential_filter', credFilter);
    if (activityFilter) params.set('activity', activityFilter);
    if (search) params.set('search', search);

    fetch(`/api/spns?${params}`, { signal: abort.signal })
      .then(r => r.json())
      .then(data => {
        setSpns(data.spns || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
    return () => abort.abort();
  }, [initialized, riskFilter, blastFilter, credFilter, activityFilter, search, hideMicrosoft]);

  // Fetch detail when selected
  useEffect(() => {
    if (!selectedId) { setDetail(null); return; }
    setDetailLoading(true);
    fetch(`/api/spns/${selectedId}`)
      .then(r => r.json())
      .then(d => { setDetail(d); setDetailLoading(false); })
      .catch(() => setDetailLoading(false));
  }, [selectedId]);

  // Client-side sort
  const sorted = useMemo(() => {
    const arr = [...spns];
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortField === 'risk_score') cmp = (a.risk_score || 0) - (b.risk_score || 0);
      else if (sortField === 'blast_radius') cmp = (BLAST_ORDER[a.blast_radius] || 0) - (BLAST_ORDER[b.blast_radius] || 0);
      else if (sortField === 'next_expiry') {
        const at = a.next_expiry ? new Date(a.next_expiry).getTime() : Infinity;
        const bt = b.next_expiry ? new Date(b.next_expiry).getTime() : Infinity;
        cmp = at - bt;
      } else {
        const av = String((a as unknown as Record<string, unknown>)[sortField] || '').toLowerCase();
        const bv = String((b as unknown as Record<string, unknown>)[sortField] || '').toLowerCase();
        cmp = av.localeCompare(bv);
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return arr;
  }, [spns, sortField, sortDir]);

  const handleSort = useCallback((f: SortField) => {
    if (f === sortField) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortField(f); setSortDir(f === 'risk_score' || f === 'blast_radius' ? 'desc' : 'asc'); }
  }, [sortField]);

  // URL sync
  useEffect(() => {
    if (!initialized) return;
    const p = new URLSearchParams();
    if (riskFilter) p.set('risk', riskFilter);
    if (blastFilter) p.set('blast', blastFilter);
    if (credFilter) p.set('cred', credFilter);
    if (activityFilter) p.set('activity', activityFilter);
    if (search) p.set('search', search);
    const qs = p.toString();
    window.history.replaceState(null, '', qs ? `${window.location.pathname}?${qs}` : window.location.pathname);
  }, [riskFilter, blastFilter, credFilter, activityFilter, search, initialized]);

  const clearFilters = () => {
    setRiskFilter(''); setBlastFilter(''); setCredFilter(''); setActivityFilter(''); setSearch('');
  };
  const hasFilters = riskFilter || blastFilter || credFilter || activityFilter || search;

  // Telemetry health — compute % with unknown activity
  const unknownPct = useMemo(() => {
    if (!stats || stats.custom === 0) return 0;
    return Math.round(((stats.by_activity?.unknown || 0) + (stats.by_activity?.never_used || 0)) / stats.custom * 100);
  }, [stats]);
  const [bannerDismissed, setBannerDismissed] = useState(false);

  // CSV export — flatten critical_roles array for export
  const exportData = useMemo(() =>
    sorted.map(s => ({
      ...s,
      critical_roles: (s.critical_roles || []).join(', '),
    })),
    [sorted]
  );

  const SPN_CSV_COLS = useMemo(() => [
    { key: 'display_name', header: 'Name' },
    { key: 'identity_category', header: 'Category' },
    { key: 'risk_level', header: 'Risk Level' },
    { key: 'risk_score', header: 'Risk Score' },
    { key: 'blast_radius', header: 'Blast Radius' },
    { key: 'critical_roles', header: 'Critical Roles' },
    { key: 'credential_risk', header: 'Credential Risk' },
    { key: 'credential_count', header: 'Credential Count' },
    { key: 'next_expiry', header: 'Next Expiry' },
    { key: 'activity_status', header: 'Activity Status' },
    { key: 'role_count', header: 'Total Roles' },
    { key: 'rbac_role_count', header: 'RBAC Roles' },
    { key: 'entra_role_count', header: 'Entra Roles' },
    { key: 'owner_display_name', header: 'Owner' },
    { key: 'owner_count', header: 'Owner Count' },
    { key: 'enabled', header: 'Enabled' },
    { key: 'identity_id', header: 'Identity ID' },
  ], []);

  const handleCSVExport = useCallback(() => {
    downloadCSV(
      exportData as unknown as Record<string, unknown>[],
      SPN_CSV_COLS,
      exportFilename('spn-audit', 'csv')
    );
  }, [exportData, SPN_CSV_COLS]);

  const [pdfGenerating, setPdfGenerating] = useState(false);

  const handlePDFExport = useCallback(async () => {
    if (!stats) return;
    setPdfGenerating(true);
    try {
      // Fetch detail for critical/high SPNs (top 10 by risk score)
      const critSpns = [...spns]
        .filter(s => s.risk_level === 'critical' || s.risk_level === 'high')
        .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
        .slice(0, 10);

      const details = await Promise.all(
        critSpns.map(s =>
          fetch(`/api/spns/${s.identity_id}`)
            .then(r => r.json())
            .catch(() => null)
        )
      );

      generateSPNReport(
        sorted,
        stats,
        details.filter(Boolean),
      );
    } catch {
      // PDF generation failed silently
    } finally {
      setPdfGenerating(false);
    }
  }, [stats, spns, sorted]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Service Principals</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Non-human identities — SPNs, managed identities, workload credentials
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handlePDFExport}
            disabled={sorted.length === 0 || !stats || pdfGenerating}
            className="px-3 py-1.5 text-xs font-medium bg-purple-600 text-white rounded-md hover:bg-purple-700 disabled:opacity-40"
          >
            {pdfGenerating ? 'Generating...' : 'PDF Report'}
          </button>
          <button
            onClick={handleCSVExport}
            disabled={sorted.length === 0}
            className="px-3 py-1.5 text-xs font-medium bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-40"
          >
            Export for Audit
          </button>
          <label className="flex items-center gap-2 text-xs text-gray-600">
            <input
              type="checkbox"
              checked={hideMicrosoft}
              onChange={e => setHideMicrosoft(e.target.checked)}
              className="rounded border-gray-300"
            />
            Hide Microsoft
          </label>
        </div>
      </div>

      {/* Telemetry Health Banner */}
      {!bannerDismissed && unknownPct >= 10 && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-amber-600 text-lg">!</span>
            <div>
              <p className="text-sm font-medium text-amber-800">
                {unknownPct}% of SPNs have unknown usage ({(stats?.by_activity?.unknown || 0) + (stats?.by_activity?.never_used || 0)} of {stats?.custom || 0})
              </p>
              <p className="text-xs text-amber-600 mt-0.5">
                Sign-in telemetry may not be enabled. Access risk still exists even without usage data.
              </p>
            </div>
          </div>
          <button onClick={() => setBannerDismissed(true)} className="text-amber-400 hover:text-amber-600 text-xs font-medium">
            Dismiss
          </button>
        </div>
      )}

      {/* Summary Cards */}
      {stats && (
        <div className="grid grid-cols-5 gap-3">
          <StatCard
            label="Custom SPNs"
            value={stats.custom}
            color="blue"
            subtitle={stats.microsoft > 0 ? `+ ${stats.microsoft} Microsoft` : undefined}
          />
          <StatCard
            label="Critical / High Risk"
            value={stats.critical + stats.high_risk}
            color={stats.critical + stats.high_risk > 0 ? 'red' : 'green'}
            subtitle={`${stats.critical} critical, ${stats.high_risk} high`}
            onClick={() => setRiskFilter(riskFilter === 'critical' ? '' : 'critical')}
            active={riskFilter === 'critical'}
          />
          <StatCard
            label="Expired Credentials"
            value={stats.expired_credentials}
            color={stats.expired_credentials > 0 ? 'red' : 'green'}
            onClick={() => setCredFilter(credFilter === 'expired' ? '' : 'expired')}
            active={credFilter === 'expired'}
          />
          <StatCard
            label="Expiring < 30d"
            value={stats.expiring_soon}
            color={stats.expiring_soon > 0 ? 'orange' : 'green'}
            onClick={() => setCredFilter(credFilter === 'expiring_soon' ? '' : 'expiring_soon')}
            active={credFilter === 'expiring_soon'}
          />
          <StatCard
            label="High Blast Radius"
            value={stats.by_blast_radius?.high || 0}
            color={stats.by_blast_radius?.high > 0 ? 'red' : 'green'}
            subtitle={`${stats.by_blast_radius?.medium || 0} medium, ${stats.by_blast_radius?.low || 0} low`}
            onClick={() => setBlastFilter(blastFilter === 'high' ? '' : 'high')}
            active={blastFilter === 'high'}
          />
        </div>
      )}

      {/* Activity + Blast Radius mini-bars */}
      {stats && (
        <div className="grid grid-cols-2 gap-3">
          {/* Activity Breakdown */}
          <div className="border border-gray-200 rounded-lg p-3">
            <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">Activity Status</h3>
            <div className="flex gap-2 flex-wrap">
              {Object.entries(stats.by_activity).map(([status, count]) => (
                <button
                  key={status}
                  onClick={() => setActivityFilter(activityFilter === status ? '' : status)}
                  className={`px-2 py-1 rounded text-xs font-medium transition ${
                    activityFilter === status ? 'ring-2 ring-blue-500 ring-offset-1' : ''
                  } ${ACTIVITY_BADGE[status] || ACTIVITY_BADGE.unknown}`}
                >
                  {status.replace('_', ' ')}: {count}
                </button>
              ))}
            </div>
          </div>

          {/* Blast Radius Breakdown */}
          <div className="border border-gray-200 rounded-lg p-3">
            <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-2">Blast Radius Distribution</h3>
            <div className="flex gap-2">
              {['high', 'medium', 'low', 'none'].map(level => (
                <button
                  key={level}
                  onClick={() => setBlastFilter(blastFilter === level ? '' : level)}
                  className={`px-2 py-1 rounded text-xs font-medium transition ${
                    blastFilter === level ? 'ring-2 ring-blue-500 ring-offset-1' : ''
                  } ${BLAST_BADGE[level]}`}
                >
                  {level}: {stats.by_blast_radius?.[level] || 0}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Filters bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)} className="text-xs border border-gray-300 rounded-md px-2 py-1.5">
          <option value="">All Risk Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>

        <select value={credFilter} onChange={e => setCredFilter(e.target.value)} className="text-xs border border-gray-300 rounded-md px-2 py-1.5">
          <option value="">All Credential Status</option>
          <option value="expired">Expired</option>
          <option value="expiring_soon">Expiring Soon</option>
          <option value="no_credentials">No Credentials</option>
        </select>

        <select value={blastFilter} onChange={e => setBlastFilter(e.target.value)} className="text-xs border border-gray-300 rounded-md px-2 py-1.5">
          <option value="">All Blast Radius</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="none">None</option>
        </select>

        <input
          type="text"
          placeholder="Search by name or App ID..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="text-xs border border-gray-300 rounded-md px-2 py-1.5 w-56"
        />

        {hasFilters && (
          <button onClick={clearFilters} className="text-xs text-blue-600 hover:underline">
            Clear filters
          </button>
        )}

        <span className="text-xs text-gray-500 ml-auto">{sorted.length} service principals</span>
      </div>

      {/* Table */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
              <tr>
                <SortHeader label="Name" field="display_name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <th className="px-3 py-2.5 text-xs">Category</th>
                <SortHeader label="Risk" field="risk_score" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Blast Radius" field="blast_radius" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <th className="px-3 py-2.5 text-xs">Critical Roles</th>
                <SortHeader label="Cred Risk" field="credential_risk" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Next Expiry" field="next_expiry" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Activity" field="activity_status" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <th className="px-3 py-2.5 text-xs">Roles</th>
                <th className="px-3 py-2.5 text-xs">Owner</th>
                <th className="px-3 py-2.5 text-xs w-6"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading ? (
                <tr><td colSpan={11} className="px-3 py-8 text-center text-gray-400">Loading service principals...</td></tr>
              ) : sorted.length === 0 ? (
                <tr><td colSpan={11} className="px-3 py-8 text-center text-gray-400">No service principals found. Run a discovery to populate.</td></tr>
              ) : sorted.map(spn => (
                <tr
                  key={spn.identity_id}
                  className={`hover:bg-blue-50/40 cursor-pointer transition-colors ${selectedId === spn.identity_id ? 'bg-blue-50' : ''}`}
                  onClick={() => setSelectedId(selectedId === spn.identity_id ? null : spn.identity_id)}
                >
                  <td className="px-3 py-2 font-medium text-gray-900 max-w-[200px] truncate" title={spn.display_name}>
                    {spn.display_name}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                      spn.identity_category === 'service_principal' ? 'bg-blue-100 text-blue-700' :
                      spn.identity_category === 'managed_identity_user' ? 'bg-purple-100 text-purple-700' :
                      'bg-teal-100 text-teal-700'
                    }`}>
                      {spn.identity_category === 'service_principal' ? 'SPN' :
                       spn.identity_category === 'managed_identity_user' ? 'MI (User)' : 'MI (System)'}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-1">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[safeLower(spn.risk_level)] || 'bg-gray-100 text-gray-600'}`}>
                        {spn.risk_level || '?'}
                      </span>
                      {spn.risk_score > 0 && <span className="text-[10px] text-gray-400 font-mono">{spn.risk_score}</span>}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${BLAST_BADGE[spn.blast_radius] || BLAST_BADGE.none}`}>
                      {spn.blast_radius}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    {spn.critical_roles.length > 0 ? (
                      <div className="flex flex-wrap gap-0.5">
                        {spn.critical_roles.map((r, i) => (
                          <span key={i} className="px-1 py-0.5 rounded text-[9px] font-semibold bg-red-100 text-red-700">{r}</span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[10px] text-gray-400">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${CRED_RISK_BADGE[spn.credential_risk] || CRED_RISK_BADGE.unknown}`}>
                      {spn.credential_risk?.replace('_', ' ') || 'unknown'}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-gray-600 text-[10px] font-mono">
                    {daysUntil(spn.next_expiry)}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${ACTIVITY_BADGE[safeLower(spn.activity_status)] || ACTIVITY_BADGE.unknown}`}>
                      {spn.activity_status?.replace('_', ' ') || 'unknown'}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-gray-600 text-[10px]">
                    {spn.role_count > 0 ? `${spn.rbac_role_count}R ${spn.entra_role_count}E` : '—'}
                  </td>
                  <td className="px-3 py-2 text-gray-600 max-w-[100px] truncate text-[10px]" title={spn.owner_display_name || ''}>
                    {spn.owner_display_name || <span className="text-orange-500">None</span>}
                  </td>
                  <td className="px-3 py-2 text-gray-400">→</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Drill-Down Panel */}
      {selectedId && detail && !detailLoading && (
        <SPNDrillDown detail={detail} onClose={() => setSelectedId(null)} />
      )}
      {selectedId && detailLoading && (
        <div className="fixed inset-y-0 right-0 w-[480px] bg-white shadow-2xl border-l border-gray-200 z-50 flex items-center justify-center">
          <div className="animate-spin h-8 w-8 border-2 border-blue-600 border-t-transparent rounded-full" />
        </div>
      )}

      {/* Overlay to close panel */}
      {selectedId && (
        <div className="fixed inset-0 z-40" onClick={() => setSelectedId(null)} />
      )}
    </div>
  );
}
