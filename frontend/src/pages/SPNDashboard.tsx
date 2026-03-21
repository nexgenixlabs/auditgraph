import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import {
  RISK_BADGE, safeLower,
  SPN_EXPOSURE_COMPONENTS, EXPOSURE_THRESHOLDS,
  getExposureLevel, EXPOSURE_LEVEL_CONFIG,
  LIFECYCLE_STATE_CONFIG, OWNER_STATUS_CONFIG, SCOPE_FLAG_CONFIG,
} from '../constants/metrics';
import { downloadCSV, exportFilename, buildExportMeta } from '../utils/exportUtils';
import { generateSPNReport } from '../utils/spnPdfGenerator';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import { SnapshotContextHeader } from '../components/ui/SnapshotContextHeader';

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
  // Exposure fields
  exposure_score: number;
  privilege_score: number;
  credential_risk_score: number;
  exposure_subscore: number;
  lifecycle_score: number;
  visibility_score: number;
  lifecycle_state: string;
  can_escalate: boolean;
  effective_scope_flag: string;
  owner_status: string;
  credential_age_days: number;
  cross_subscription: boolean;
  activity_confidence: number;
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
  exposure_critical: number;
  can_escalate_count: number;
  orphaned_privileged: number;
  blind_count: number;
  cross_sub_count: number;
  avg_exposure_score: number;
}

interface ExposureFinding {
  finding_type: string;
  severity: string;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  remediation: string;
  component: string;
  score_impact: number;
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
  exposure: {
    total: number;
    privilege: number;
    credential_risk: number;
    exposure: number;
    lifecycle: number;
    visibility: number;
    can_escalate: boolean;
    effective_scope_flag: string;
    lifecycle_state: string;
    owner_status: string;
    federated_trust: boolean;
    cross_subscription: boolean;
    credential_age_days: number;
    critical_overrides: Array<{ type: string; description: string }>;
  };
  findings: ExposureFinding[];
  activity_inference: { confidence: number; classification: string };
  status?: string;
  status_display?: { label: string; badge_class: string };
}

type SortField = 'exposure_score' | 'display_name' | 'privilege_score' | 'credential_risk_score' | 'next_expiry' | 'activity_status';

const PRIORITY_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-green-100 text-green-700 border-green-200',
  info: 'bg-blue-100 text-blue-600 border-blue-200',
};

// ─── Small Components ─────────────────────────────────────────────

function ExposureCard({ label, value, color, subtitle, onClick, active }: {
  label: string; value: number; color: string; subtitle?: string; onClick?: () => void; active?: boolean;
}) {
  const colorMap: Record<string, string> = {
    red: 'bg-red-50 border-red-200 text-red-700',
    orange: 'bg-orange-50 border-orange-200 text-orange-700',
    yellow: 'bg-yellow-50 border-yellow-200 text-yellow-700',
    green: 'bg-green-50 border-green-200 text-green-700',
    purple: 'bg-purple-50 border-purple-200 text-purple-700',
    gray: 'bg-gray-50 border-gray-200 text-gray-600',
    blue: 'bg-blue-50 border-blue-200 text-blue-700',
  };
  return (
    <div
      onClick={onClick}
      className={`border rounded-lg p-3 ${colorMap[color] || colorMap.gray} ${onClick ? 'cursor-pointer hover:shadow-sm transition-shadow' : ''} ${active ? 'ring-2 ring-blue-500 ring-offset-1' : ''}`}
    >
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs font-medium text-gray-600">{label}</div>
      {subtitle && <div className="text-[10px] text-gray-500 mt-0.5">{subtitle}</div>}
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

/** Mini exposure score ring */
function ExposureRing({ score }: { score: number }) {
  const level = getExposureLevel(score);
  const config = EXPOSURE_LEVEL_CONFIG[level];
  const pct = Math.min(score, 100);
  const r = 14;
  const circ = 2 * Math.PI * r;
  const offset = circ - (pct / 100) * circ;
  return (
    <div className="flex items-center gap-1.5">
      <svg width="34" height="34" className="shrink-0">
        <circle cx="17" cy="17" r={r} fill="none" stroke="#e5e7eb" strokeWidth="3" />
        <circle cx="17" cy="17" r={r} fill="none" stroke={config.color}
          strokeWidth="3" strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round" transform="rotate(-90 17 17)" />
        <text x="17" y="17" textAnchor="middle" dominantBaseline="central"
          className="text-[8px] font-bold fill-current" style={{ fill: config.color }}>
          {score}
        </text>
      </svg>
      <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase ${config.badgeClass}`}>
        {config.label}
      </span>
    </div>
  );
}

/** Component score bar */
function ComponentBar({ label, score, max, color }: { label: string; score: number; max: number; color: string }) {
  const pct = max > 0 ? Math.min((score / max) * 100, 100) : 0;
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-24 text-gray-600 text-right shrink-0">{label}</span>
      <div className="flex-1 h-3 bg-gray-100 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <span className="w-10 text-right font-mono text-[10px] text-gray-500">{score}/{max}</span>
    </div>
  );
}

// ─── Risk Breakdown Modal ─────────────────────────────────────────

function RiskBreakdownModal({ detail, onClose }: { detail: SPNDetail; onClose: () => void }) {
  const identity = detail.identity;
  const name = (identity.display_name as string) || 'Unknown';
  const exp = detail.exposure;
  const level = getExposureLevel(exp.total);
  const levelConfig = EXPOSURE_LEVEL_CONFIG[level];
  const lcConfig = LIFECYCLE_STATE_CONFIG[exp.lifecycle_state] || LIFECYCLE_STATE_CONFIG.blind;
  const ownerConfig = OWNER_STATUS_CONFIG[exp.owner_status] || OWNER_STATUS_CONFIG.unknown;
  const scopeConfig = SCOPE_FLAG_CONFIG[exp.effective_scope_flag] || SCOPE_FLAG_CONFIG.resource;

  // Group findings by component
  const findingsByComponent: Record<string, ExposureFinding[]> = {};
  for (const f of detail.findings) {
    findingsByComponent[f.component] = findingsByComponent[f.component] || [];
    findingsByComponent[f.component].push(f);
  }

  return (
    <>
      <div className="fixed inset-0 z-50 bg-black/60" onClick={onClose} />
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={onClose}>
        <div
          className="bg-white rounded-xl shadow-lg max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col"
          onClick={e => e.stopPropagation()}
        >
          {/* Header */}
          <div className="px-6 py-4 border-b border-gray-200 bg-gray-50 flex items-center justify-between shrink-0">
            <div>
              <h2 className="text-base font-bold text-gray-900 truncate max-w-[500px]" title={name}>{name}</h2>
              <div className="flex items-center gap-2 mt-1">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${levelConfig.badgeClass}`}>
                  Exposure: {exp.total}/100
                </span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${lcConfig.badgeClass}`}>
                  Activity: {lcConfig.label}
                </span>
                {!!detail && (
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                    detail.status_display?.badge_class ||
                    (detail.status === 'active' ? 'bg-green-100 text-green-700' :
                     detail.status === 'disabled' ? 'bg-red-100 text-red-700' :
                     'bg-gray-100 text-gray-500')
                  }`}>
                    {detail.status_display?.label || detail.status || 'Active'}
                  </span>
                )}
                {!!exp.can_escalate && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-600 text-white">CAN ESCALATE</span>
                )}
              </div>
            </div>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-lg font-bold p-1">x</button>
          </div>

          {/* Scrollable content */}
          <div className="flex-1 overflow-y-auto p-6 space-y-4">
            {/* Critical Overrides banner */}
            {exp.critical_overrides.length > 0 && (
              <div className="bg-red-50 border border-red-300 rounded-lg p-3">
                <p className="text-xs font-bold text-red-800 uppercase mb-1">Critical Override — Score forced to 100</p>
                {exp.critical_overrides.map((o, i) => (
                  <p key={i} className="text-xs text-red-700">{o.description}</p>
                ))}
              </div>
            )}

            {/* Component Breakdown */}
            <section>
              <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-3">Exposure Components</h3>
              <div className="space-y-2">
                {Object.entries(SPN_EXPOSURE_COMPONENTS).map(([key, cfg]) => {
                  const scoreKey = key === 'exposure' ? 'exposure' : key;
                  const val = (exp as Record<string, unknown>)[scoreKey];
                  return (
                    <ComponentBar
                      key={key}
                      label={cfg.label}
                      score={typeof val === 'number' ? val : 0}
                      max={cfg.max}
                      color={cfg.color}
                    />
                  );
                })}
              </div>
            </section>

            {/* Findings by component */}
            <section>
              <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-3">
                Findings ({detail.findings.length})
              </h3>
              {detail.findings.length === 0 ? (
                <p className="text-xs text-gray-400 italic">No findings generated</p>
              ) : (
                <div className="space-y-2">
                  {Object.entries(SPN_EXPOSURE_COMPONENTS).map(([compKey, compCfg]) => {
                    const compFindings = findingsByComponent[compKey] || [];
                    if (compFindings.length === 0) return null;
                    return (
                      <div key={compKey}>
                        <p className="text-[10px] font-bold text-gray-500 uppercase mb-1">{compCfg.label}</p>
                        {compFindings.map((f, i) => (
                          <div key={i} className={`border rounded-lg p-3 mb-1.5 ${PRIORITY_BADGE[f.severity] || PRIORITY_BADGE.info}`}>
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-medium">{f.title}</span>
                              <span className="text-[9px] font-bold">+{f.score_impact}</span>
                            </div>
                            <p className="text-[10px] mt-0.5 opacity-80">{f.description}</p>
                            <p className="text-[10px] mt-1 text-gray-600 italic">Fix: {f.remediation}</p>
                          </div>
                        ))}
                      </div>
                    );
                  })}
                </div>
              )}
            </section>

            {/* Activity Inference */}
            <section>
              <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-3">Activity Inference</h3>
              <div className="bg-gray-50 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-gray-600">Confidence</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${lcConfig.badgeClass}`}>
                    {detail.activity_inference.confidence}% — {lcConfig.label}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{
                      width: `${detail.activity_inference.confidence}%`,
                      backgroundColor: EXPOSURE_LEVEL_CONFIG[
                        detail.activity_inference.confidence >= 70 ? 'low' :
                        detail.activity_inference.confidence >= 40 ? 'medium' :
                        detail.activity_inference.confidence >= 15 ? 'high' : 'critical'
                      ].color,
                    }}
                  />
                </div>
                {detail.activity_inference.classification === 'blind' && (
                  <p className="text-[10px] text-gray-500 mt-2">
                    No sign-in telemetry available. This is a <strong>visibility gap</strong> — usage cannot be determined without enhanced logging.
                  </p>
                )}
              </div>
            </section>

            {/* Derived Flags */}
            <section>
              <h3 className="text-xs font-bold text-gray-600 uppercase tracking-wider mb-3">Identity Flags</h3>
              <div className="grid grid-cols-2 gap-2">
                <div className="flex items-center justify-between border rounded-md p-2">
                  <span className="text-xs text-gray-600">Scope</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${scopeConfig.badgeClass}`}>{scopeConfig.label}</span>
                </div>
                <div className="flex items-center justify-between border rounded-md p-2">
                  <span className="text-xs text-gray-600">Owner</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${ownerConfig.badgeClass}`}>{ownerConfig.label}</span>
                </div>
                <div className="flex items-center justify-between border rounded-md p-2">
                  <span className="text-xs text-gray-600">Can Escalate</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${exp.can_escalate ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`}>
                    {exp.can_escalate ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="flex items-center justify-between border rounded-md p-2">
                  <span className="text-xs text-gray-600">Cross-Sub</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${exp.cross_subscription ? 'bg-orange-100 text-orange-700' : 'bg-green-100 text-green-700'}`}>
                    {exp.cross_subscription ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="flex items-center justify-between border rounded-md p-2">
                  <span className="text-xs text-gray-600">Federated</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${exp.federated_trust ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-500'}`}>
                    {exp.federated_trust ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="flex items-center justify-between border rounded-md p-2">
                  <span className="text-xs text-gray-600">Cred Age</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${exp.credential_age_days > 365 ? 'bg-red-100 text-red-700' : exp.credential_age_days > 180 ? 'bg-yellow-100 text-yellow-700' : 'bg-gray-100 text-gray-500'}`}>
                    {exp.credential_age_days}d
                  </span>
                </div>
              </div>
            </section>

            {/* Recommendations */}
            {detail.recommendations.length > 0 && (
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
            )}
          </div>

          {/* Footer */}
          <div className="px-6 py-3 border-t border-gray-200 bg-gray-50 shrink-0 flex items-center gap-3">
            <button
              onClick={() => window.open(`/identities/${identity.identity_id as string}`, '_blank')}
              className="flex-1 text-xs text-center py-2 px-3 bg-blue-600 text-white rounded-md hover:bg-blue-700 font-medium"
            >
              Open Full Identity Detail
            </button>
            <button
              onClick={onClose}
              className="text-xs py-2 px-4 border border-gray-300 rounded-md hover:bg-gray-50 font-medium"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Main Component ───────────────────────────────────────────────

export default function SPNDashboard() {
  const location = useLocation();
  const { withConnection, selectedConnectionId } = useConnection();
  const { user, activeOrgId, activeOrgName } = useAuth();

  const [stats, setStats] = useState<SPNStats | null>(null);
  const [spns, setSpns] = useState<SPNRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [latestSnapshotId, setLatestSnapshotId] = useState<number | null>(null);
  const [initialized, setInitialized] = useState(false);

  // Filters
  const [exposureFilter, setExposureFilter] = useState('');
  const [lifecycleFilter, setLifecycleFilter] = useState('');
  const [ownerFilter, setOwnerFilter] = useState('');
  const [canEscalateFilter, setCanEscalateFilter] = useState(false);
  const [search, setSearch] = useState('');
  const [hideMicrosoft, setHideMicrosoft] = useState(true);
  const [sortField, setSortField] = useState<SortField>('exposure_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  // Detail modal
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<SPNDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Sync from URL
  useEffect(() => {
    const p = new URLSearchParams(location.search);
    if (p.get('exposure')) setExposureFilter(p.get('exposure') || '');
    if (p.get('lifecycle')) setLifecycleFilter(p.get('lifecycle') || '');
    if (p.get('owner')) setOwnerFilter(p.get('owner') || '');
    if (p.get('escalate') === 'true') setCanEscalateFilter(true);
    if (p.get('search')) setSearch(p.get('search') || '');
    setInitialized(true);
  }, [location.search]);

  // Fetch latest snapshot ID for export metadata
  useEffect(() => {
    fetch(withConnection('/api/runs'))
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        const runs = data?.runs || data || [];
        if (Array.isArray(runs) && runs.length > 0) setLatestSnapshotId(runs[0].id);
      })
      .catch(() => {});
  }, [withConnection]);

  // Fetch stats
  useEffect(() => {
    if (!initialized) return;
    fetch(withConnection('/api/spns/stats'))
      .then(r => r.json())
      .then(setStats)
      .catch(() => {});
  }, [initialized, selectedConnectionId, activeOrgId]);

  // Fetch SPN list
  useEffect(() => {
    if (!initialized) return;
    setLoading(true);
    const abort = new AbortController();
    const params = new URLSearchParams();
    params.set('limit', '500');
    params.set('hide_microsoft', hideMicrosoft ? 'true' : 'false');
    params.set('sort', sortField);
    params.set('dir', sortDir);
    if (exposureFilter) params.set('exposure_level', exposureFilter);
    if (lifecycleFilter) params.set('lifecycle_state', lifecycleFilter);
    if (ownerFilter) params.set('owner_status', ownerFilter);
    if (canEscalateFilter) params.set('can_escalate', 'true');
    if (search) params.set('search', search);

    fetch(withConnection(`/api/spns?${params}`), { signal: abort.signal })
      .then(r => r.json())
      .then(data => {
        setSpns(data.spns || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
    return () => abort.abort();
  }, [initialized, exposureFilter, lifecycleFilter, ownerFilter, canEscalateFilter, search, hideMicrosoft, sortField, sortDir, selectedConnectionId, activeOrgId]);

  // Fetch detail when selected
  useEffect(() => {
    if (!selectedId) { setDetail(null); return; }
    setDetailLoading(true);
    fetch(withConnection(`/api/spns/${selectedId}`))
      .then(r => r.json())
      .then(d => { setDetail(d); setDetailLoading(false); })
      .catch(() => setDetailLoading(false));
  }, [selectedId]);

  // Client-side sort
  const sorted = useMemo(() => {
    const arr = [...spns];
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortField === 'exposure_score') cmp = (a.exposure_score || 0) - (b.exposure_score || 0);
      else if (sortField === 'privilege_score') cmp = (a.privilege_score || 0) - (b.privilege_score || 0);
      else if (sortField === 'credential_risk_score') cmp = (a.credential_risk_score || 0) - (b.credential_risk_score || 0);
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
    else { setSortField(f); setSortDir('desc'); }
  }, [sortField]);

  // URL sync
  useEffect(() => {
    if (!initialized) return;
    const p = new URLSearchParams();
    if (exposureFilter) p.set('exposure', exposureFilter);
    if (lifecycleFilter) p.set('lifecycle', lifecycleFilter);
    if (ownerFilter) p.set('owner', ownerFilter);
    if (canEscalateFilter) p.set('escalate', 'true');
    if (search) p.set('search', search);
    const qs = p.toString();
    window.history.replaceState(null, '', qs ? `${window.location.pathname}?${qs}` : window.location.pathname);
  }, [exposureFilter, lifecycleFilter, ownerFilter, canEscalateFilter, search, initialized]);

  const clearFilters = () => {
    setExposureFilter(''); setLifecycleFilter(''); setOwnerFilter(''); setCanEscalateFilter(false); setSearch('');
  };
  const hasFilters = exposureFilter || lifecycleFilter || ownerFilter || canEscalateFilter || search;

  // CSV export
  const exportData = useMemo(() =>
    sorted.map(s => ({
      ...s,
      critical_roles: (s.critical_roles || []).join(', '),
    })),
    [sorted]
  );

  const SPN_CSV_COLS = useMemo(() => [
    { key: 'display_name', header: 'Name' },
    { key: 'exposure_score', header: 'Exposure Score' },
    { key: 'privilege_score', header: 'Privilege (/40)' },
    { key: 'credential_risk_score', header: 'Credential Risk (/25)' },
    { key: 'lifecycle_state', header: 'Lifecycle State' },
    { key: 'owner_status', header: 'Owner Status' },
    { key: 'effective_scope_flag', header: 'Scope' },
    { key: 'can_escalate', header: 'Can Escalate' },
    { key: 'cross_subscription', header: 'Cross-Sub' },
    { key: 'risk_level', header: 'Risk Level' },
    { key: 'blast_radius', header: 'Blast Radius' },
    { key: 'credential_risk', header: 'Credential Risk' },
    { key: 'identity_id', header: 'Identity ID' },
  ], []);

  const handleCSVExport = useCallback(() => {
    const meta = buildExportMeta(latestSnapshotId, activeOrgId ?? user?.organization_id ?? null, activeOrgName ?? user?.org_name ?? null);
    downloadCSV(
      exportData as unknown as Record<string, unknown>[],
      SPN_CSV_COLS,
      exportFilename('spn-exposure-audit', 'csv'),
      meta
    );
  }, [exportData, SPN_CSV_COLS, latestSnapshotId, activeOrgId, activeOrgName, user]);

  const [pdfGenerating, setPdfGenerating] = useState(false);

  const handlePDFExport = useCallback(async () => {
    if (!stats) return;
    setPdfGenerating(true);
    try {
      const critSpns = [...spns]
        .sort((a, b) => (b.exposure_score || 0) - (a.exposure_score || 0))
        .slice(0, 10);

      const details = await Promise.all(
        critSpns.map(s =>
          fetch(withConnection(`/api/spns/${s.identity_id}`))
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

  // Count of critical exposure for banner
  const criticalExposureCount = stats?.exposure_critical || 0;
  const [bannerDismissed, setBannerDismissed] = useState(false);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Workload Identity Exposure</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            SPNs, managed identities, workload credentials — attack-based exposure scoring
          </p>
          <SnapshotContextHeader snapshotId={latestSnapshotId} />
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
            Export CSV
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

      {/* Export Metadata Strip */}
      {latestSnapshotId && (
        <div className="flex items-center gap-4 text-[10px] text-gray-500 border border-gray-200 rounded-lg px-3 py-1.5 bg-gray-50">
          <span className="font-semibold uppercase tracking-wide text-gray-400">Export Metadata</span>
          <span>Snapshot: <span className="font-mono font-semibold text-gray-700">#{latestSnapshotId}</span></span>
          <span>Organization: <span className="font-mono font-semibold text-gray-700">{activeOrgId ?? user?.organization_id ?? 'N/A'}</span></span>
          <span>Schema: <span className="font-mono font-semibold text-gray-700">v1.0</span></span>
        </div>
      )}

      {/* Critical Exposure Banner */}
      {!bannerDismissed && criticalExposureCount > 0 && (
        <div className="bg-red-50 border border-red-300 rounded-lg px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-red-600 text-lg font-bold">!</span>
            <div>
              <p className="text-sm font-bold text-red-800">
                {criticalExposureCount} workload {criticalExposureCount === 1 ? 'identity' : 'identities'} at critical exposure
              </p>
              <p className="text-xs text-red-600 mt-0.5">
                Exposure score {'\u2265'}80 — immediate remediation recommended
              </p>
            </div>
          </div>
          <button onClick={() => setBannerDismissed(true)} className="text-red-400 hover:text-red-600 text-xs font-medium">
            Dismiss
          </button>
        </div>
      )}

      {/* 5 Exposure Cards */}
      {stats && (
        <div className="grid grid-cols-5 gap-3">
          <ExposureCard
            label="Critical Exposure"
            value={stats.exposure_critical}
            color={stats.exposure_critical > 0 ? 'red' : 'green'}
            subtitle={`Score \u226580 | Avg: ${stats.avg_exposure_score}`}
            onClick={() => setExposureFilter(exposureFilter === 'critical' ? '' : 'critical')}
            active={exposureFilter === 'critical'}
          />
          <ExposureCard
            label="Can Escalate"
            value={stats.can_escalate_count}
            color={stats.can_escalate_count > 0 ? 'red' : 'green'}
            subtitle="Tenant admin or sub owner"
            onClick={() => setCanEscalateFilter(!canEscalateFilter)}
            active={canEscalateFilter}
          />
          <ExposureCard
            label="Orphaned & Privileged"
            value={stats.orphaned_privileged}
            color={stats.orphaned_privileged > 0 ? 'orange' : 'green'}
            subtitle="No owner + privileged roles"
            onClick={() => setOwnerFilter(ownerFilter === 'orphaned' ? '' : 'orphaned')}
            active={ownerFilter === 'orphaned'}
          />
          <ExposureCard
            label="Visibility Gap"
            value={stats.blind_count}
            color={stats.blind_count > 0 ? 'gray' : 'green'}
            subtitle="No sign-in telemetry"
            onClick={() => setLifecycleFilter(lifecycleFilter === 'blind' ? '' : 'blind')}
            active={lifecycleFilter === 'blind'}
          />
          <ExposureCard
            label="Cross-Subscription"
            value={stats.cross_sub_count}
            color={stats.cross_sub_count > 0 ? 'purple' : 'green'}
            subtitle="Roles in 2+ subscriptions"
          />
        </div>
      )}

      {/* Filters bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <select value={exposureFilter} onChange={e => setExposureFilter(e.target.value)} className="text-xs border border-gray-300 rounded-md px-2 py-1.5">
          <option value="">All Exposure Levels</option>
          <option value="critical">Critical ({'\u2265'}80)</option>
          <option value="high">High (60-79)</option>
          <option value="medium">Medium (35-59)</option>
          <option value="low">Low ({'<'}35)</option>
        </select>

        <select value={lifecycleFilter} onChange={e => setLifecycleFilter(e.target.value)} className="text-xs border border-gray-300 rounded-md px-2 py-1.5">
          <option value="">All Lifecycle States</option>
          {Object.entries(LIFECYCLE_STATE_CONFIG).map(([k, v]) => (
            <option key={k} value={k}>{v.label}</option>
          ))}
        </select>

        <select value={ownerFilter} onChange={e => setOwnerFilter(e.target.value)} className="text-xs border border-gray-300 rounded-md px-2 py-1.5">
          <option value="">All Owner Status</option>
          {Object.entries(OWNER_STATUS_CONFIG).map(([k, v]) => (
            <option key={k} value={k}>{v.label}</option>
          ))}
        </select>

        <label className="flex items-center gap-1 text-xs text-gray-600">
          <input
            type="checkbox"
            checked={canEscalateFilter}
            onChange={e => setCanEscalateFilter(e.target.checked)}
            className="rounded border-gray-300"
          />
          Can Escalate
        </label>

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

        <span className="text-xs text-gray-500 ml-auto">{sorted.length} workload identities</span>
      </div>

      {/* Table */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-gray-50 border-b border-gray-200 text-gray-600 uppercase tracking-wider font-medium">
              <tr>
                <SortHeader label="Name" field="display_name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Exposure" field="exposure_score" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Privilege (/40)" field="privilege_score" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Cred Risk (/25)" field="credential_risk_score" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <th className="px-3 py-2.5 text-xs">Lifecycle</th>
                <th className="px-3 py-2.5 text-xs">Owner</th>
                <th className="px-3 py-2.5 text-xs">Scope</th>
                <th className="px-3 py-2.5 text-xs w-6"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading ? (
                <tr><td colSpan={8} className="px-3 py-8 text-center text-gray-400">Loading workload identities...</td></tr>
              ) : sorted.length === 0 ? (
                <tr><td colSpan={8} className="px-3 py-8 text-center text-gray-400">No workload identities found. Capture a snapshot to populate.</td></tr>
              ) : sorted.map(spn => {
                const lcCfg = LIFECYCLE_STATE_CONFIG[spn.lifecycle_state] || LIFECYCLE_STATE_CONFIG.blind;
                const owCfg = OWNER_STATUS_CONFIG[spn.owner_status] || OWNER_STATUS_CONFIG.unknown;
                const scCfg = SCOPE_FLAG_CONFIG[spn.effective_scope_flag] || SCOPE_FLAG_CONFIG.resource;
                const privPct = spn.privilege_score > 0 ? Math.min((spn.privilege_score / 40) * 100, 100) : 0;
                const credPct = spn.credential_risk_score > 0 ? Math.min((spn.credential_risk_score / 25) * 100, 100) : 0;

                return (
                  <tr
                    key={spn.identity_id}
                    className={`hover:bg-blue-50/40 cursor-pointer transition-colors ${selectedId === spn.identity_id ? 'bg-blue-50' : ''}`}
                    onClick={() => setSelectedId(selectedId === spn.identity_id ? null : spn.identity_id)}
                  >
                    <td className="px-3 py-2 max-w-[200px]">
                      <div className="font-medium text-gray-900 truncate" title={spn.display_name}>{spn.display_name}</div>
                      <div className="flex items-center gap-1 mt-0.5">
                        {!!spn.can_escalate && <span className="px-1 py-0 rounded text-[8px] font-bold bg-red-600 text-white">ESC</span>}
                        {!!spn.cross_subscription && <span className="px-1 py-0 rounded text-[8px] font-semibold bg-purple-100 text-purple-700">X-SUB</span>}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <ExposureRing score={spn.exposure_score || 0} />
                    </td>
                    <td className="px-3 py-2">
                      <div className="w-20 h-2 bg-gray-100 rounded-full overflow-hidden" title={`${spn.privilege_score}/40`}>
                        <div className="h-full rounded-full bg-red-400" style={{ width: `${privPct}%` }} />
                      </div>
                      <span className="text-[10px] text-gray-400 font-mono">{spn.privilege_score}/40</span>
                    </td>
                    <td className="px-3 py-2">
                      <div className="w-16 h-2 bg-gray-100 rounded-full overflow-hidden" title={`${spn.credential_risk_score}/25`}>
                        <div className="h-full rounded-full bg-orange-400" style={{ width: `${credPct}%` }} />
                      </div>
                      <span className="text-[10px] text-gray-400 font-mono">{spn.credential_risk_score}/25</span>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${lcCfg.badgeClass}`} title={lcCfg.tooltip}>
                        {lcCfg.label}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${owCfg.badgeClass}`}>
                        {owCfg.label}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${scCfg.badgeClass}`}>
                        {scCfg.label}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-gray-400">{'\u2192'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Risk Breakdown Modal */}
      {selectedId && detail && !detailLoading && (
        <RiskBreakdownModal detail={detail} onClose={() => setSelectedId(null)} />
      )}
      {selectedId && detailLoading && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/20">
          <div className="animate-spin h-8 w-8 border-2 border-blue-600 border-t-transparent rounded-full" />
        </div>
      )}
    </div>
  );
}
