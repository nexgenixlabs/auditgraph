import React, { useEffect, useState, useMemo, useCallback, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { RISK_BADGE, safeLower, TIME_MS } from '../constants/metrics';
// AG-POLISH-D (2026-06-10)
import { TableSkeletonRow, LoadingState } from '../components/LoadingState';
import { downloadCSV, exportFilename, buildExportMeta } from '../utils/exportUtils';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import { SnapshotContextHeader } from '../components/ui/SnapshotContextHeader';
import { normalizeScore } from '../utils/identityRiskScore';

// ─── Types ────────────────────────────────────────────────────────

interface AppRegRow {
  id: number;
  app_id: string;
  app_object_id: string;
  display_name: string;
  risk_level: string;
  risk_score: number;
  permission_count: number;
  application_permission_count: number;
  delegated_permission_count: number;
  high_risk_permissions: string[];
  secret_count: number;
  certificate_count: number;
  next_expiry: string | null;
  has_expired_credential: boolean;
  has_expiring_soon: boolean;
  owner_count: number;
  primary_owner: string | null;
  sign_in_audience: string;
  is_third_party: boolean;
  has_service_principal: boolean;
  spn_activity_status: string | null;
  created_datetime: string | null;
}

interface AppRegStats {
  total: number;
  by_risk: Record<string, number>;
  ownerless: number;
  stale: number;
  no_spn: number;
  expired_credentials: number;
  expiring_soon: number;
  multi_tenant: number;
  third_party: number;
  by_audience: Record<string, number>;
}

interface Recommendation {
  priority: string;
  action: string;
  reason: string;
}

interface AppRegDetail {
  app_registration: Record<string, unknown>;
  linked_spn: { id: number; identity_id?: string; display_name: string; identity_category: string; risk_level: string; activity_status: string } | null;
  recommendations: Recommendation[];
}

type SortField = 'risk_score' | 'display_name' | 'permission_count' | 'application_permission_count' | 'owner_count' | 'next_expiry' | 'created_datetime';

// ─── Badge Maps ──────────────────────────────────────────────────

const AUDIENCE_BADGE: Record<string, string> = {
  AzureADMyOrg: 'bg-green-100 text-green-700',
  AzureADMultipleOrgs: 'bg-orange-100 text-orange-700',
  AzureADandPersonalMicrosoftAccount: 'bg-red-100 text-red-700',
  PersonalMicrosoftAccount: 'bg-purple-100 text-purple-700',
};

const AUDIENCE_LABEL: Record<string, string> = {
  AzureADMyOrg: 'Single Tenant',
  AzureADMultipleOrgs: 'Multi-Tenant',
  AzureADandPersonalMicrosoftAccount: 'Multi + Personal',
  PersonalMicrosoftAccount: 'Personal Only',
};

const CRED_RISK_BADGE: Record<string, string> = {
  expired: 'bg-red-100 text-red-700',
  expiring_soon: 'bg-yellow-100 text-yellow-700',
  healthy: 'bg-green-100 text-green-700',
  none: 'bg-gray-100 text-gray-500',
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
    blue: 'bg-blue-50 border-blue-200 text-blue-700 dark:bg-blue-950/40 dark:border-blue-800 dark:text-blue-300',
    red: 'bg-red-50 border-red-200 text-red-700 dark:bg-red-950/40 dark:border-red-800 dark:text-red-300',
    orange: 'bg-orange-50 border-orange-200 text-orange-700 dark:bg-orange-950/40 dark:border-orange-800 dark:text-orange-300',
    yellow: 'bg-yellow-50 border-yellow-200 text-yellow-700 dark:bg-yellow-950/40 dark:border-yellow-800 dark:text-yellow-300',
    green: 'bg-green-50 border-green-200 text-green-700 dark:bg-green-950/40 dark:border-green-800 dark:text-green-300',
    purple: 'bg-purple-50 border-purple-200 text-purple-700 dark:bg-purple-950/40 dark:border-purple-800 dark:text-purple-300',
    gray: 'bg-gray-50 border-gray-200 text-gray-600 dark:bg-gray-800/40 dark:border-gray-700 dark:text-gray-300',
  };
  return (
    <div
      onClick={onClick}
      className={`border rounded-lg p-3 ${colorMap[color] || colorMap.blue} ${onClick ? 'cursor-pointer hover:shadow-sm transition-shadow' : ''} ${active ? 'ring-2 ring-blue-500 ring-offset-1' : ''}`}
    >
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>{label}</div>
      {subtitle && <div className="text-[10px] mt-0.5" style={{ color: 'var(--text-tertiary, var(--text-secondary))' }}>{subtitle}</div>}
    </div>
  );
}

function SortHeader({ label, field, currentField, currentDir, onSort }: {
  label: string; field: SortField; currentField: SortField; currentDir: 'asc' | 'desc'; onSort: (f: SortField) => void;
}) {
  const isActive = currentField === field;
  return (
    <th className="px-3 py-2.5 cursor-pointer select-none hover:bg-gray-100 dark:hover:bg-slate-700 whitespace-nowrap text-xs" onClick={() => onSort(field)}>
      <div className="flex items-center gap-0.5">
        <span>{label}</span>
        <span className={`text-[10px] ${isActive ? 'text-blue-600' : 'text-gray-400'}`}>
          {isActive ? (currentDir === 'asc' ? '\u25B2' : '\u25BC') : '\u2195'}
        </span>
      </div>
    </th>
  );
}

function daysUntil(iso: string | null): string {
  if (!iso) return '\u2014';
  const d = Math.ceil((new Date(iso).getTime() - Date.now()) / TIME_MS.DAY);
  if (d < 0) return `${Math.abs(d)}d ago`;
  if (d === 0) return 'Today';
  return `${d}d`;
}

function credStatus(row: AppRegRow): { label: string; key: string } {
  if (row.has_expired_credential) return { label: 'Expired', key: 'expired' };
  if (row.has_expiring_soon) return { label: 'Expiring', key: 'expiring_soon' };
  if (row.secret_count + row.certificate_count > 0) return { label: 'Healthy', key: 'healthy' };
  return { label: 'None', key: 'none' };
}

// ─── Drill-Down Panel ─────────────────────────────────────────────

function AppRegDrillDown({ detail, onClose }: { detail: AppRegDetail; onClose: () => void }) {
  const app = detail.app_registration;
  const name = (app.display_name as string) || 'Unknown';
  const riskReasons = (app.risk_reasons as string[]) || [];
  const credDetails = (app.credential_details as Array<Record<string, unknown>>) || [];
  const owners = (app.owners as Array<Record<string, unknown>>) || [];
  const redirectUris = (app.redirect_uris as string[]) || [];
  const highRiskPerms = (app.high_risk_permissions as string[]) || [];

  return (
    <div className="fixed inset-y-0 right-0 w-[480px] shadow-lg border-l z-50 flex flex-col overflow-hidden" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-default)' }}>
      {/* Header */}
      <div className="px-5 py-4 border-b flex items-center justify-between shrink-0" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-elevated, var(--bg-primary))' }}>
        <div>
          <h2 className="text-base font-bold truncate max-w-[320px]" style={{ color: 'var(--text-primary)' }} title={name}>{name}</h2>
          <div className="flex items-center gap-2 mt-1">
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[safeLower(app.risk_level as string)] || 'bg-gray-100 text-gray-600'}`}>
              {(app.risk_level as string) || 'info'}
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${AUDIENCE_BADGE[(app.sign_in_audience as string)] || 'bg-gray-100 text-gray-600'}`}>
              {AUDIENCE_LABEL[(app.sign_in_audience as string)] || (app.sign_in_audience as string) || 'Unknown'}
            </span>
          </div>
        </div>
        <button onClick={onClose} className="text-lg font-bold" style={{ color: 'var(--text-secondary)' }}>x</button>
      </div>

      {/* Scrollable content */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Risk Summary */}
        {riskReasons.length > 0 && (
          <section>
            <h3 className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-secondary)' }}>Risk Summary</h3>
            <div className="bg-red-50 border border-red-200 rounded-lg p-3 space-y-1">
              {riskReasons.map((point, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-red-800">
                  <span className="mt-0.5 shrink-0">!</span>
                  <span>{point}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* App Details */}
        <section>
          <h3 className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-secondary)' }}>App Details</h3>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
            <span style={{ color: 'var(--text-secondary)' }}>App ID</span>
            <span className="font-mono text-[10px] break-all">{(app.app_id as string) || '\u2014'}</span>
            <span style={{ color: 'var(--text-secondary)' }}>Object ID</span>
            <span className="font-mono text-[10px] break-all">{(app.app_object_id as string) || '\u2014'}</span>
            <span style={{ color: 'var(--text-secondary)' }}>Created</span>
            <span>{app.created_datetime ? new Date(app.created_datetime as string).toLocaleDateString() : '\u2014'}</span>
            <span style={{ color: 'var(--text-secondary)' }}>Publisher Domain</span>
            <span>{(app.publisher_domain as string) || '\u2014'}</span>
            <span style={{ color: 'var(--text-secondary)' }}>Audience</span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${AUDIENCE_BADGE[(app.sign_in_audience as string)] || 'bg-gray-100 text-gray-600'}`}>
              {AUDIENCE_LABEL[(app.sign_in_audience as string)] || (app.sign_in_audience as string) || 'Unknown'}
            </span>
            <span style={{ color: 'var(--text-secondary)' }}>Third-Party</span>
            <span>{app.is_third_party ? 'Yes' : 'No'}</span>
            <span style={{ color: 'var(--text-secondary)' }}>Approval Status</span>
            <span className="capitalize">{(app.approval_status as string) || 'unknown'}</span>
          </div>
        </section>

        {/* Permissions */}
        <section>
          <h3 className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-secondary)' }}>
            Permissions ({(app.permission_count as number) || 0})
          </h3>
          <div className="grid grid-cols-2 gap-3 mb-2">
            <div className="border border-orange-200 bg-orange-50 rounded-md p-2.5 text-center">
              <div className="text-lg font-bold text-orange-700">{(app.application_permission_count as number) || 0}</div>
              <div className="text-[10px] text-orange-600 font-medium">Application</div>
            </div>
            <div className="border border-blue-200 bg-blue-50 rounded-md p-2.5 text-center">
              <div className="text-lg font-bold text-blue-700">{(app.delegated_permission_count as number) || 0}</div>
              <div className="text-[10px] text-blue-600 font-medium">Delegated</div>
            </div>
          </div>
          {highRiskPerms.length > 0 && (
            <div className="space-y-1">
              <div className="text-[10px] font-semibold text-red-600 uppercase">High-Risk Permissions</div>
              {highRiskPerms.map((p, i) => (
                <div key={i} className="flex items-center gap-1.5 text-xs">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" />
                  <span className="text-red-800 font-mono text-[10px]">{p}</span>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Credentials */}
        <section>
          <h3 className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-secondary)' }}>
            Credentials ({(app.secret_count as number || 0) + (app.certificate_count as number || 0)})
          </h3>
          {credDetails.length === 0 ? (
            <p className="text-xs italic" style={{ color: 'var(--text-secondary)' }}>No credentials</p>
          ) : (
            <div className="space-y-2">
              {credDetails.map((c, i) => {
                const endDate = c.end as string | null;
                const isExpired = endDate ? new Date(endDate) < new Date() : false;
                return (
                  <div key={i} className={`border rounded-md p-2.5 text-xs ${isExpired ? 'border-red-200 bg-red-50/50 dark:border-red-800 dark:bg-red-950/30' : ''}`} style={isExpired ? undefined : { borderColor: 'var(--border-default)' }}>
                    <div className="flex items-center justify-between">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
                        (c.type as string) === 'secret' ? 'bg-orange-100 text-orange-700' : 'bg-blue-100 text-blue-700'
                      }`}>{(c.type as string) || '?'}</span>
                      <span className={`text-[10px] font-semibold ${isExpired ? 'text-red-600' : ''}`} style={isExpired ? undefined : { color: 'var(--text-secondary)' }}>
                        {endDate ? (isExpired ? 'EXPIRED' : `Expires ${daysUntil(endDate)}`) : 'No expiry'}
                      </span>
                    </div>
                    {!!c.display_name && <div className="mt-1 truncate" style={{ color: 'var(--text-primary)' }}>{c.display_name as string}</div>}
                    <div className="text-[10px] mt-0.5 font-mono truncate" style={{ color: 'var(--text-secondary)' }}>
                      Key: {((c.key_id as string) || '').slice(0, 16)}...
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* Owners */}
        <section>
          <h3 className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-secondary)' }}>
            Owners ({owners.length})
          </h3>
          {owners.length === 0 ? (
            <div className="bg-orange-50 border border-orange-200 rounded-md p-3">
              <p className="text-xs text-orange-700 font-semibold">No registered owner</p>
              <p className="text-[10px] text-orange-600 mt-0.5">This app has no accountability for credential rotation or security review.</p>
            </div>
          ) : (
            <div className="space-y-1">
              {owners.map((o, i) => (
                <div key={i} className="text-xs border rounded p-2" style={{ borderColor: 'var(--border-default)' }}>
                  <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{o.display_name as string}</span>
                  {!!o.upn && <span className="ml-2 text-[10px]" style={{ color: 'var(--text-secondary)' }}>{o.upn as string}</span>}
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Redirect URIs */}
        {redirectUris.length > 0 && (
          <section>
            <h3 className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-secondary)' }}>
              Redirect URIs ({redirectUris.length})
            </h3>
            <div className="space-y-1">
              {redirectUris.map((uri, i) => {
                const isLocalhost = uri.toLowerCase().includes('localhost') || uri.includes('127.0.0.1');
                const isHttp = uri.toLowerCase().startsWith('http://') && !isLocalhost;
                return (
                  <div key={i} className={`text-xs border rounded p-2 font-mono text-[10px] break-all ${
                    isLocalhost ? 'border-yellow-200 bg-yellow-50 text-yellow-800 dark:border-yellow-800 dark:bg-yellow-950/30 dark:text-yellow-300' :
                    isHttp ? 'border-red-200 bg-red-50 text-red-800 dark:border-red-800 dark:bg-red-950/30 dark:text-red-300' :
                    ''
                  }`} style={(!isLocalhost && !isHttp) ? { borderColor: 'var(--border-default)', color: 'var(--text-primary)' } : undefined}>
                    {uri}
                    {isLocalhost && <span className="ml-2 text-yellow-600 font-sans font-semibold">[localhost]</span>}
                    {isHttp && <span className="ml-2 text-red-600 font-sans font-semibold">[HTTP]</span>}
                  </div>
                );
              })}
            </div>
          </section>
        )}

        {/* Linked SPN */}
        <section>
          <h3 className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-secondary)' }}>Linked Service Principal</h3>
          {detail.linked_spn ? (
            <div className="border rounded-md p-3 text-xs" style={{ borderColor: 'var(--border-default)' }}>
              <div className="flex items-center justify-between">
                <span className="font-medium" style={{ color: 'var(--text-primary)' }}>{detail.linked_spn.display_name}</span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${ACTIVITY_BADGE[safeLower(detail.linked_spn.activity_status)] || ACTIVITY_BADGE.unknown}`}>
                  {detail.linked_spn.activity_status || 'unknown'}
                </span>
              </div>
              <button
                onClick={() => window.open(`/identities/${detail.linked_spn!.identity_id || detail.linked_spn!.id}`, '_blank')}
                className="mt-2 text-[10px] text-blue-600 hover:text-blue-800 font-medium"
              >
                Open SPN Detail &rarr;
              </button>
            </div>
          ) : (
            <div className="border rounded-md p-3" style={{ backgroundColor: 'var(--bg-elevated, var(--bg-primary))', borderColor: 'var(--border-default)' }}>
              <p className="text-xs italic" style={{ color: 'var(--text-secondary)' }}>No Service Principal — this app has never been consented or used.</p>
            </div>
          )}
        </section>

        {/* Recommendations */}
        {detail.recommendations.length > 0 && (
          <section>
            <h3 className="text-xs font-bold uppercase tracking-wider mb-2" style={{ color: 'var(--text-secondary)' }}>Recommendations</h3>
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
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────

export default function AppRegistrations() {
  const location = useLocation();
  const { withConnection, selectedConnectionId } = useConnection();
  const { user, activeOrgId, activeOrgName } = useAuth();

  const [stats, setStats] = useState<AppRegStats | null>(null);
  const [items, setItems] = useState<AppRegRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [latestSnapshotId, setLatestSnapshotId] = useState<number | null>(null);
  const [initialized, setInitialized] = useState(false);

  // Filters
  const [riskFilter, setRiskFilter] = useState('');
  const [credFilter, setCredFilter] = useState('');
  const [audienceFilter, setAudienceFilter] = useState('');
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const searchTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => {
    searchTimerRef.current = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(searchTimerRef.current);
  }, [search]);
  const [sortField, setSortField] = useState<SortField>('risk_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  // Drill-down
  const [selectedAppId, setSelectedAppId] = useState<string | null>(null);
  const [detail, setDetail] = useState<AppRegDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Sync from URL
  useEffect(() => {
    const p = new URLSearchParams(location.search);
    if (p.get('risk')) setRiskFilter(p.get('risk') || '');
    if (p.get('cred')) setCredFilter(p.get('cred') || '');
    if (p.get('audience')) setAudienceFilter(p.get('audience') || '');
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
    fetch(withConnection('/api/app-registrations/stats'))
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setStats(d))
      .catch(() => {});
  }, [initialized, selectedConnectionId, activeOrgId]);

  // Fetch list
  useEffect(() => {
    if (!initialized) return;
    setLoading(true);
    const abort = new AbortController();
    const params = new URLSearchParams();
    params.set('limit', '500');
    params.set('sort', sortField);
    params.set('dir', sortDir);
    if (riskFilter) params.set('risk_level', riskFilter);
    if (credFilter) params.set('credential_status', credFilter);
    if (audienceFilter) params.set('audience', audienceFilter);
    if (debouncedSearch) params.set('search', debouncedSearch);

    fetch(withConnection(`/api/app-registrations?${params}`), { signal: abort.signal })
      .then(r => r.ok ? r.json() : { items: [], total: 0 })
      .then(data => {
        setItems(data.items || []);
        setTotal(data.total || 0);
        setLoading(false);
      })
      .catch(() => setLoading(false));
    return () => abort.abort();
  }, [initialized, riskFilter, credFilter, audienceFilter, debouncedSearch, sortField, sortDir, selectedConnectionId, activeOrgId]);

  // Fetch detail when selected
  useEffect(() => {
    if (!selectedAppId) { setDetail(null); return; }
    setDetailLoading(true);
    fetch(withConnection(`/api/app-registrations/${selectedAppId}`))
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setDetail(d); setDetailLoading(false); })
      .catch(() => setDetailLoading(false));
  }, [selectedAppId]);

  // Client-side sort
  const sorted = useMemo(() => {
    const arr = [...items];
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortField === 'risk_score') cmp = (a.risk_score || 0) - (b.risk_score || 0);
      else if (sortField === 'next_expiry') {
        const at = a.next_expiry ? new Date(a.next_expiry).getTime() : Infinity;
        const bt = b.next_expiry ? new Date(b.next_expiry).getTime() : Infinity;
        cmp = at - bt;
      } else if (sortField === 'permission_count' || sortField === 'application_permission_count' || sortField === 'owner_count') {
        cmp = ((a as unknown as Record<string, number>)[sortField] || 0) - ((b as unknown as Record<string, number>)[sortField] || 0);
      } else {
        const av = String((a as unknown as Record<string, unknown>)[sortField] || '').toLowerCase();
        const bv = String((b as unknown as Record<string, unknown>)[sortField] || '').toLowerCase();
        cmp = av.localeCompare(bv);
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return arr;
  }, [items, sortField, sortDir]);

  const handleSort = useCallback((f: SortField) => {
    if (f === sortField) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortField(f); setSortDir(f === 'risk_score' || f === 'permission_count' ? 'desc' : 'asc'); }
  }, [sortField]);

  // URL sync
  useEffect(() => {
    if (!initialized) return;
    const p = new URLSearchParams();
    if (riskFilter) p.set('risk', riskFilter);
    if (credFilter) p.set('cred', credFilter);
    if (audienceFilter) p.set('audience', audienceFilter);
    if (search) p.set('search', search);
    const qs = p.toString();
    window.history.replaceState(null, '', qs ? `${window.location.pathname}?${qs}` : window.location.pathname);
  }, [riskFilter, credFilter, audienceFilter, search, initialized]);

  const clearFilters = () => {
    setRiskFilter(''); setCredFilter(''); setAudienceFilter(''); setSearch('');
  };
  const hasFilters = riskFilter || credFilter || audienceFilter || search;

  // CSV export
  const CSV_COLS = useMemo(() => [
    { key: 'display_name', header: 'Name' },
    { key: 'risk_level', header: 'Risk Level' },
    { key: 'risk_score', header: 'Risk Score' },
    { key: 'application_permission_count', header: 'App Permissions' },
    { key: 'delegated_permission_count', header: 'Delegated Permissions' },
    { key: 'high_risk_permissions', header: 'High-Risk Permissions' },
    { key: 'secret_count', header: 'Secrets' },
    { key: 'certificate_count', header: 'Certificates' },
    { key: 'next_expiry', header: 'Next Expiry' },
    { key: 'owner_count', header: 'Owner Count' },
    { key: 'primary_owner', header: 'Primary Owner' },
    { key: 'sign_in_audience', header: 'Audience' },
    { key: 'has_service_principal', header: 'Has SPN' },
    { key: 'spn_activity_status', header: 'SPN Activity' },
    { key: 'created_datetime', header: 'Created' },
    { key: 'app_id', header: 'App ID' },
  ], []);

  const exportData = useMemo(() =>
    sorted.map(s => ({
      ...s,
      high_risk_permissions: (s.high_risk_permissions || []).join(', '),
    })),
    [sorted]
  );

  const handleCSVExport = useCallback(() => {
    const meta = buildExportMeta(latestSnapshotId, activeOrgId ?? user?.organization_id ?? null, activeOrgName ?? user?.org_name ?? null);
    downloadCSV(
      exportData as unknown as Record<string, unknown>[],
      CSV_COLS,
      exportFilename('app-registrations-audit', 'csv'),
      meta
    );
  }, [exportData, CSV_COLS, latestSnapshotId, activeOrgId, activeOrgName, user]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>App Registrations</h1>
          <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary)' }}>
            Entra ID application definitions — permissions, credentials, ownership audit
          </p>
          <SnapshotContextHeader snapshotId={latestSnapshotId} />
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleCSVExport}
            disabled={sorted.length === 0}
            className="px-3 py-1.5 text-xs font-medium rounded-md border disabled:opacity-40"
            style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)', borderColor: 'var(--border-default)' }}
          >
            Export CSV
          </button>
        </div>
      </div>

      {/* Export Metadata Strip */}
      {latestSnapshotId && (
        <div className="flex items-center gap-4 text-[10px] border rounded-lg px-3 py-1.5" style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-tertiary, var(--bg-secondary))' }}>
          <span className="font-semibold uppercase tracking-wide" style={{ color: 'var(--text-tertiary, var(--text-secondary))' }}>Export Metadata</span>
          <span>Snapshot: <span className="font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>#{latestSnapshotId}</span></span>
          <span>Organization: <span className="font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>{activeOrgId ?? user?.organization_id ?? 'N/A'}</span></span>
          <span>Schema: <span className="font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>v1.0</span></span>
        </div>
      )}

      {/* Summary Cards */}
      {stats && (
        <div className="grid grid-cols-5 gap-3">
          <StatCard
            label="Total App Registrations"
            value={stats.total}
            color="blue"
            onClick={() => { setRiskFilter(''); setCredFilter(''); setAudienceFilter(''); setSearch(''); }}
          />
          <StatCard
            label="Critical / High Risk"
            value={(stats.by_risk.critical || 0) + (stats.by_risk.high || 0)}
            color={(stats.by_risk.critical || 0) + (stats.by_risk.high || 0) > 0 ? 'red' : 'green'}
            subtitle={`${stats.by_risk.critical || 0} critical, ${stats.by_risk.high || 0} high`}
            onClick={() => setRiskFilter(riskFilter === 'critical' ? '' : 'critical')}
            active={riskFilter === 'critical'}
          />
          <StatCard
            label="Ownerless"
            value={stats.ownerless}
            color={stats.ownerless > 0 ? 'orange' : 'green'}
            subtitle="No registered owner"
            onClick={() => setSearch(search === 'ownerless' ? '' : 'ownerless')}
          />
          <StatCard
            label="Expired Credentials"
            value={stats.expired_credentials}
            color={stats.expired_credentials > 0 ? 'red' : 'green'}
            subtitle={stats.expiring_soon > 0 ? `${stats.expiring_soon} expiring soon` : undefined}
            onClick={() => setCredFilter(credFilter === 'expired' ? '' : 'expired')}
            active={credFilter === 'expired'}
          />
          <StatCard
            label="Multi-Tenant"
            value={stats.multi_tenant}
            color={stats.multi_tenant > 0 ? 'purple' : 'gray'}
            subtitle={stats.third_party > 0 ? `${stats.third_party} third-party` : undefined}
            onClick={() => setAudienceFilter(audienceFilter === 'AzureADMultipleOrgs' ? '' : 'AzureADMultipleOrgs')}
            active={audienceFilter === 'AzureADMultipleOrgs'}
          />
        </div>
      )}

      {/* Filter Bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <select
          value={riskFilter}
          onChange={e => setRiskFilter(e.target.value)}
          className="border rounded-md px-2.5 py-1.5 text-xs" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)', borderColor: 'var(--border-default)' }}
        >
          <option value="">All Risk Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>

        <select
          value={credFilter}
          onChange={e => setCredFilter(e.target.value)}
          className="border rounded-md px-2.5 py-1.5 text-xs" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)', borderColor: 'var(--border-default)' }}
        >
          <option value="">All Credentials</option>
          <option value="expired">Expired</option>
          <option value="expiring">Expiring Soon</option>
          <option value="healthy">Healthy</option>
        </select>

        <select
          value={audienceFilter}
          onChange={e => setAudienceFilter(e.target.value)}
          className="border rounded-md px-2.5 py-1.5 text-xs" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)', borderColor: 'var(--border-default)' }}
        >
          <option value="">All Audiences</option>
          <option value="AzureADMyOrg">Single Tenant</option>
          <option value="AzureADMultipleOrgs">Multi-Tenant</option>
          <option value="AzureADandPersonalMicrosoftAccount">Multi + Personal</option>
        </select>

        <input
          type="text"
          placeholder="Search by name..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="border rounded-md px-2.5 py-1.5 text-xs w-48"
          style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)', borderColor: 'var(--border-default)' }}
        />

        {hasFilters && (
          <button
            onClick={clearFilters}
            className="text-xs text-blue-600 hover:text-blue-800 font-medium"
          >
            Clear filters
          </button>
        )}

        <span className="ml-auto text-xs" style={{ color: 'var(--text-secondary)' }}>
          {total} result{total !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Table */}
      <div className="border rounded-lg overflow-hidden" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-default)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs" style={{ color: 'var(--text-primary)' }}>
            <thead className="border-b" style={{ backgroundColor: 'var(--bg-elevated, var(--bg-primary))', borderColor: 'var(--border-default)' }}>
              <tr>
                <SortHeader label="Name" field="display_name" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="Risk" field="risk_score" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <SortHeader label="App Perms" field="application_permission_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <th className="px-3 py-2.5 text-xs whitespace-nowrap">Credentials</th>
                <SortHeader label="Owners" field="owner_count" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
                <th className="px-3 py-2.5 text-xs whitespace-nowrap">Audience</th>
                <th className="px-3 py-2.5 text-xs whitespace-nowrap">SPN Activity</th>
                <SortHeader label="Created" field="created_datetime" currentField={sortField} currentDir={sortDir} onSort={handleSort} />
              </tr>
            </thead>
            <tbody className="divide-y" style={{ borderColor: 'var(--border-default)' }}>
              {/* AG-POLISH-D (2026-06-10) */}
              {loading && (
                <TableSkeletonRow columns={8} count={4} />
              )}
              {!loading && sorted.length === 0 && (
                <tr><td colSpan={8} className="py-12">
                  <div className="text-center max-w-md mx-auto">
                    <svg className="w-10 h-10 mx-auto mb-3 text-slate-600" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                    </svg>
                    <div className="text-sm font-semibold text-slate-300">No app registrations found</div>
                    <p className="text-xs text-slate-500 mt-1">Run a discovery to enumerate every App Registration in your tenant — including ownerless and orphaned apps.</p>
                  </div>
                </td></tr>
              )}
              {!loading && sorted.map(row => {
                const cs = credStatus(row);
                return (
                  <tr
                    key={row.app_id}
                    onClick={() => setSelectedAppId(row.app_id)}
                    className={`cursor-pointer hover:bg-blue-50/50 dark:hover:bg-blue-950/30 transition-colors ${selectedAppId === row.app_id ? 'bg-blue-50 dark:bg-blue-950/30' : ''}`}
                  >
                    <td className="px-3 py-2.5 max-w-[200px]">
                      <div className="font-medium truncate" style={{ color: 'var(--text-primary)' }} title={row.display_name}>{row.display_name}</div>
                      <div className="text-[10px] font-mono truncate" style={{ color: 'var(--text-secondary)' }}>{row.app_id}</div>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_BADGE[safeLower(row.risk_level)] || 'bg-gray-100 text-gray-600'}`}>
                        {row.risk_level}
                      </span>
                      <div className="text-[10px] mt-0.5" style={{ color: 'var(--text-secondary)' }}>{normalizeScore(row.risk_score, 10).toFixed(1)}/10</div>
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-1.5">
                        <span className="bg-orange-100 text-orange-700 px-1.5 py-0.5 rounded text-[10px] font-semibold">
                          {row.application_permission_count} App
                        </span>
                        <span className="bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded text-[10px] font-semibold">
                          {row.delegated_permission_count} Del
                        </span>
                      </div>
                      {row.high_risk_permissions && row.high_risk_permissions.length > 0 && (
                        <div className="text-[9px] text-red-600 font-semibold mt-0.5">
                          {row.high_risk_permissions.length} high-risk
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-1">
                        <span style={{ color: 'var(--text-primary)' }}>{row.secret_count + row.certificate_count}</span>
                        <span className={`px-1 py-0.5 rounded text-[9px] font-semibold ${CRED_RISK_BADGE[cs.key] || CRED_RISK_BADGE.none}`}>
                          {cs.label}
                        </span>
                      </div>
                      {row.next_expiry && (
                        <div className="text-[10px] mt-0.5" style={{ color: 'var(--text-secondary)' }}>{daysUntil(row.next_expiry)}</div>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      {row.owner_count === 0 ? (
                        <span className="bg-orange-100 text-orange-700 px-1.5 py-0.5 rounded text-[10px] font-semibold">None</span>
                      ) : (
                        <div>
                          <span style={{ color: 'var(--text-primary)' }}>{row.owner_count}</span>
                          {row.primary_owner && (
                            <div className="text-[10px] truncate max-w-[120px]" style={{ color: 'var(--text-secondary)' }} title={row.primary_owner}>{row.primary_owner}</div>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${AUDIENCE_BADGE[row.sign_in_audience] || 'bg-gray-100 text-gray-600'}`}>
                        {AUDIENCE_LABEL[row.sign_in_audience] || row.sign_in_audience || '?'}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      {row.has_service_principal ? (
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${ACTIVITY_BADGE[safeLower(row.spn_activity_status || '')] || ACTIVITY_BADGE.unknown}`}>
                          {row.spn_activity_status || 'unknown'}
                        </span>
                      ) : (
                        <span className="text-[10px] italic" style={{ color: 'var(--text-secondary)' }}>No SPN</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
                      {row.created_datetime ? new Date(row.created_datetime).toLocaleDateString() : '\u2014'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Drill-down panel */}
      {selectedAppId && detail && !detailLoading && (
        <AppRegDrillDown detail={detail} onClose={() => setSelectedAppId(null)} />
      )}
      {/* AG-POLISH-D (2026-06-10) */}
      {selectedAppId && detailLoading && (
        <div className="fixed inset-y-0 right-0 w-[480px] shadow-lg border-l z-50 flex items-center justify-center" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-default)' }}>
          <LoadingState message="Loading app registration detail…" size="sm" />
        </div>
      )}

      {/* Click-away overlay */}
      {selectedAppId && (
        <div className="fixed inset-0 z-40" onClick={() => setSelectedAppId(null)} />
      )}
    </div>
  );
}
