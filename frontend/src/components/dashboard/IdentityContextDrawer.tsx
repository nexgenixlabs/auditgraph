/**
 * IdentityContextDrawer — right-side inline drawer for CISO Dashboard.
 *
 * Two-stage UX:
 *   1. List View: Shows filtered identities matching the DN link
 *   2. Detail View: Shows full identity detail when a row is clicked
 *
 * Uses CISO inline styles (COLORS/FONT tokens). Matches PillarDrilldownPanel pattern.
 */
import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../../contexts/ConnectionContext';
import { useIdentityDrawer } from '../../contexts/IdentityDrawerContext';
import { COLORS } from '../../constants/ciso';
import { FONT } from './ciso-shared';
import { computeIdentityRisk } from '../../utils/identityRiskScore';
import { getSeverityColor } from '../../constants/riskScoring';
import { deriveIdentityState, STATE_COLORS } from '../../constants/identityState';
import { TIME_MS } from '../../constants/metrics';

// ─── Filter label mapping ────────────────────────────────────────

const FILTER_LABELS: Record<string, string> = {
  // Canonical metric drill-downs (exact dashboard count match)
  'metric=dormant': 'Dormant Identities',
  'metric=ghost': 'Ghost Identities',
  'metric=unowned_nhi': 'Unowned Service Principals',
  'metric=privileged': 'Privileged Identities',
  'metric=high_risk': 'High Risk Identities',
  'metric=critical': 'Critical Identities',
  'metric=credential_expired': 'Expired Credentials',
  // Pillar filters
  'pillar=effective-privilege': 'Effective Privilege Risk',
  'pillar=credential-risk': 'Credential Exposure',
  'pillar=credential-hygiene': 'Credential Hygiene',
  'pillar=external-exposure': 'External Exposure',
  'pillar=dormant-risk': 'Dormant Risk',
  'pillar=compliance-alignment': 'Compliance Alignment',
  // Priority action routes (CISO posture dashboard)
  'status=Disabled&hasRoles=true': 'Ghost Identities',
  'workload=true&owner=none': 'Unowned Service Principals',
  'risk=critical,high': 'At-Risk Identities',
  // Ad-hoc filters
  'risk_level=critical': 'Critical Risk Identities',
  'risk_level=high': 'High Risk Identities',
  'risk_level=medium': 'Medium Risk Identities',
  'risk_level=low': 'Low Risk Identities',
  'privilege_tier=0': 'T0 Administrators',
  'privilege_tier=0,1': 'T0/T1 Privileged',
  'activity_status=dormant': 'Dormant Identities',
  'activity_status=dormant_strict': 'Dormant Privileged Identities',
  'activity_status=stale': 'Stale Identities',
  'identity_category=guest': 'Guest Identities',
  'identity_category=service_principal': 'Service Principals',
  'identity_category=human_user': 'Human Users',
  'credential_status=expired': 'Expired Credentials',
  'sort=blast_radius_score': 'High Blast Radius Identities',
  'sort=risk_score': 'Highest Risk Identities',
};

// Maps filter query params to risk driver labels for drawer context header
const DRIVER_LABELS: Record<string, string> = {
  'metric=dormant': 'Dormant Privileged',
  'metric=ghost': 'Ghost Identities',
  'metric=unowned_nhi': 'Unowned SPNs',
  'status=Disabled&hasRoles=true': 'Ghost Identities',
  'workload=true&owner=none': 'Unowned SPNs',
  'activity_status=dormant_strict': 'Dormant Privileged',
  'activity_status=stale': 'Dormant Privileged',
  'pillar=effective-privilege': 'Over-Privileged',
  'pillar=credential-risk': 'Credential Exposure',
  'sort=blast_radius_score': 'High Blast Radius',
  'sort=risk_score': 'Identity Risk Score',
};

function deriveFilterLabel(filterUrl: string): string {
  const query = filterUrl.split('?')[1] || '';
  for (const [key, label] of Object.entries(FILTER_LABELS)) {
    if (query.includes(key)) return label;
  }
  // Fallback: humanize first query param
  const first = query.split('&')[0] || '';
  const [k, v] = first.split('=');
  if (k && v) return `${k.replace(/_/g, ' ')} = ${v}`.replace(/\b\w/g, c => c.toUpperCase());
  return 'Filtered Identities';
}

function deriveDriverLabel(filterUrl: string): string | null {
  const query = filterUrl.split('?')[1] || '';
  for (const [key, label] of Object.entries(DRIVER_LABELS)) {
    if (query.includes(key)) return label;
  }
  return null;
}

// ─── Risk level colors ───────────────────────────────────────────

function riskDot(level: string): string {
  switch (level) {
    case 'critical': return COLORS.danger;
    case 'high': return '#FF8C42';
    case 'medium': return COLORS.warning;
    case 'low': return COLORS.success;
    default: return COLORS.textMuted;
  }
}

function categoryLabel(cat: string): string {
  return (cat || 'unknown')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}

/** Resolve status from the enabled boolean — matches backend SSOT. */
function resolveRowStatus(row: IdentityRow): { label: string; color: string } | null {
  if (row.enabled === false) return { label: 'Disabled', color: '#ef4444' };
  if (row.activity_status === 'stale' || row.activity_status === 'never_used')
    return { label: 'Dormant', color: '#f59e0b' };
  return null; // active — no extra badge needed
}

// ─── Types ───────────────────────────────────────────────────────

interface IdentityRow {
  identity_id: string;
  db_id?: number;
  display_name: string;
  identity_category: string;
  risk_level: string;
  risk_score: number;
  privilege_tier?: string | number;
  role_count?: number;
  enabled?: boolean;
  activity_status?: string;
}

interface IdentityDetail {
  identity_id: string;
  db_id: number;
  display_name: string;
  identity_type: string;
  identity_category: string;
  risk_level: string;
  risk_score: number;
  privilege_tier?: string | number;
  role_count?: number;
  rbac_role_count?: number;
  entra_role_count?: number;
  last_seen_auth?: string | null;
  last_sign_in?: string | null;
  risk_factors?: Array<{ factor?: string; severity: string; detail?: string; description?: string; category?: string; code?: string }>;
  blast_radius_score?: number;
  attack_path_count?: number;
  credential_count?: number;
  credential_risk?: string;
  activity_status?: string;
  owner_display_name?: string | null;
  owner_status?: string | null;
  roles?: Array<Record<string, any>>;
  trend?: {
    previous_risk_level?: string | null;
    previous_risk_score?: number | null;
    risk_direction?: string;
    is_new?: boolean;
  } | null;
  // SSOT canonical activity fields
  last_activity_date?: string | null;
  last_activity_source?: string | null;
  last_activity_confidence?: string | null;
  // IP observation fields (ARM Activity Log)
  last_observed_ip?: string | null;
  last_observed_ip_source?: string | null;
  last_observed_ip_date?: string | null;
  last_observed_operation?: string | null;
  // Additional fields
  enabled?: boolean;
  account_enabled?: boolean;
  user_type?: string | null;
  highest_role?: string | null;
  assigned_roles?: number;
  blast_scope?: string | null;
  federated_credential_issuer?: string | null;
  inferred_origin?: string | null;
  associated_resource?: string | null;
  lineage_verdict?: string | null;
  owner_deleted?: boolean;
  app_id?: string | null;
  effective_scope?: string;
  federated_workload_type?: string | null;
  federated_workload_name?: string | null;
  associated_resource_name?: string | null;
  created_datetime?: string | null;
  credential_status?: string;
  effective_access?: string | null;
  sensitive_access?: string | null;
  first_seen?: string | null;
  days_inactive?: number | null;
  // Canonical identity state (from build_identity_state)
  activity_label?: string | null;
  activity_detail?: string | null;
  is_dormant?: boolean;
  lifecycle_state?: string | null;
  governance_state?: string | null;
  privilege_level?: string | null;
  risk_label?: string | null;
  is_federated?: boolean;
  last_signin_at?: string | null;
}

// ─── Time helpers ────────────────────────────────────────────────

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins} minute${mins !== 1 ? 's' : ''} ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} hour${hours !== 1 ? 's' : ''} ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} day${days !== 1 ? 's' : ''} ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months} month${months !== 1 ? 's' : ''} ago`;
  const years = Math.floor(months / 12);
  return `${years} year${years !== 1 ? 's' : ''} ago`;
}

// ─── Slide-in keyframes (injected once) ──────────────────────────

const ANIMATION_CSS = `
@keyframes identityDrawerSlideIn {
  from { transform: translateX(100%); }
  to   { transform: translateX(0); }
}
`;

// ─── Component ───────────────────────────────────────────────────

export function IdentityContextDrawer() {
  const ctx = useIdentityDrawer();
  const navigate = useNavigate();
  const { withConnection } = useConnection();

  const [identities, setIdentities] = useState<IdentityRow[]>([]);
  const [detail, setDetail] = useState<IdentityDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const open = ctx?.state.open ?? false;
  const filterUrl = ctx?.state.filterUrl ?? null;
  const selectedIdentityId = ctx?.state.selectedIdentityId ?? null;
  const prefill = ctx?.state.prefill ?? null;
  const closeDrawer = ctx?.closeDrawer ?? (() => {});
  const selectIdentity = ctx?.selectIdentity ?? (() => {});
  const backToList = ctx?.backToList ?? (() => {});

  // ─── Escape key handler ──────────────────────────────────────
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeDrawer();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, closeDrawer]);

  // ─── Fetch identity list when drawer opens ───────────────────
  useEffect(() => {
    if (!open || !filterUrl) return;
    setLoading(true);
    setIdentities([]);
    setDetail(null);

    const queryStr = filterUrl.includes('?') ? filterUrl.split('?')[1] : '';
    const apiUrl = withConnection(`/api/identities?${queryStr}&limit=20`);

    fetch(apiUrl)
      .then(r => r.ok ? r.json() : { identities: [] })
      .then(data => {
        setIdentities(data.identities || []);
        setLoading(false);
      })
      .catch(() => {
        setIdentities([]);
        setLoading(false);
      });
  }, [open, filterUrl, withConnection]);

  // ─── Fetch identity detail when selected ─────────────────────
  useEffect(() => {
    if (!selectedIdentityId) { setDetail(null); setDetailError(null); return; }
    setDetailLoading(true);
    setDetailError(null);
    // Show prefill immediately so name/type are visible while loading
    setDetail(prefill ? { identity_id: String(selectedIdentityId), ...prefill } as unknown as IdentityDetail : null);

    // Find the identity_id (string) from the list
    const match = identities.find(i => (i.db_id ?? 0) === selectedIdentityId || i.identity_id === String(selectedIdentityId));
    const idParam = match?.identity_id || String(selectedIdentityId);

    fetch(withConnection(`/api/identities/${encodeURIComponent(idParam)}`))
      .then(r => {
        if (r.status === 404) throw new Error('Identity not found. It may have been deleted or is not in this snapshot.');
        if (!r.ok) throw new Error('Failed to load identity details.');
        return r.json();
      })
      .then(data => {
        // API returns { identity: {...fields}, roles: [...], trend: {...}, ... }
        // Flatten so component can read detail.identity_id, detail.blast_radius_score, etc.
        const { identity: identityFields, ...rest } = data;
        const flat = identityFields ? { ...identityFields, ...rest } : data;
        // Merge: API response wins, but prefill fills any blank fields
        const merged = prefill ? {
          ...flat,
          display_name: flat.display_name || prefill.display_name || '',
          identity_category: flat.identity_category || prefill.identity_category || '',
        } : flat;
        setDetail(merged);
        setDetailLoading(false);
      })
      .catch((err) => {
        setDetail(null);
        setDetailError(err?.message || 'Failed to load identity. Please try again.');
        setDetailLoading(false);
      });
  }, [selectedIdentityId, withConnection, identities]);

  if (!ctx || !open) return null;

  // ─── Render ──────────────────────────────────────────────────

  return (
    <>
      <style>{ANIMATION_CSS}</style>

      {/* Backdrop */}
      <div
        onClick={closeDrawer}
        style={{
          position: 'fixed', inset: 0,
          background: 'rgba(0,0,0,0.35)',
          zIndex: 40,
        }}
      />

      {/* Panel */}
      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0,
        width: 480,
        background: COLORS.surface,
        borderLeft: `1px solid ${COLORS.border}`,
        zIndex: 50,
        display: 'flex', flexDirection: 'column',
        boxShadow: '-8px 0 32px rgba(0,0,0,0.3)',
        animation: 'identityDrawerSlideIn 0.25s ease',
      }}>
        {selectedIdentityId
          ? <DetailView
              detail={detail}
              loading={detailLoading}
              error={detailError}
              onBack={filterUrl ? backToList : closeDrawer}
              onClose={closeDrawer}
              onOpenFull={(id) => {
                const resolvedId = id || (selectedIdentityId != null ? String(selectedIdentityId) : '');
                if (!resolvedId || resolvedId === 'undefined') return;
                closeDrawer();
                navigate(`/identities/${encodeURIComponent(resolvedId)}`);
              }}
              onNavigate={(path) => { closeDrawer(); navigate(path); }}
            />
          : <ListView
              filterUrl={filterUrl || ''}
              identities={identities}
              loading={loading}
              onSelect={(row) => selectIdentity(row.db_id ?? row.identity_id)}
              onClose={closeDrawer}
              onOpenFullPage={() => { closeDrawer(); navigate(filterUrl || '/identities'); }}
            />
        }
      </div>
    </>
  );
}

// ─── List View ───────────────────────────────────────────────────

function getContextBadge(row: IdentityRow, filterUrl: string): { label: string; value: string; color: string } | null {
  const query = filterUrl.split('?')[1] || '';
  if (query.includes('status=Disabled')) {
    return { label: 'Status', value: row.enabled === false ? 'Disabled' : 'Active', color: row.enabled === false ? COLORS.danger : COLORS.success };
  }
  if (query.includes('pillar=effective-privilege') || query.includes('contributing_pillar=effective_privilege')) {
    const rawT = row.privilege_tier;
    const tier = rawT == null ? null : (typeof rawT === 'string' && String(rawT).startsWith('T') ? String(rawT) : `T${rawT}`);
    if (tier) return { label: 'Tier', value: tier, color: tier === 'T0' ? COLORS.danger : tier === 'T1' ? '#FF8C42' : COLORS.warning };
  }
  if (query.includes('activity_status=stale') || query.includes('activity_status=dormant') || query.includes('pillar=usage-dormancy')) {
    return { label: 'Status', value: 'Dormant', color: COLORS.elevated };
  }
  if (query.includes('pillar=credential-risk') || query.includes('credential_status=')) {
    return { label: 'Creds', value: 'At Risk', color: COLORS.warning };
  }
  if (query.includes('pillar=ownership-governance') || query.includes('has_owner=false')) {
    return { label: 'Owner', value: 'None', color: COLORS.elevated };
  }
  if (query.includes('pillar=external-exposure')) {
    return { label: 'Scope', value: 'Tenant-wide', color: COLORS.danger };
  }
  if (query.includes('blast_radius_score')) {
    return { label: 'Blast', value: (row.risk_level || 'HIGH').toUpperCase(), color: COLORS.danger };
  }
  return null;
}

function ListView({ filterUrl, identities, loading, onSelect, onClose, onOpenFullPage }: {
  filterUrl: string;
  identities: IdentityRow[];
  loading: boolean;
  onSelect: (row: IdentityRow) => void;
  onClose: () => void;
  onOpenFullPage: () => void;
}) {
  const label = deriveFilterLabel(filterUrl);
  const driver = deriveDriverLabel(filterUrl);

  return (
    <>
      {/* Header */}
      <div style={{
        padding: '16px 20px',
        borderBottom: `1px solid ${COLORS.border}`,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui }}>{label}</div>
          <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 2 }}>
            {driver && <span style={{ color: COLORS.accent, fontWeight: 600 }}>Driver: {driver} &middot; </span>}
            {loading ? 'Loading...' : `${identities.length} identities`}
          </div>
        </div>
        <button
          onClick={onClose}
          style={{ background: 'none', border: 'none', color: COLORS.textSecondary, cursor: 'pointer', fontSize: 20, fontFamily: FONT.ui }}
        >
          ×
        </button>
      </div>

      {/* Identity list */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 0' }}>
        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 40 }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%',
              border: `3px solid ${COLORS.border}`, borderTopColor: COLORS.accent,
              animation: 'spin 1s linear infinite',
            }} />
          </div>
        ) : identities.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 40, color: COLORS.textSecondary, fontSize: 12, fontFamily: FONT.ui }}>
            No identities match this filter.
          </div>
        ) : (
          identities.map((row, idx) => {
            const badge = getContextBadge(row, filterUrl);
            return (
            <div
              key={row.identity_id + idx}
              onClick={() => onSelect(row)}
              style={{
                padding: '10px 20px',
                cursor: 'pointer',
                borderBottom: `1px solid ${COLORS.border}22`,
                transition: 'background 0.15s',
                display: 'flex', alignItems: 'center', gap: 12,
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = COLORS.surfaceAlt || '#0f1729'; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
            >
              {/* Risk dot */}
              <span style={{
                width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                background: riskDot(row.risk_level),
              }} />

              {/* Name + category + status */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui,
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {row.display_name || row.identity_id}
                </div>
                <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 1, display: 'flex', alignItems: 'center', gap: 4 }}>
                  {categoryLabel(row.identity_category)}
                  {(() => {
                    const st = resolveRowStatus(row);
                    return st ? (
                      <span style={{
                        fontSize: 8, fontWeight: 700, fontFamily: FONT.mono,
                        padding: '1px 4px', borderRadius: 3,
                        background: `${st.color}18`, color: st.color,
                        border: `1px solid ${st.color}30`,
                      }}>
                        {st.label}
                      </span>
                    ) : null;
                  })()}
                </div>
              </div>

              {/* Context-relevant badge (when available) */}
              {badge && (
                <span style={{
                  fontSize: 8, fontWeight: 700, padding: '2px 6px', borderRadius: 3,
                  background: `${badge.color}18`, color: badge.color,
                  border: `1px solid ${badge.color}30`, fontFamily: FONT.mono,
                  flexShrink: 0,
                }}>
                  {badge.value}
                </span>
              )}

              {/* Severity badge */}
              <span style={{
                fontSize: 9, fontWeight: 700, fontFamily: FONT.mono,
                padding: '2px 6px', borderRadius: 4, textTransform: 'uppercase',
                background: riskDot(row.risk_level) + '22',
                color: riskDot(row.risk_level),
                border: `1px solid ${riskDot(row.risk_level)}44`,
                letterSpacing: '0.3px', flexShrink: 0,
              }}>
                {(row.risk_level || 'INFO').toUpperCase()}
              </span>
            </div>
            );
          })
        )}
      </div>

      {/* Footer */}
      <div style={{ padding: '12px 20px', borderTop: `1px solid ${COLORS.border}` }}>
        <button
          onClick={onOpenFullPage}
          style={{
            width: '100%', padding: '8px 0',
            background: COLORS.accent + '18',
            border: `1px solid ${COLORS.accent}44`,
            borderRadius: 6, cursor: 'pointer',
            fontSize: 12, fontWeight: 600, color: COLORS.accent, fontFamily: FONT.ui,
          }}
        >
          Open Full Page →
        </button>
      </div>
    </>
  );
}

// ─── Identity Timeline ───────────────────────────────────────────

interface TimelineEvent {
  timestamp: string | null;
  event_type: string;
  severity: string;
  title: string;
  description: string;
  metadata?: Record<string, unknown>;
}

const EVENT_STYLES: Record<string, { icon: string; color: string; label: string }> = {
  anomaly:        { icon: '\u26A0', color: '#EF4444', label: 'Anomaly' },
  risk_change:    { icon: '\u2195', color: '#F59E0B', label: 'Risk Change' },
  pim_activation: { icon: '\uD83D\uDEE1', color: '#A855F7', label: 'PIM Activation' },
  role_assignment: { icon: '\uD83D\uDEE1', color: COLORS.accent, label: 'Role Assignment' },
  soar_action:    { icon: '\u2699', color: '#3B82F6', label: 'SOAR Action' },
  remediation:    { icon: '\uD83D\uDD27', color: '#22C55E', label: 'Remediation' },
  auth:           { icon: '\uD83D\uDC64', color: '#6366F1', label: 'Authentication' },
  credential:     { icon: '\uD83D\uDD11', color: '#F97316', label: 'Credential' },
  dormancy:       { icon: '\u23F8', color: '#EF4444', label: 'Dormancy' },
};

function getEventStyle(type: string) {
  return EVENT_STYLES[type] || { icon: '\u2022', color: COLORS.textSecondary, label: type };
}

function extractEventDetails(ev: TimelineEvent): { label: string; value: string }[] {
  const m = ev.metadata || {};
  const details: { label: string; value: string }[] = [];
  const str = (v: unknown) => (v != null && v !== '') ? String(v) : null;

  switch (ev.event_type) {
    case 'role_assignment':
    case 'pim_activation': {
      const role = str(m.role_name) || str(m.role) || str(m.directory_role);
      if (role) details.push({ label: 'Role', value: role });
      const resource = str(m.resource) || str(m.scope) || str(m.subscription);
      if (resource) details.push({ label: 'Resource', value: resource });
      break;
    }
    case 'auth': {
      const location = str(m.location) || str(m.region) || str(m.ip_location);
      if (location) details.push({ label: 'Location', value: location });
      const ip = str(m.ip_address) || str(m.ip);
      if (ip) details.push({ label: 'IP', value: ip });
      const status = str(m.status) || str(m.result);
      if (status) details.push({ label: 'Status', value: status });
      break;
    }
    case 'credential': {
      const app = str(m.application) || str(m.app_name) || str(m.display_name);
      if (app) details.push({ label: 'Application', value: app });
      const credType = str(m.credential_type) || str(m.type);
      if (credType) details.push({ label: 'Type', value: credType });
      const expiry = str(m.expires) || str(m.expiry_date);
      if (expiry) details.push({ label: 'Expires', value: expiry });
      break;
    }
    case 'remediation': {
      const action = str(m.action_type) || str(m.action);
      if (action) details.push({ label: 'Action', value: action });
      const target = str(m.target) || str(m.identity_name) || str(m.resource);
      if (target) details.push({ label: 'Target', value: target });
      const status = str(m.status) || str(m.result);
      if (status) details.push({ label: 'Status', value: status });
      break;
    }
    case 'anomaly': {
      const anomalyType = str(m.anomaly_type) || str(m.type);
      if (anomalyType) details.push({ label: 'Type', value: anomalyType });
      const severity = str(m.severity);
      if (severity) details.push({ label: 'Severity', value: severity });
      break;
    }
    case 'risk_change': {
      const prev = str(m.previous_score) || str(m.old_score);
      const curr = str(m.new_score) || str(m.current_score);
      if (prev && curr) details.push({ label: 'Change', value: `${prev} \u2192 ${curr}` });
      else if (curr) details.push({ label: 'Score', value: curr });
      const reason = str(m.reason) || str(m.trigger);
      if (reason) details.push({ label: 'Reason', value: reason });
      break;
    }
    case 'soar_action': {
      const playbook = str(m.playbook_name) || str(m.playbook);
      if (playbook) details.push({ label: 'Playbook', value: playbook });
      const status = str(m.status) || str(m.result);
      if (status) details.push({ label: 'Status', value: status });
      break;
    }
    case 'dormancy': {
      const days = str(m.days_inactive) || str(m.inactive_days);
      if (days) details.push({ label: 'Inactive', value: `${days} days` });
      break;
    }
    default: {
      // Generic: show first 2 meaningful metadata keys
      const entries = Object.entries(m).filter(([, v]) => v != null && v !== '').slice(0, 2);
      for (const [k, v] of entries) {
        details.push({ label: k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()), value: String(v) });
      }
    }
  }
  return details.slice(0, 3);
}

function IdentityTimeline({ identityId }: { identityId: string }) {
  const { withConnection } = useConnection();
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    fetch(withConnection(`/api/identities/${encodeURIComponent(identityId)}/timeline?limit=10`))
      .then(r => r.ok ? r.json() : { events: [] })
      .then(data => { setEvents(data.events || []); setLoading(false); })
      .catch(() => { setEvents([]); setLoading(false); });
  }, [identityId, withConnection]);

  // Synthesize events from identity detail data when API returns empty
  // (the detail is not available here, so we only show API events)

  if (loading) {
    return (
      <div style={{ marginTop: 16 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Timeline
        </div>
        <div style={{ padding: 16, textAlign: 'center' }}>
          <div style={{
            width: 18, height: 18, borderRadius: '50%', margin: '0 auto',
            border: `2px solid ${COLORS.border}`, borderTopColor: COLORS.accent,
            animation: 'spin 1s linear infinite',
          }} />
        </div>
      </div>
    );
  }

  if (events.length === 0) return (
    <div style={{ marginTop: 16 }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        Timeline
      </div>
      <div style={{ fontSize: 11, color: COLORS.textDim, fontFamily: FONT.ui }}>
        No activity events recorded for this identity.
      </div>
    </div>
  );

  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        Timeline
      </div>
      <div style={{ position: 'relative', paddingLeft: 20 }}>
        {/* Vertical line */}
        <div style={{
          position: 'absolute', left: 5, top: 4, bottom: 4, width: 1,
          background: COLORS.border,
        }} />
        {events.map((ev, i) => {
          const style = getEventStyle(ev.event_type);
          const details = extractEventDetails(ev);
          return (
            <div key={i} style={{ position: 'relative', paddingBottom: i < events.length - 1 ? 12 : 0 }}>
              {/* Dot */}
              <div style={{
                position: 'absolute', left: -18, top: 2,
                width: 10, height: 10, borderRadius: '50%',
                background: `${style.color}25`, border: `2px solid ${style.color}`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }} />
              {/* Content */}
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <span style={{ fontSize: 10, lineHeight: 1, color: style.color }}>{style.icon}</span>
                    <span style={{
                      fontSize: 8, fontWeight: 700, padding: '1px 5px', borderRadius: 3,
                      background: `${style.color}15`, color: style.color,
                      fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.03em',
                    }}>
                      {style.label}
                    </span>
                  </div>
                  <div style={{
                    fontSize: 11, color: COLORS.text, fontFamily: FONT.ui, marginTop: 2,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {ev.title}
                  </div>
                  {ev.description && (
                    <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 1 }}>
                      {ev.description.length > 80 ? ev.description.slice(0, 80) + '\u2026' : ev.description}
                    </div>
                  )}
                  {details.length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 4 }}>
                      {details.map((d, j) => (
                        <span key={j} style={{
                          fontSize: 9, fontFamily: FONT.ui,
                          padding: '1px 6px', borderRadius: 3,
                          background: `${COLORS.border}`,
                        }}>
                          <span style={{ color: COLORS.textDim }}>{d.label}: </span>
                          <span style={{ color: COLORS.textSecondary, fontWeight: 600 }}>
                            {d.value.length > 30 ? d.value.slice(0, 30) + '\u2026' : d.value}
                          </span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                {ev.timestamp && (
                  <span style={{ fontSize: 9, color: COLORS.textDim, fontFamily: FONT.mono, flexShrink: 0, whiteSpace: 'nowrap', marginTop: 2 }}>
                    {timeAgo(ev.timestamp)}
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── AI Explanation Panel ────────────────────────────────────────

interface AIExplanation {
  summary: string;
  drivers: string[];
  implications: string;
  recommended_action: string;
}

// ─── Activity Signals — architecture-derived, no log dependency ──

function ActivitySignals({ detail }: { detail: IdentityDetail }) {
  const d = detail as Record<string, any>;

  // Derive latest role assignment date from roles array
  const roles: Array<{ created_on?: string }> = d.roles || [];
  const latestRoleDate = roles
    .map(r => r.created_on)
    .filter(Boolean)
    .sort((a, b) => new Date(b!).getTime() - new Date(a!).getTime())[0] || null;

  // Canonical SSOT last-activity fields
  const lastActivityDate: string | null = d.last_activity_date || null;
  const lastActivitySource: string | null = d.last_activity_source || null;
  const lastActivityConf: string = d.last_activity_confidence || 'none';

  const SOURCE_LABELS: Record<string, string> = {
    entra_signin_log: 'Entra sign-in logs',
    graph_signin: 'Graph API sign-in activity',
    entra_noninteractive: 'Non-interactive sign-in',
    role_assignment: 'Role assignment date',
    credential_rotation: 'Credential rotation',
    federated_credential: 'Federated credential',
    created_date: 'Creation date only',
    auditgraph_scan: 'AuditGraph scan',
  };

  // Legacy sign-in detection (for backward compat log-access note)
  const lastSignIn = d.last_signin_at || d.last_seen_auth || d.last_sign_in;
  const hasLogAccess = !!lastSignIn || !!lastActivityDate;
  const activitySources: Array<{ type: string; available: boolean; detail?: string }> = d.activity_sources || [];
  const p2Source = activitySources.find(s => s.type === 'azure_signin');

  // Credential state
  const credCount = d.credential_count ?? 0;
  const credExpiry = d.credential_expiration;
  const credStatus = d.credential_status || '';

  const fmtDate = (iso: string) => new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });

  // Dormancy — prefer canonical backend state, fallback to frontend heuristic
  const rawStatus = d.activity_status || 'unknown';
  const isFederated = !!(d.is_federated || d.federated_workload_type);
  const hasRoles = roles.length > 0;
  const hasRecentRole = !!latestRoleDate && ((Date.now() - new Date(latestRoleDate).getTime()) / TIME_MS.DAY) < 90;
  const hasActiveCreds = credCount > 0 && d.credential_risk !== 'expired';
  const tierStr = typeof d.privilege_tier === 'string' ? d.privilege_tier : `T${d.privilege_tier ?? 3}`;
  const isPrivileged = tierStr === 'T0' || tierStr === 'T1';

  // Use canonical activity_label when available from backend
  let activityStatus = rawStatus;
  let dormancySub = '';
  if (d.activity_label) {
    activityStatus = d.is_dormant ? 'stale' : 'active';
    dormancySub = d.activity_detail || '';
  } else if (rawStatus === 'never_used') {
    // Legacy frontend override when backend canonical state not available
    if (isFederated) {
      activityStatus = 'likely_active';
      dormancySub = 'OIDC federation — no sign-in logs expected';
    } else if (isPrivileged) {
      activityStatus = 'likely_active';
      dormancySub = 'Privileged account with active roles';
    } else if (hasActiveCreds) {
      activityStatus = 'likely_active';
      dormancySub = 'Active credentials configured';
    } else if (hasRecentRole) {
      activityStatus = 'likely_active';
      dormancySub = `Role assigned ${latestRoleDate ? fmtDate(latestRoleDate) : 'recently'}`;
    } else if (hasRoles) {
      dormancySub = 'Has roles but no activity signals';
    } else {
      dormancySub = 'No credentials, roles, or sign-in data';
    }
  }

  const dormancyColor = activityStatus === 'never_used' ? COLORS.danger
    : activityStatus === 'stale' || activityStatus === 'dormant' ? COLORS.warning
    : activityStatus === 'active' || activityStatus === 'likely_active' ? COLORS.success
    : activityStatus === 'recently_created' ? COLORS.accent
    : COLORS.textDim;
  const dormancyLabel = activityStatus === 'never_used' ? 'Provisioned'
    : activityStatus === 'stale' ? 'Stale'
    : activityStatus === 'dormant' ? 'Dormant'
    : activityStatus === 'inactive' ? 'Inactive'
    : activityStatus === 'active' ? 'Active'
    : activityStatus === 'likely_active' ? 'Likely active'
    : activityStatus === 'recently_created' ? 'Recently created'
    : 'Unknown';

  const signalRowStyle: React.CSSProperties = {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    padding: '5px 0', borderBottom: `1px solid ${COLORS.border}15`,
  };
  const labelStyle: React.CSSProperties = { fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui };
  const valueStyle: React.CSSProperties = { fontSize: 10, fontFamily: FONT.mono, fontWeight: 600 };

  return (
    <div style={{ marginTop: 14 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: COLORS.textSecondary, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Activity Signals
        </span>
        <span style={{ fontSize: 8, color: COLORS.textDim, fontFamily: FONT.ui }}>
          Architecture-derived
        </span>
      </div>

      <div style={{
        padding: '8px 10px', borderRadius: 8,
        background: COLORS.surfaceAlt || '#0f1729',
        border: `1px solid ${COLORS.border}`,
      }}>
        {/* Credential state */}
        <div style={signalRowStyle}>
          <span style={labelStyle}>Credential</span>
          <span style={{ ...valueStyle, color: credCount === 0 ? COLORS.textDim : credExpiry ? COLORS.warning : COLORS.textSecondary }}>
            {credCount === 0
              ? 'No secrets'
              : credExpiry
                ? `Expires ${fmtDate(credExpiry)}`
                : credStatus === 'Valid' ? `${credCount} active` : (credStatus || `${credCount} credential${credCount !== 1 ? 's' : ''}`)}
          </span>
        </div>

        {/* Latest role assignment */}
        <div style={signalRowStyle}>
          <span style={labelStyle}>Last Role Assignment</span>
          <span style={{ ...valueStyle, color: latestRoleDate ? COLORS.textSecondary : COLORS.textDim }}>
            {latestRoleDate ? fmtDate(latestRoleDate) : 'No assignments'}
          </span>
        </div>

        {/* Federated credential */}
        {(d.is_federated || d.federated_workload_type) && (
          <div style={signalRowStyle}>
            <span style={labelStyle}>Federated Credential</span>
            <span style={{ ...valueStyle, color: COLORS.accent }}>
              {d.federated_workload_type || 'Configured'}
            </span>
          </div>
        )}

        {/* Identity State — architecture-derived, always has a value */}
        {(() => {
          const roleCount = (d.roles || []).length + (d.entra_roles || []).length;
          const state = deriveIdentityState({
            enabled: d.enabled !== false,
            identity_category: d.identity_category,
            role_count: roleCount > 0 ? roleCount : (d.rbac_role_count || 0) + (d.entra_role_count || 0),
            privilege_tier: d.privilege_tier,
            effective_scope: d.effective_scope,
            federated_workload_type: d.federated_workload_type,
            is_federated: d.is_federated,
            associated_resource_name: d.associated_resource_name,
            owner_display_name: d.owner_display_name,
            last_activity_source: d.last_activity_source,
            last_activity_date: d.last_activity_date,
            created_datetime: d.created_datetime,
          });
          const stateHex = STATE_COLORS[state.color].hex;
          return (
            <div style={{ ...signalRowStyle, flexDirection: 'column', alignItems: 'stretch', gap: 2, borderBottom: 'none' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={labelStyle}>Identity State</span>
                <span style={{ ...valueStyle, color: stateHex }}>
                  {state.label}
                </span>
              </div>
              <span style={{ fontSize: 9, color: COLORS.textDim, fontFamily: FONT.ui, textAlign: 'right' }}>
                {state.sublabel}
              </span>
            </div>
          );
        })()}
      </div>
    </div>
  );
}

function AIExplanationPanel({ identityId }: { identityId: string }) {
  const { withConnection } = useConnection();
  const [explanation, setExplanation] = useState<AIExplanation | null>(null);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [error, setError] = useState('');

  const fetchExplanation = useCallback(() => {
    if (explanation || loading) return;
    setLoading(true);
    setError('');
    fetch(withConnection(`/api/identities/${encodeURIComponent(identityId)}/ai-risk-explanation`))
      .then(r => r.ok ? r.json() : Promise.reject('Failed to load'))
      .then(data => { setExplanation(data); setLoading(false); })
      .catch(e => { setError(String(e)); setLoading(false); });
  }, [identityId, withConnection, explanation, loading]);

  const handleToggle = () => {
    if (!expanded && !explanation && !loading) fetchExplanation();
    setExpanded(prev => !prev);
  };

  const AI_ACCENT = '#A855F7';

  return (
    <div style={{ marginTop: 16 }}>
      <button
        onClick={handleToggle}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 8,
          background: 'none', border: 'none', cursor: 'pointer', padding: 0,
        }}
      >
        <span style={{ fontSize: 13, lineHeight: 1 }}>&#x2728;</span>
        <span style={{
          fontSize: 11, fontWeight: 700, color: AI_ACCENT, fontFamily: FONT.ui,
          textTransform: 'uppercase', letterSpacing: '0.05em',
        }}>
          AI Explanation
        </span>
        <span style={{
          marginLeft: 'auto', fontSize: 10, color: COLORS.textDim,
          fontFamily: FONT.ui, transition: 'transform 0.2s',
          transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)',
        }}>
          &#x25BC;
        </span>
      </button>

      {expanded && (
        <div style={{
          marginTop: 8, padding: '12px 14px', borderRadius: 8,
          background: `${AI_ACCENT}08`,
          border: `1px solid ${AI_ACCENT}25`,
        }}>
          {loading ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 0' }}>
              <div style={{
                width: 14, height: 14, borderRadius: '50%',
                border: `2px solid ${COLORS.border}`, borderTopColor: AI_ACCENT,
                animation: 'spin 1s linear infinite',
              }} />
              <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                Generating AI analysis...
              </span>
            </div>
          ) : error ? (
            <div style={{ fontSize: 11, color: COLORS.danger, fontFamily: FONT.ui }}>
              {error}
            </div>
          ) : explanation ? (
            <>
              {/* Summary */}
              <div style={{ marginBottom: 10 }}>
                <div style={{
                  fontSize: 9, fontWeight: 700, color: AI_ACCENT, fontFamily: FONT.ui,
                  textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 4,
                }}>
                  Summary
                </div>
                <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui, lineHeight: 1.5 }}>
                  {explanation.summary}
                </div>
              </div>

              {/* Key Drivers */}
              {explanation.drivers.length > 0 && (
                <div style={{ marginBottom: 10 }}>
                  <div style={{
                    fontSize: 9, fontWeight: 700, color: AI_ACCENT, fontFamily: FONT.ui,
                    textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 4,
                  }}>
                    Key Risk Drivers
                  </div>
                  {explanation.drivers.map((d, i) => (
                    <div key={i} style={{
                      fontSize: 11, color: COLORS.text, fontFamily: FONT.ui,
                      padding: '3px 0', paddingLeft: 12, position: 'relative', lineHeight: 1.4,
                    }}>
                      <span style={{
                        position: 'absolute', left: 0, top: 5,
                        width: 4, height: 4, borderRadius: '50%',
                        background: AI_ACCENT,
                      }} />
                      {d}
                    </div>
                  ))}
                </div>
              )}

              {/* Implications */}
              <div style={{ marginBottom: 10 }}>
                <div style={{
                  fontSize: 9, fontWeight: 700, color: AI_ACCENT, fontFamily: FONT.ui,
                  textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 4,
                }}>
                  Security Implications
                </div>
                <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.5 }}>
                  {explanation.implications}
                </div>
              </div>

              {/* Recommended Action */}
              <div style={{
                padding: '8px 10px', borderRadius: 6,
                background: `${AI_ACCENT}12`,
                border: `1px solid ${AI_ACCENT}20`,
              }}>
                <div style={{
                  fontSize: 9, fontWeight: 700, color: AI_ACCENT, fontFamily: FONT.ui,
                  textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 3,
                }}>
                  Recommended Action
                </div>
                <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui, fontWeight: 600, lineHeight: 1.4 }}>
                  {explanation.recommended_action}
                </div>
              </div>
            </>
          ) : null}
        </div>
      )}
    </div>
  );
}

// ─── Risk Score Breakdown ────────────────────────────────────────

function RiskScoreBreakdown({ detail }: { detail: IdentityDetail }) {
  const result = computeIdentityRisk(detail as Record<string, any>);
  // Use backend risk_level as authoritative severity badge — dimension bars show the breakdown
  const backendLevel = (detail.risk_level || '').toLowerCase();
  const badgeSeverity = backendLevel || result.overall_severity;
  const badgeColor = riskDot(badgeSeverity);

  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: COLORS.textSecondary, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Risk Score Breakdown
        </span>
        <span style={{
          fontSize: 8, fontWeight: 600, padding: '2px 5px', borderRadius: 3,
          background: `${badgeColor}18`, color: badgeColor,
          fontFamily: FONT.mono, textTransform: 'uppercase',
        }}>
          {badgeSeverity}
        </span>
      </div>
      <div style={{
        fontSize: 9, color: COLORS.textMuted, letterSpacing: '0.5px',
        marginBottom: 12, fontFamily: FONT.mono,
      }}>
        CVSS v3.1 · NIST SP 800-63B · SP 800-207 · CIS Controls v8
      </div>
      <div style={{
        padding: '10px 12px', borderRadius: 8,
        background: COLORS.surfaceAlt || '#0f1729',
        border: `1px solid ${COLORS.border}`,
      }}>
        {result.dimensions.map(dim => {
          const barPct = (dim.score / 10) * 100;
          const sevColor = getSeverityColor(dim.severity);
          const primaryMitre = dim.score > 0 && dim.mitre.length > 0 ? dim.mitre[0] : null;
          return (
            <div key={dim.dimension} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0' }}>
              <span style={{ fontSize: 12, width: 16, textAlign: 'center', flexShrink: 0 }}>{dim.icon}</span>
              <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, width: 110, flexShrink: 0 }}>
                {dim.name}
              </span>
              <div style={{ flex: 1, height: 4, borderRadius: 2, background: COLORS.border, overflow: 'hidden' }}>
                <div style={{
                  width: `${barPct}%`, height: '100%', borderRadius: 2,
                  background: dim.score > 0 ? dim.color : COLORS.textDim,
                  transition: 'width 0.3s ease',
                }} />
              </div>
              <span style={{
                fontSize: 10, fontWeight: 700, fontFamily: FONT.mono, width: 28, textAlign: 'right', flexShrink: 0,
                color: dim.score > 0 ? sevColor : COLORS.textDim,
              }}>
                {dim.score.toFixed(1)}
              </span>
              {primaryMitre && (
                <span style={{
                  fontSize: 7, padding: '1px 4px', borderRadius: 2,
                  background: `${COLORS.accent}18`, color: COLORS.accent,
                  fontWeight: 600, fontFamily: FONT.mono, flexShrink: 0,
                }}>
                  {primaryMitre}
                </span>
              )}
            </div>
          );
        })}
        {/* Overall */}
        <div style={{
          borderTop: `1px solid ${COLORS.border}`, marginTop: 6, paddingTop: 6,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span style={{ fontSize: 10, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui }}>Peak Dimension</span>
          <span style={{ fontSize: 13, fontWeight: 700, color: badgeColor, fontFamily: FONT.mono }}>
            {Math.min(10, result.overall_score).toFixed(1)}/10
          </span>
        </div>
      </div>
    </div>
  );
}

// ─── Quick Actions ───────────────────────────────────────────────

const ACTION_ICONS: Record<string, string> = {
  disable: '\u26D4',
  remove_role: '\u2702',
  assign_owner: '\u263A',
  ticket: '\u2709',
  rotate: '\u21BB',
  review: '\u2714',
};

interface ActionImpact {
  projectedScore: number;
  reasons: string[];
}

interface QuickAction {
  id: string;
  label: string;
  icon: string;
  description: string;
  navigateTo: string;
  color: string;
  impact?: ActionImpact;
}

function deriveActions(
  detail: IdentityDetail,
  privilegeTier: string,
  roleCount: number,
  riskFactors: Array<{ factor: string; severity: string; detail?: string }>,
): QuickAction[] {
  const actions: QuickAction[] = [];
  const cat = detail.identity_category || '';
  const isDormant = detail.is_dormant === true || detail.activity_status === 'stale' || detail.activity_status === 'never_used';
  const isHighRisk = detail.risk_level === 'critical' || detail.risk_level === 'high';
  const hasCredIssue = detail.credential_risk === 'expired' || detail.credential_risk === 'expiring_soon';
  const isUnowned = !detail.owner_display_name;
  const isPrivileged = privilegeTier === 'T0' || privilegeTier === 'T1';
  const hasEscalation = riskFactors.some(rf => /privilege|escalat|admin|owner/i.test(rf.factor || rf.detail || ''));

  // Disable — dormant or high-risk human/guest
  if (isDormant || (isHighRisk && (cat === 'human_user' || cat === 'guest'))) {
    actions.push({
      id: 'disable', label: 'Disable Identity', icon: ACTION_ICONS.disable,
      description: isDormant ? 'Dormant account — safe to disable' : 'High-risk identity flagged for review',
      navigateTo: `/identities/${encodeURIComponent(detail.identity_id)}?tab=remediation`,
      color: COLORS.danger,
    });
  }

  // Remove privileged role — with projected impact
  if (isPrivileged && roleCount > 0) {
    const currentScore = detail.risk_score ?? 0;
    let reduction = 0;
    const reasons: string[] = [];

    // Privilege tier reduction (T0→T2 or T1→T2)
    const tierDrop = privilegeTier === 'T0' ? 30 : 20;
    reduction += tierDrop;
    reasons.push('Privilege tier reduced');

    // Attack path elimination if privileged roles enable escalation
    if ((detail.attack_path_count ?? 0) > 0 || hasEscalation) {
      reduction += 10;
      reasons.push('Attack path eliminated');
    }

    // Blast radius reduction from losing privileged scope
    if ((detail.blast_radius_score ?? 0) > 40) {
      reduction += 8;
      reasons.push('Blast radius scope narrowed');
    }

    const projected = Math.max(0, currentScore - reduction);

    actions.push({
      id: 'remove_role', label: 'Remove Privileged Role', icon: ACTION_ICONS.remove_role,
      description: `${privilegeTier} with ${roleCount} role${roleCount !== 1 ? 's' : ''} — reduce standing access`,
      navigateTo: `/identities/${encodeURIComponent(detail.identity_id)}?tab=roles`,
      color: '#FF8C42',
      impact: { projectedScore: projected, reasons },
    });
  }

  // Assign owner — unowned service principals / managed identities
  if (isUnowned && (cat === 'service_principal' || cat.startsWith('managed_identity'))) {
    actions.push({
      id: 'assign_owner', label: 'Assign Owner', icon: ACTION_ICONS.assign_owner,
      description: 'No owner assigned — accountability gap',
      navigateTo: `/identities/${encodeURIComponent(detail.identity_id)}?tab=ownership`,
      color: COLORS.warning,
    });
  }

  // Rotate credentials
  if (hasCredIssue) {
    actions.push({
      id: 'rotate', label: 'Rotate Credentials', icon: ACTION_ICONS.rotate,
      description: `Credential status: ${detail.credential_risk || 'unknown'}`,
      navigateTo: `/identities/${encodeURIComponent(detail.identity_id)}?tab=credentials`,
      color: '#A855F7',
    });
  }

  // Create remediation ticket — always available for high risk or escalation paths
  if (isHighRisk || hasEscalation) {
    actions.push({
      id: 'ticket', label: 'Create Remediation Ticket', icon: ACTION_ICONS.ticket,
      description: 'Open a tracked remediation workflow',
      navigateTo: `/identities/${encodeURIComponent(detail.identity_id)}?tab=remediation`,
      color: COLORS.accent,
    });
  }

  // Access review — privileged identities that are active
  if (isPrivileged && !isDormant && actions.length < 4) {
    actions.push({
      id: 'review', label: 'Schedule Access Review', icon: ACTION_ICONS.review,
      description: 'Validate continued need for privileged access',
      navigateTo: `/identities/${encodeURIComponent(detail.identity_id)}?tab=compliance`,
      color: COLORS.success,
    });
  }

  // Fallback — always show at least the ticket action
  if (actions.length === 0) {
    actions.push({
      id: 'ticket', label: 'Create Remediation Ticket', icon: ACTION_ICONS.ticket,
      description: 'Open a tracked remediation workflow',
      navigateTo: `/identities/${encodeURIComponent(detail.identity_id)}?tab=remediation`,
      color: COLORS.accent,
    });
  }

  return actions.slice(0, 4);
}

function ActionRow({ action, detail, onNavigate }: { action: QuickAction; detail: IdentityDetail; onNavigate: (path: string) => void }) {
  const [hover, setHover] = useState(false);
  const a = action;
  const impact = a.impact;
  const currentScore = detail.risk_score ?? 0;

  return (
    <div
      onClick={() => onNavigate(a.navigateTo)}
      style={{
        position: 'relative',
        padding: '8px 12px', borderRadius: 6, cursor: 'pointer',
        background: `${a.color}0a`, border: `1px solid ${hover ? a.color + '50' : a.color + '20'}`,
        display: 'flex', alignItems: 'center', gap: 10,
        transition: 'border-color 0.15s, background 0.15s',
      }}
      onMouseEnter={(e) => {
        setHover(true);
        (e.currentTarget as HTMLElement).style.background = `${a.color}14`;
      }}
      onMouseLeave={(e) => {
        setHover(false);
        (e.currentTarget as HTMLElement).style.background = `${a.color}0a`;
      }}
    >
      <span style={{ fontSize: 14, lineHeight: 1, flexShrink: 0 }}>{a.icon}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: a.color, fontFamily: FONT.ui }}>{a.label}</div>
        <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 1 }}>{a.description}</div>
      </div>
      <span style={{ fontSize: 12, color: COLORS.textDim, flexShrink: 0 }}>{'\u203A'}</span>

      {/* Impact preview tooltip */}
      {hover && impact && (
        <div style={{
          position: 'absolute', bottom: '100%', left: 12, marginBottom: 6,
          width: 220, padding: '10px 12px', borderRadius: 8,
          background: '#0f172a', border: `1px solid ${COLORS.border}`,
          boxShadow: '0 6px 20px rgba(0,0,0,0.5)',
          zIndex: 10, pointerEvents: 'none',
        }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui, marginBottom: 8, letterSpacing: '0.03em' }}>
            Risk Score Impact
          </div>

          {/* Current → Projected */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Current Score</span>
            <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: riskDot(detail.risk_level) }}>{currentScore}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 2 }}>
            <span style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Projected Score</span>
            <span style={{ fontSize: 12, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.success }}>{impact.projectedScore}</span>
          </div>

          {/* Delta badge */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 8 }}>
            <span style={{
              fontSize: 10, fontWeight: 700, fontFamily: FONT.mono,
              padding: '1px 6px', borderRadius: 3,
              background: `${COLORS.success}15`, color: COLORS.success,
            }}>
              {impact.projectedScore - currentScore}
            </span>
          </div>

          {/* Reasons */}
          {impact.reasons.length > 0 && (
            <>
              <div style={{ fontSize: 9, color: COLORS.textDim, fontFamily: FONT.ui, marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.03em' }}>
                Reason
              </div>
              {impact.reasons.map((r, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '1px 0' }}>
                  <span style={{ width: 3, height: 3, borderRadius: '50%', background: COLORS.success, flexShrink: 0 }} />
                  <span style={{ fontSize: 10, color: COLORS.text, fontFamily: FONT.ui }}>{r}</span>
                </div>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function QuickActions({ detail, privilegeTier, roleCount, riskFactors, onNavigate }: {
  detail: IdentityDetail;
  privilegeTier: string;
  roleCount: number;
  riskFactors: Array<{ factor: string; severity: string; detail?: string }>;
  onNavigate: (path: string) => void;
}) {
  const actions = deriveActions(detail, privilegeTier, roleCount, riskFactors);

  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        Actions
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {actions.map(a => (
          <ActionRow key={a.id} action={a} detail={detail} onNavigate={onNavigate} />
        ))}
      </div>
    </div>
  );
}

// ─── Privilege Comparison ─────────────────────────────────────────

function PrivilegeComparison({ detail }: { detail: IdentityDetail }) {
  const { withConnection } = useConnection();
  const [stats, setStats] = useState<{ tierPct: number; blastPct: number; total: number } | null>(null);

  useEffect(() => {
    fetch(withConnection('/api/identities?limit=2000'))
      .then(r => r.ok ? r.json() : { identities: [] })
      .then(data => {
        const all: Array<{ privilege_tier?: string | number; risk_score: number }> = data.identities || [];
        if (all.length < 2) return;

        // Normalize tier to number: "T0"→0, "T1"→1, etc.
        const tierNum = (t: any): number => {
          if (t == null) return 3;
          if (typeof t === 'number') return t;
          const s = String(t).replace(/^T/i, '');
          const n = parseInt(s, 10);
          return isNaN(n) ? 3 : n;
        };
        const myTier = tierNum(detail.privilege_tier);
        const myBlast = detail.blast_radius_score ?? 0;

        // Privilege tier: lower tier = more privileged. Percentile = % of identities with a HIGHER (less privileged) tier.
        const higherTier = all.filter(i => tierNum(i.privilege_tier) > myTier).length;
        const tierPct = Math.round((higherTier / all.length) * 100);

        // Blast radius: higher = more impactful. Percentile = % of identities with a LOWER blast radius.
        // Use risk_score as proxy since blast_radius_score isn't in list response
        const lowerBlast = all.filter(i => (i.risk_score ?? 0) < myBlast).length;
        const blastPct = myBlast > 0 ? Math.round((lowerBlast / all.length) * 100) : 0;

        setStats({ tierPct, blastPct, total: all.length });
      })
      .catch(() => {});
  }, [detail.identity_id, detail.privilege_tier, detail.blast_radius_score, withConnection]);

  if (!stats || stats.total < 2) return null;

  const rows: Array<{ label: string; pct: number; description: string }> = [];

  if (stats.tierPct > 0) {
    rows.push({
      label: 'Privilege Level',
      pct: stats.tierPct,
      description: `Higher than ${stats.tierPct}% of identities in this tenant`,
    });
  }

  if (stats.blastPct > 0) {
    rows.push({
      label: 'Blast Radius',
      pct: stats.blastPct,
      description: `Greater than ${stats.blastPct}% of identities in this tenant`,
    });
  }

  if (rows.length === 0) return null;

  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        Privilege Comparison
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {rows.map(r => {
          const barColor = r.pct >= 90 ? COLORS.danger : r.pct >= 70 ? '#FF8C42' : r.pct >= 40 ? COLORS.warning : COLORS.success;
          return (
            <div key={r.label} style={{
              padding: '10px 12px', borderRadius: 8,
              background: COLORS.surfaceAlt || '#0f1729',
              border: `1px solid ${COLORS.border}`,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>{r.label}</span>
                <span style={{
                  fontSize: 11, fontWeight: 700, padding: '1px 8px', borderRadius: 10,
                  background: `${barColor}18`, color: barColor,
                  fontFamily: FONT.mono,
                }}>
                  P{r.pct}
                </span>
              </div>
              {/* Percentile bar */}
              <div style={{ height: 4, borderRadius: 2, background: COLORS.border, overflow: 'hidden', marginBottom: 6 }}>
                <div style={{
                  width: `${r.pct}%`, height: '100%', borderRadius: 2,
                  background: barColor, transition: 'width 0.4s ease',
                }} />
              </div>
              <div style={{ fontSize: 10, color: COLORS.textDim, fontFamily: FONT.ui }}>
                {r.description}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Recent Risk Changes ─────────────────────────────────────────

function deriveChangeReasons(detail: IdentityDetail): string[] {
  const reasons: string[] = [];
  const factors = detail.risk_factors || [];

  for (const rf of factors) {
    const text = (rf.factor || rf.detail || rf.description || '').toLowerCase();
    if (/role.*assign|new.*role|contributor|owner role|reader role/i.test(text))
      reasons.push(rf.factor || rf.description || rf.detail || 'Role assignment change');
    else if (/attack.*path|lateral|escalat/i.test(text))
      reasons.push('New attack path detected');
    else if (/credential.*expir|secret.*expir|cert.*expir/i.test(text))
      reasons.push('Credential expiration detected');
    else if (/dormant|inactive|stale/i.test(text))
      reasons.push('Dormancy status change');
    else if (/privilege|admin|tier/i.test(text))
      reasons.push('Privilege level change');
    else if (/owner|unowned|no.*owner/i.test(text))
      reasons.push('Ownership gap identified');
    else if (/mfa|conditional.*access|authentication/i.test(text))
      reasons.push('Authentication policy change');
  }

  // Deduplicate
  const unique = Array.from(new Set(reasons));

  // Fallback if no specific reasons derived
  if (unique.length === 0 && detail.trend?.risk_direction === 'worsened')
    unique.push('Risk factors increased since last scan');
  if (unique.length === 0 && detail.trend?.risk_direction === 'improved')
    unique.push('Risk factors reduced since last scan');

  return unique.slice(0, 4);
}

function RecentRiskChanges({ detail }: { detail: IdentityDetail }) {
  const trend = detail.trend;
  if (!trend || trend.previous_risk_score == null) return null;

  const current = detail.risk_score ?? 0;
  const previous = trend.previous_risk_score;
  const delta = current - previous;
  const direction = trend.risk_direction || (delta > 0 ? 'worsened' : delta < 0 ? 'improved' : 'unchanged');

  if (direction === 'unchanged' && delta === 0) return null;

  const isNew = trend.is_new === true;
  const deltaColor = delta > 0 ? COLORS.danger : delta < 0 ? COLORS.success : COLORS.textSecondary;
  const directionLabel = isNew ? 'New Identity' : direction === 'worsened' ? 'Increased' : direction === 'improved' ? 'Decreased' : 'Unchanged';
  const reasons = deriveChangeReasons(detail);

  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        Recent Risk Changes
      </div>
      <div style={{
        padding: '12px 14px', borderRadius: 8,
        background: COLORS.surfaceAlt || '#0f1729',
        border: `1px solid ${COLORS.border}`,
      }}>
        {/* Score delta row */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Risk Score Change</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 2 }}>
              <span style={{ fontSize: 22, fontWeight: 700, fontFamily: FONT.mono, color: deltaColor }}>
                {isNew ? 'NEW' : `${delta > 0 ? '+' : ''}${delta}`}
              </span>
              <span style={{
                fontSize: 9, fontWeight: 600, padding: '1px 6px', borderRadius: 3,
                background: `${deltaColor}15`, color: deltaColor,
                fontFamily: FONT.ui, textTransform: 'uppercase',
              }}>
                {directionLabel}
              </span>
            </div>
          </div>
          {/* Previous → Current */}
          {!isNew && (
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 9, color: COLORS.textDim, fontFamily: FONT.ui }}>Previous</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 1 }}>
                <span style={{ fontSize: 13, fontWeight: 600, fontFamily: FONT.mono, color: COLORS.textSecondary }}>{previous}</span>
                <span style={{ fontSize: 10, color: COLORS.textDim }}>{'\u2192'}</span>
                <span style={{ fontSize: 13, fontWeight: 700, fontFamily: FONT.mono, color: riskDot(detail.risk_level) }}>{current}</span>
              </div>
            </div>
          )}
        </div>

        {/* Change reasons */}
        {reasons.length > 0 && (
          <div style={{ marginTop: 10, borderTop: `1px solid ${COLORS.border}`, paddingTop: 8 }}>
            <div style={{ fontSize: 9, color: COLORS.textDim, fontFamily: FONT.ui, marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.03em' }}>
              Reason
            </div>
            {reasons.map((r, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '2px 0' }}>
                <span style={{ width: 4, height: 4, borderRadius: '50%', background: deltaColor, flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{r}</span>
              </div>
            ))}
          </div>
        )}

        {/* Level change badge */}
        {!isNew && trend.previous_risk_level && trend.previous_risk_level !== detail.risk_level && (
          <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{
              fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 3,
              background: riskDot(trend.previous_risk_level) + '22',
              color: riskDot(trend.previous_risk_level),
              fontFamily: FONT.ui, textTransform: 'uppercase',
            }}>
              {trend.previous_risk_level}
            </span>
            <span style={{ fontSize: 10, color: COLORS.textDim }}>{'\u2192'}</span>
            <span style={{
              fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 3,
              background: riskDot(detail.risk_level) + '22',
              color: riskDot(detail.risk_level),
              fontFamily: FONT.ui, textTransform: 'uppercase',
            }}>
              {detail.risk_level}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Detail View ─────────────────────────────────────────────────

function DetailView({ detail, loading, error, onBack, onClose, onOpenFull, onNavigate }: {
  detail: IdentityDetail | null;
  loading: boolean;
  error: string | null;
  onBack: () => void;
  onClose: () => void;
  onOpenFull: (identityId: string) => void;
  onNavigate: (path: string) => void;
}) {
  if (loading && !detail) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1 }}>
        <div style={{
          width: 28, height: 28, borderRadius: '50%',
          border: `3px solid ${COLORS.border}`, borderTopColor: COLORS.accent,
          animation: 'spin 1s linear infinite',
        }} />
      </div>
    );
  }

  if (error || !detail) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flex: 1, padding: 24, gap: 16 }}>
        <div style={{ fontSize: 13, color: COLORS.textSecondary, fontFamily: FONT.ui, textAlign: 'center', maxWidth: 280 }}>
          {error || 'Identity not found.'}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={onBack}
            style={{
              padding: '6px 16px', borderRadius: 6, fontSize: 12, fontWeight: 600, fontFamily: FONT.ui,
              background: COLORS.accent + '18', border: `1px solid ${COLORS.accent}44`,
              color: COLORS.accent, cursor: 'pointer',
            }}
          >
            Back
          </button>
          <button
            onClick={onClose}
            style={{
              padding: '6px 16px', borderRadius: 6, fontSize: 12, fontWeight: 600, fontFamily: FONT.ui,
              background: 'none', border: `1px solid ${COLORS.border}`,
              color: COLORS.textSecondary, cursor: 'pointer',
            }}
          >
            Close
          </button>
        </div>
      </div>
    );
  }

  const roleCount = detail.role_count ?? ((detail as any).roles?.length ?? ((detail.rbac_role_count ?? 0) + (detail.entra_role_count ?? 0)));
  // API returns privilege_tier as "T0"/"T1"/"T2"/"T3" (string) or number 0-3
  const rawTier = detail.privilege_tier;
  const privilegeTier = rawTier == null ? 'T3'
    : typeof rawTier === 'string' && rawTier.startsWith('T') ? rawTier
    : `T${rawTier}`;
  const riskFactors = (detail.risk_factors || []).map((rf: any) => ({
    factor: rf.factor || rf.description || rf.code || '',
    severity: rf.severity || 'medium',
    detail: rf.detail || rf.description || '',
  }));
  const blastRadius = detail.blast_radius_score ?? 0;
  const attackPaths = detail.attack_path_count ?? 0;

  const fields: Array<{ label: string; value: React.ReactNode }> = [
    { label: 'Identity Name', value: detail.display_name || detail.identity_id },
    { label: 'Identity Type', value: categoryLabel(detail.identity_category) },
    { label: 'Privilege Tier', value: (
      <span style={{
        padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700, fontFamily: FONT.mono,
        background: privilegeTier === 'T0' ? COLORS.danger + '22' : privilegeTier === 'T1' ? '#FF8C42' + '22' : COLORS.surfaceAlt,
        color: privilegeTier === 'T0' ? COLORS.danger : privilegeTier === 'T1' ? '#FF8C42' : COLORS.textSecondary,
      }}>
        {privilegeTier}
      </span>
    )},
    { label: 'Assigned Roles', value: (
      <span style={{ fontFamily: FONT.mono, fontWeight: 600, color: COLORS.text }}>{roleCount}</span>
    )},
    { label: 'Created', value: (
      <span style={{ fontFamily: FONT.mono, fontSize: 11, color: COLORS.textSecondary }}>
        {(detail as any).created_datetime
          ? new Date((detail as any).created_datetime).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
          : 'Unknown'}
      </span>
    )},
    { label: 'Blast Radius Score', value: (
      <span style={{ fontFamily: FONT.mono, fontWeight: 700, color: blastRadius > 60 ? COLORS.danger : blastRadius > 30 ? COLORS.warning : COLORS.success }}>
        {blastRadius}
      </span>
    )},
    { label: 'Attack Path Count', value: (
      <span style={{ fontFamily: FONT.mono, fontWeight: 700, color: attackPaths > 0 ? COLORS.danger : COLORS.textSecondary }}>
        {attackPaths}
      </span>
    )},
  ];

  return (
    <>
      {/* Sticky Header */}
      <div style={{
        position: 'sticky', top: 0, zIndex: 2,
        padding: '16px 20px',
        borderBottom: `1px solid ${COLORS.border}`,
        background: COLORS.surface,
        display: 'flex', alignItems: 'center', gap: 12,
      }}>
        <button
          onClick={onBack}
          style={{
            background: 'none', border: 'none', color: COLORS.textSecondary,
            cursor: 'pointer', fontSize: 16, fontFamily: FONT.ui, padding: '0 4px',
          }}
        >
          ←
        </button>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontSize: 14, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui,
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {detail.display_name || detail.identity_id}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 2 }}>
            <span style={{
              fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 3,
              background: riskDot(detail.risk_level) + '22',
              color: riskDot(detail.risk_level),
              fontFamily: FONT.ui, textTransform: 'uppercase',
            }}>
              {detail.risk_level}
            </span>
            <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
              {categoryLabel(detail.identity_category)}
            </span>
          </div>
        </div>

        {/* Severity badge — replaces raw numeric score */}
        <span style={{
          fontFamily: FONT.mono,
          fontSize: 11, fontWeight: 700,
          padding: '4px 10px', borderRadius: 6,
          letterSpacing: '0.5px', textTransform: 'uppercase',
          background: riskDot(detail.risk_level) + '33',
          color: riskDot(detail.risk_level),
          border: `1px solid ${riskDot(detail.risk_level)}66`,
        }}>
          {detail.risk_level ?? 'INFO'}
        </span>

        <button
          onClick={onClose}
          style={{ background: 'none', border: 'none', color: COLORS.textSecondary, cursor: 'pointer', fontSize: 20, fontFamily: FONT.ui }}
        >
          ×
        </button>
      </div>

      {/* Detail fields */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 20px' }}>
        {fields.map(f => (
          <div key={f.label} style={{
            padding: '10px 0',
            borderBottom: `1px solid ${COLORS.border}22`,
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui }}>{f.label}</span>
            <span style={{ fontSize: 12, color: COLORS.text, fontFamily: FONT.ui, textAlign: 'right', maxWidth: '60%' }}>
              {f.value}
            </span>
          </div>
        ))}

        {/* Activity Signals — architecture-derived, no log dependency */}
        <ActivitySignals detail={detail} />

        {/* Risk factors section */}
        {riskFactors.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Risk Factors
            </div>
            {riskFactors.slice(0, 6).map((rf, i) => (
              <div key={i} style={{
                padding: '6px 10px', marginBottom: 4, borderRadius: 6,
                background: COLORS.surfaceAlt || '#0f1729',
                display: 'flex', alignItems: 'center', gap: 8,
              }}>
                <span style={{
                  fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 3,
                  background: rf.severity === 'critical' ? COLORS.danger + '22' :
                              rf.severity === 'high' ? '#FF8C42' + '22' :
                              rf.severity === 'medium' ? COLORS.warning + '22' : COLORS.border,
                  color: rf.severity === 'critical' ? COLORS.danger :
                         rf.severity === 'high' ? '#FF8C42' :
                         rf.severity === 'medium' ? COLORS.warning : COLORS.textSecondary,
                  textTransform: 'uppercase',
                  fontFamily: FONT.ui,
                }}>
                  {rf.severity || 'info'}
                </span>
                <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>
                  {rf.factor || rf.detail || 'Unknown factor'}
                </span>
              </div>
            ))}
          </div>
        )}

        {/* AI Explanation Panel */}
        <AIExplanationPanel identityId={detail.identity_id} />

        {/* Privilege Comparison */}
        <PrivilegeComparison detail={detail} />

        {/* Recent Risk Changes */}
        <RecentRiskChanges detail={detail} />

        {/* Risk Score Breakdown */}
        <RiskScoreBreakdown detail={detail} />

        {/* Identity Timeline */}
        <IdentityTimeline identityId={detail.identity_id} />

        {/* Actions section */}
        <QuickActions detail={detail} privilegeTier={privilegeTier} roleCount={roleCount} riskFactors={riskFactors} onNavigate={onNavigate} />
      </div>

      {/* Footer */}
      <div style={{ padding: '12px 20px', borderTop: `1px solid ${COLORS.border}` }}>
        <button
          onClick={() => onOpenFull(detail.identity_id || String(detail.db_id || ''))}
          style={{
            width: '100%', padding: '8px 0',
            background: COLORS.accent + '18',
            border: `1px solid ${COLORS.accent}44`,
            borderRadius: 6, cursor: 'pointer',
            fontSize: 12, fontWeight: 600, color: COLORS.accent, fontFamily: FONT.ui,
          }}
        >
          Open Full Identity Page →
        </button>
      </div>
    </>
  );
}
