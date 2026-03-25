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

// ─── Filter label mapping ────────────────────────────────────────

const FILTER_LABELS: Record<string, string> = {
  'pillar=effective-privilege': 'Effective Privilege Risk',
  'pillar=credential-risk': 'Credential Exposure',
  'pillar=credential-hygiene': 'Credential Hygiene',
  'pillar=external-exposure': 'External Exposure',
  'pillar=dormant-risk': 'Dormant Risk',
  'pillar=compliance-alignment': 'Compliance Alignment',
  'risk_level=critical': 'Critical Risk Identities',
  'risk_level=high': 'High Risk Identities',
  'risk_level=medium': 'Medium Risk Identities',
  'privilege_tier=0': 'T0 Administrators',
  'privilege_tier=0,1': 'T0/T1 Privileged',
  'activity_status=dormant': 'Dormant Identities',
  'activity_status=stale': 'Dormant Privileged Identities',
  'identity_category=guest': 'Guest Identities',
  'identity_category=service_principal': 'Service Principals',
  'identity_category=human_user': 'Human Users',
  'credential_status=expired': 'Expired Credentials',
  'sort=blast_radius_score': 'High Blast Radius Identities',
  'sort=risk_score': 'Highest Risk Identities',
};

// Maps filter query params to risk driver labels for drawer context header
const DRIVER_LABELS: Record<string, string> = {
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

// ─── Types ───────────────────────────────────────────────────────

interface IdentityRow {
  identity_id: string;
  db_id?: number;
  display_name: string;
  identity_category: string;
  risk_level: string;
  risk_score: number;
  privilege_tier?: number;
  role_count?: number;
}

interface IdentityDetail {
  identity_id: string;
  db_id: number;
  display_name: string;
  identity_type: string;
  identity_category: string;
  risk_level: string;
  risk_score: number;
  privilege_tier?: number;
  role_count?: number;
  rbac_role_count?: number;
  entra_role_count?: number;
  last_seen_auth?: string | null;
  last_sign_in?: string | null;
  risk_factors?: Array<{ factor: string; severity: string; detail?: string }>;
  blast_radius_score?: number;
  attack_path_count?: number;
  credential_count?: number;
  credential_risk?: string;
  activity_status?: string;
  owner_display_name?: string | null;
  trend?: {
    previous_risk_level?: string | null;
    previous_risk_score?: number | null;
    risk_direction?: string;
    is_new?: boolean;
  } | null;
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

  const open = ctx?.state.open ?? false;
  const filterUrl = ctx?.state.filterUrl ?? null;
  const selectedIdentityId = ctx?.state.selectedIdentityId ?? null;
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
    if (!selectedIdentityId) { setDetail(null); return; }
    setDetailLoading(true);

    // Find the identity_id (string) from the list
    const match = identities.find(i => (i.db_id ?? 0) === selectedIdentityId || i.identity_id === String(selectedIdentityId));
    const idParam = match?.identity_id || String(selectedIdentityId);

    fetch(withConnection(`/api/identities/${encodeURIComponent(idParam)}`))
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        setDetail(data);
        setDetailLoading(false);
      })
      .catch(() => {
        setDetail(null);
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
        {selectedIdentityId && detail
          ? <DetailView
              detail={detail}
              loading={detailLoading}
              onBack={backToList}
              onClose={closeDrawer}
              onOpenFull={(id) => { closeDrawer(); navigate(`/identities/${encodeURIComponent(id)}`); }}
              onNavigate={(path) => { closeDrawer(); navigate(path); }}
            />
          : <ListView
              filterUrl={filterUrl || ''}
              identities={identities}
              loading={loading}
              onSelect={(row) => selectIdentity(row.db_id ?? parseInt(row.identity_id, 10))}
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
  if (query.includes('pillar=effective-privilege') || query.includes('contributing_pillar=effective_privilege')) {
    const tier = row.privilege_tier != null ? `T${row.privilege_tier}` : null;
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
    return { label: 'Blast', value: String(row.risk_score), color: COLORS.danger };
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

              {/* Name + category */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui,
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {row.display_name || row.identity_id}
                </div>
                <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 1 }}>
                  {categoryLabel(row.identity_category)}
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

              {/* Risk score */}
              <div style={{
                fontSize: 13, fontWeight: 700, fontFamily: FONT.mono,
                color: riskDot(row.risk_level),
                minWidth: 28, textAlign: 'right',
              }}>
                {row.risk_score}
              </div>
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

function computeDetailRisk(d: IdentityDetail): { label: string; points: number; max: number }[] {
  const factors: { label: string; points: number; max: number }[] = [];

  // Privilege Tier (0–30)
  const tier = d.privilege_tier ?? 3;
  const tierPts = tier === 0 ? 30 : tier === 1 ? 20 : tier === 2 ? 8 : 0;
  factors.push({ label: 'Privilege Tier', points: tierPts, max: 30 });

  // Blast Radius (0–25)
  const brPts = Math.min(25, Math.round(((d.blast_radius_score ?? 0) / 100) * 25));
  factors.push({ label: 'Blast Radius', points: brPts, max: 25 });

  // Dormancy (0–15)
  const isDormant = d.activity_status === 'stale' || d.activity_status === 'never_used' || d.activity_status === 'inactive';
  factors.push({ label: 'Dormancy', points: isDormant ? 15 : 0, max: 15 });

  // Credential Risk (0–15)
  const hasCred = d.credential_risk === 'expired' || d.credential_risk === 'expiring_soon'
    || (d.risk_factors || []).some(rf => /credential|secret|cert|expired/i.test(rf.factor || rf.detail || ''));
  factors.push({ label: 'Credential Risk', points: hasCred ? 15 : 0, max: 15 });

  // Attack Path Participation (0–10)
  const apPts = (d.attack_path_count ?? 0) > 0 ? 10 : d.risk_score >= 80 ? 10 : d.risk_score >= 60 ? 6 : d.risk_score >= 40 ? 3 : 0;
  factors.push({ label: 'Attack Path Participation', points: apPts, max: 10 });

  // Ownership Status (0–5)
  const unowned = !d.owner_display_name;
  const isMachine = d.identity_category === 'service_principal' || d.identity_category?.startsWith('managed_identity');
  factors.push({ label: 'Ownership Status', points: unowned && isMachine ? 5 : 0, max: 5 });

  return factors;
}

function RiskScoreBreakdown({ detail }: { detail: IdentityDetail }) {
  const factors = computeDetailRisk(detail);
  const total = Math.min(100, factors.reduce((s, f) => s + f.points, 0));
  const totalColor = total >= 75 ? COLORS.danger : total >= 50 ? '#FF8C42' : total >= 25 ? COLORS.warning : COLORS.success;

  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        Risk Score Breakdown
      </div>
      <div style={{
        padding: '10px 12px', borderRadius: 8,
        background: COLORS.surfaceAlt || '#0f1729',
        border: `1px solid ${COLORS.border}`,
      }}>
        {factors.map(f => {
          const pct = f.max > 0 ? (f.points / f.max) * 100 : 0;
          const barColor = f.points === 0 ? COLORS.textDim
            : pct >= 80 ? COLORS.danger
            : pct >= 50 ? '#FF8C42'
            : COLORS.warning;
          return (
            <div key={f.label} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0' }}>
              <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, width: 140, flexShrink: 0 }}>
                {f.label}
              </span>
              <div style={{ flex: 1, height: 4, borderRadius: 2, background: `${COLORS.border}`, overflow: 'hidden' }}>
                <div style={{ width: `${pct}%`, height: '100%', borderRadius: 2, background: barColor, transition: 'width 0.3s ease' }} />
              </div>
              <span style={{
                fontSize: 10, fontWeight: 700, fontFamily: FONT.mono, width: 24, textAlign: 'right', flexShrink: 0,
                color: f.points > 0 ? COLORS.text : COLORS.textDim,
              }}>
                {f.points}
              </span>
            </div>
          );
        })}
        {/* Total */}
        <div style={{
          borderTop: `1px solid ${COLORS.border}`, marginTop: 6, paddingTop: 6,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span style={{ fontSize: 10, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui }}>Total</span>
          <span style={{ fontSize: 13, fontWeight: 700, color: totalColor, fontFamily: FONT.mono }}>{total}</span>
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
  const isDormant = detail.activity_status === 'stale' || detail.activity_status === 'never_used';
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
        const all: Array<{ privilege_tier?: number; risk_score: number }> = data.identities || [];
        if (all.length < 2) return;

        const myTier = detail.privilege_tier ?? 3;
        const myBlast = detail.blast_radius_score ?? 0;

        // Privilege tier: lower tier = more privileged. Percentile = % of identities with a HIGHER (less privileged) tier.
        const higherTier = all.filter(i => (i.privilege_tier ?? 3) > myTier).length;
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
    const text = (rf.factor || rf.detail || '').toLowerCase();
    if (/role.*assign|new.*role|contributor|owner role|reader role/i.test(text))
      reasons.push(rf.factor || rf.detail || 'Role assignment change');
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

function DetailView({ detail, loading, onBack, onClose, onOpenFull, onNavigate }: {
  detail: IdentityDetail;
  loading: boolean;
  onBack: () => void;
  onClose: () => void;
  onOpenFull: (identityId: string) => void;
  onNavigate: (path: string) => void;
}) {
  if (loading || !detail) {
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

  const roleCount = detail.role_count ?? ((detail.rbac_role_count ?? 0) + (detail.entra_role_count ?? 0));
  const privilegeTier = detail.privilege_tier != null ? `T${detail.privilege_tier}` : 'T3';
  const riskFactors = detail.risk_factors || [];
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
    { label: 'Last Authentication', value: (
      <span style={{ fontFamily: FONT.mono, fontSize: 11, color: COLORS.textSecondary }}>
        {detail.last_seen_auth ? new Date(detail.last_seen_auth).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : 'Never'}
      </span>
    )},
    { label: 'Last Activity', value: (() => {
      const candidates = [detail.last_seen_auth, detail.last_sign_in].filter(Boolean) as string[];
      const latest = candidates.length > 0 ? candidates.sort((a, b) => new Date(b).getTime() - new Date(a).getTime())[0] : null;
      if (!latest) return <span style={{ fontFamily: FONT.mono, fontSize: 11, color: COLORS.textDim }}>No activity recorded</span>;
      const days = Math.floor((Date.now() - new Date(latest).getTime()) / 86400000);
      const color = days > 90 ? COLORS.danger : days > 30 ? COLORS.warning : COLORS.success;
      return (
        <span style={{ fontFamily: FONT.mono, fontSize: 11, fontWeight: 600, color }}>
          {timeAgo(latest)}
        </span>
      );
    })()},
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

        {/* Composite risk score badge */}
        <div style={{
          width: 36, height: 36, borderRadius: '50%',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: riskDot(detail.risk_level) + '22',
          border: `2px solid ${riskDot(detail.risk_level)}`,
          fontSize: 13, fontWeight: 700, fontFamily: FONT.mono,
          color: riskDot(detail.risk_level),
        }}>
          {detail.risk_score}
        </div>

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
          onClick={() => onOpenFull(detail.identity_id)}
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
