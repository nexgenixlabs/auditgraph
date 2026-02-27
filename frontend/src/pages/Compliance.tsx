import { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';

/* ───────── Types ───────── */

interface EvidenceIdentity {
  id: number;
  identity_id: string;
  display_name: string;
  risk_level: string;
  risk_score: number;
  identity_category: string;
  reason: string;
}

interface IntelControl {
  control_id: string;
  name: string;
  status: 'pass' | 'warn' | 'fail';
  detail: string;
  metric: string;
  value: number;
  pass_threshold: string;
  drilldown_url: string | null;
  severity: string;
  weight: number;
  cloud: string;
  pillar: string | null;
  root_cause_id: number | null;
  evidence_identities: EvidenceIdentity[];
  evidence_count: number;
}

interface IntelFramework {
  name: string;
  version: string | null;
  score: number;
  risk_weighted_score: number;
  pass_count: number;
  warn_count: number;
  fail_count: number;
  total_controls: number;
  controls: IntelControl[];
  tier?: string;
  category?: string;
  short_name?: string;
  identity_controls_count?: number;
  total_framework_controls?: number;
  scope_label?: string;
}

interface IntelligenceData {
  overall_score: number;
  risk_weighted_score: number;
  total_controls: number;
  passing: number;
  warnings: number;
  failing: number;
  cloud_failures: Record<string, number>;
  top_risk_drivers: { control_id: string; name: string; framework: string; severity: string; weight: number; value: number }[];
  frameworks: Record<string, IntelFramework>;
  root_causes: unknown[];
  trend_mini: { run_id: number; date: string | null; overall_score: number }[];
  tier_summary?: Record<string, { tier: string; category: string; frameworks: number; total_controls: number; passing: number; warnings: number; failing: number; score: number }>;
  generated_at: string;
}

/* ───────── Constants ───────── */

const C = {
  bg: 'var(--bg-primary)',
  card: 'var(--bg-secondary)',
  border: 'var(--border-default)',
  critical: '#EF4444',
  warning: '#F59E0B',
  good: '#22C55E',
  text: 'var(--text-primary)',
  textMuted: 'var(--text-secondary)',
  textDim: 'var(--text-tertiary)',
  accent: '#F59E0B',
  accentBlue: '#3B82F6',
};

const mono = "'JetBrains Mono', 'Fira Code', monospace";

const TIER_CONFIG: Record<string, { label: string; order: number }> = {
  core:      { label: "Core Governance", order: 0 },
  industry:  { label: "Industry Specific", order: 1 },
  privacy:   { label: "Privacy & Data Protection", order: 2 },
  benchmark: { label: "Technical Benchmarks", order: 3 },
};

const STATUS_META: Record<string, { label: string; color: string; badge: string }> = {
  fail: { label: 'Fail', color: C.critical, badge: 'bg-red-50 text-red-700 border-red-200' },
  warn: { label: 'Warn', color: C.warning, badge: 'bg-amber-50 text-amber-700 border-amber-200' },
  pass: { label: 'Pass', color: C.good, badge: 'bg-emerald-50 text-emerald-700 border-emerald-200' },
};
const STATUS_ORDER: Record<string, number> = { fail: 0, warn: 1, pass: 2 };

/* ───────── Evidence Source Logic ───────── */

function evidenceSource(ctrl: IntelControl): string {
  if (ctrl.pillar) return ctrl.pillar.replace(/_/g, ' ');
  if (ctrl.cloud && ctrl.cloud !== 'azure') return `${ctrl.cloud} identity`;
  if (ctrl.metric) return ctrl.metric.replace(/_/g, ' ');
  return 'Identity audit';
}

/* ───────── Main Component ───────── */

export default function Compliance() {
  const [data, setData] = useState<IntelligenceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { withConnection, selectedConnectionId } = useConnection();
  const [searchParams] = useSearchParams();
  const highlightFramework = searchParams.get('framework') || '';
  const [expandedFw, setExpandedFw] = useState<string | null>(null);
  const [expandedCtrl, setExpandedCtrl] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const navigate = useNavigate();

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(withConnection('/api/compliance/intelligence'));
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        setData(await res.json());
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : 'Failed to load compliance data');
      } finally {
        setLoading(false);
      }
    })();
  }, [selectedConnectionId]);

  // Auto-expand when navigating from Overview
  useEffect(() => {
    if (highlightFramework && data) {
      setExpandedFw(highlightFramework);
      setTimeout(() => {
        document.getElementById(`fw-${highlightFramework}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 300);
    }
  }, [highlightFramework, data]);

  /* Loading */
  if (loading) {
    return (
      <div style={{ minHeight: 400, display: 'flex', alignItems: 'center', justifyContent: 'center', background: C.bg }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ width: 32, height: 32, borderRadius: '50%', border: `3px solid ${C.border}`, borderTopColor: C.accentBlue, animation: 'spin 1s linear infinite', margin: '0 auto 12px' }} />
          <div style={{ fontSize: 12, color: C.textMuted }}>Loading compliance data...</div>
        </div>
        <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      </div>
    );
  }

  /* Error */
  if (error || !data) {
    return (
      <div style={{ padding: 32, maxWidth: 1200, margin: '0 auto' }}>
        <div style={{ borderRadius: 12, padding: 24, textAlign: 'center', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
          <p style={{ color: C.critical, fontWeight: 600 }}>{error || 'No compliance data available'}</p>
          <p style={{ color: C.textMuted, fontSize: 13, marginTop: 4 }}>
            Capture a snapshot to generate compliance posture data.
          </p>
        </div>
      </div>
    );
  }

  /* Group frameworks by tier */
  const tierGroups: Record<string, IntelFramework[]> = {};
  for (const fw of Object.values(data.frameworks)) {
    const tier = fw.tier || 'core';
    if (!tierGroups[tier]) tierGroups[tier] = [];
    tierGroups[tier].push(fw);
  }
  const sortedTiers = Object.keys(tierGroups).sort(
    (a, b) => (TIER_CONFIG[a]?.order ?? 99) - (TIER_CONFIG[b]?.order ?? 99)
  );

  /* Latest snapshot ID from trend data */
  const latestSnapshotId = data.trend_mini?.length > 0
    ? data.trend_mini[data.trend_mini.length - 1].run_id
    : null;

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1400, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0, color: C.text }}>Compliance Evidence</h1>
          <span style={{
            padding: '3px 10px', borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: mono,
            background: 'rgba(59,130,246,0.08)', color: C.accentBlue,
            border: '1px solid rgba(59,130,246,0.2)', letterSpacing: '0.5px', textTransform: 'uppercase',
          }}>Identity Controls</span>
          {latestSnapshotId && (
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 8px', borderRadius: 4,
              background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)',
              fontSize: 9, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#059669', fontFamily: mono,
            }} title="Snapshot data is immutable — it reflects the state at capture time">
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
              Immutable
            </span>
          )}
        </div>
        <p style={{ margin: 0, fontSize: 13, color: C.textMuted }}>
          Framework controls with status, evidence sources, and snapshot references
        </p>
      </div>

      {/* Summary Strip */}
      <div style={{
        display: 'flex', gap: 20, marginBottom: 20, padding: '14px 20px',
        background: C.card, border: `1px solid ${C.border}`, borderRadius: 10,
        alignItems: 'center', flexWrap: 'wrap',
      }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
          <span style={{ fontSize: 22, fontWeight: 800, fontFamily: mono, color: C.text }}>{data.total_controls}</span>
          <span style={{ fontSize: 11, color: C.textMuted }}>Controls</span>
        </div>
        <div style={{ width: 1, height: 28, background: C.border }} />
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
          <span style={{ fontSize: 22, fontWeight: 800, fontFamily: mono, color: C.good }}>{data.passing}</span>
          <span style={{ fontSize: 11, color: C.textMuted }}>Passing</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
          <span style={{ fontSize: 22, fontWeight: 800, fontFamily: mono, color: C.warning }}>{data.warnings}</span>
          <span style={{ fontSize: 11, color: C.textMuted }}>Warnings</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
          <span style={{ fontSize: 22, fontWeight: 800, fontFamily: mono, color: C.critical }}>{data.failing}</span>
          <span style={{ fontSize: 11, color: C.textMuted }}>Failing</span>
        </div>
        <div style={{ width: 1, height: 28, background: C.border }} />
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
          <span style={{ fontSize: 14, fontWeight: 700, fontFamily: mono, color: C.text }}>
            {Object.keys(data.frameworks).length}
          </span>
          <span style={{ fontSize: 11, color: C.textMuted }}>Frameworks</span>
        </div>
        {latestSnapshotId && (
          <>
            <div style={{ width: 1, height: 28, background: C.border }} />
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 12, fontWeight: 600, fontFamily: mono, color: C.textMuted }}>
                Snapshot #{latestSnapshotId}
              </span>
              <span style={{ fontSize: 10, color: C.textDim }}>
                {new Date(data.generated_at).toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' })}
              </span>
            </div>
          </>
        )}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
          <button
            onClick={() => navigate('/exports')}
            style={{
              padding: '5px 14px', borderRadius: 6, fontSize: 11, fontWeight: 600, fontFamily: mono,
              background: 'transparent', border: `1px solid ${C.border}`, color: C.textMuted, cursor: 'pointer',
            }}
          >Export All</button>
        </div>
      </div>

      {/* Status Filter */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 16 }}>
        {[
          { key: 'all', label: 'All', count: data.total_controls },
          { key: 'fail', label: 'Failing', count: data.failing },
          { key: 'warn', label: 'Warnings', count: data.warnings },
          { key: 'pass', label: 'Passing', count: data.passing },
        ].map(f => (
          <button
            key={f.key}
            onClick={() => setStatusFilter(f.key)}
            style={{
              padding: '4px 12px', borderRadius: 6, fontSize: 11, fontWeight: 600, fontFamily: mono,
              background: statusFilter === f.key ? (f.key === 'fail' ? 'rgba(239,68,68,0.1)' : f.key === 'warn' ? 'rgba(245,158,11,0.1)' : f.key === 'pass' ? 'rgba(34,197,94,0.1)' : 'var(--bg-hover)') : 'transparent',
              border: `1px solid ${statusFilter === f.key ? (STATUS_META[f.key]?.color || C.border) + '40' : C.border}`,
              color: statusFilter === f.key ? (STATUS_META[f.key]?.color || C.text) : C.textMuted,
              cursor: 'pointer',
            }}
          >
            {f.label} ({f.count})
          </button>
        ))}
      </div>

      {/* Framework Tables */}
      {sortedTiers.map(tier => {
        const cfg = TIER_CONFIG[tier] || { label: tier, order: 99 };
        const fws = tierGroups[tier];

        return (
          <div key={tier} style={{ marginBottom: 24 }}>
            {/* Tier Header */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12,
              padding: '8px 0', borderBottom: `1px solid ${C.border}`,
            }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: C.text, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                {cfg.label}
              </span>
              <span style={{ fontSize: 11, fontFamily: mono, color: C.textDim }}>
                {fws.length} framework{fws.length !== 1 ? 's' : ''}
              </span>
              {tier === 'benchmark' && (
                <span style={{ fontSize: 10, color: C.textDim, fontStyle: 'italic', marginLeft: 8 }}>
                  Not included in executive posture score
                </span>
              )}
            </div>

            {/* Each Framework */}
            {fws.map(fw => {
              const fwId = fw.short_name || fw.name || '';
              const isExpanded = expandedFw === fwId;

              const sorted = [...fw.controls].sort(
                (a, b) => (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9) || b.weight - a.weight
              );
              const filtered = statusFilter === 'all' ? sorted : sorted.filter(c => c.status === statusFilter);

              return (
                <div key={fwId} id={`fw-${fwId}`} style={{ marginBottom: 16 }}>
                  {/* Framework Header Row */}
                  <button
                    onClick={() => setExpandedFw(isExpanded ? null : fwId)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 12, width: '100%', textAlign: 'left',
                      padding: '10px 14px', borderRadius: 8, cursor: 'pointer',
                      background: isExpanded ? 'var(--bg-hover)' : C.card,
                      border: `1px solid ${isExpanded ? C.accentBlue + '30' : C.border}`,
                      transition: 'all 0.15s',
                    }}
                  >
                    <span style={{ fontSize: 9, color: C.textDim, transition: 'transform 0.2s', transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)' }}>&#9654;</span>
                    <span style={{ fontSize: 13, fontWeight: 700, color: C.text, flex: 1 }}>{fw.short_name || fw.name}</span>
                    {fw.version && <span style={{ fontSize: 10, fontFamily: mono, color: C.textDim }}>{fw.version}</span>}
                    <span style={{ fontSize: 11, fontFamily: mono, fontWeight: 600, color: C.good }}>{fw.pass_count} pass</span>
                    {fw.warn_count > 0 && <span style={{ fontSize: 11, fontFamily: mono, fontWeight: 600, color: C.warning }}>{fw.warn_count} warn</span>}
                    {fw.fail_count > 0 && <span style={{ fontSize: 11, fontFamily: mono, fontWeight: 600, color: C.critical }}>{fw.fail_count} fail</span>}
                    <span style={{ fontSize: 11, fontFamily: mono, color: C.textDim }}>
                      {fw.identity_controls_count ?? fw.total_controls} controls
                    </span>
                  </button>

                  {/* Expanded: Controls Table */}
                  {isExpanded && (
                    <div style={{
                      marginTop: 4, background: C.card, border: `1px solid ${C.border}`,
                      borderRadius: 8, overflow: 'hidden',
                    }}>
                      {filtered.length === 0 ? (
                        <div style={{ padding: 20, textAlign: 'center', fontSize: 12, color: C.textDim }}>
                          No {statusFilter !== 'all' ? statusFilter + 'ing' : ''} controls in this framework.
                        </div>
                      ) : (
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                          <thead>
                            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                              <th style={thStyle}>Control</th>
                              <th style={thStyle}>Status</th>
                              <th style={thStyle}>Severity</th>
                              <th style={thStyle}>Evidence Source</th>
                              <th style={thStyle}>Impacted</th>
                              <th style={{ ...thStyle, textAlign: 'center' }}>Snapshot</th>
                              <th style={{ ...thStyle, textAlign: 'right' }}>Export</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filtered.map(ctrl => {
                              const meta = STATUS_META[ctrl.status] || STATUS_META.pass;
                              const isCtrlExpanded = expandedCtrl === `${fwId}::${ctrl.control_id}`;
                              const hasEvidence = ctrl.evidence_identities && ctrl.evidence_identities.length > 0;
                              const sevColor = ctrl.severity === 'critical' ? C.critical : ctrl.severity === 'high' ? '#FF8C42' : ctrl.severity === 'medium' ? C.warning : C.textDim;

                              return (
                                <ControlTableRow
                                  key={ctrl.control_id}
                                  ctrl={ctrl}
                                  meta={meta}
                                  sevColor={sevColor}
                                  isCtrlExpanded={isCtrlExpanded}
                                  hasEvidence={hasEvidence}
                                  latestSnapshotId={latestSnapshotId}
                                  onToggle={() => {
                                    if (hasEvidence && ctrl.status !== 'pass') {
                                      setExpandedCtrl(isCtrlExpanded ? null : `${fwId}::${ctrl.control_id}`);
                                    }
                                  }}
                                  onIdentityClick={(id) => navigate(`/identities/${id}`)}
                                  onExport={() => navigate('/exports')}
                                />
                              );
                            })}
                          </tbody>
                        </table>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        );
      })}
    </div>
  );
}

/* ───────── Table Styles ───────── */

const thStyle: React.CSSProperties = {
  textAlign: 'left', padding: '8px 10px', fontSize: 10, fontWeight: 600,
  color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.08em',
  fontFamily: "'JetBrains Mono', monospace",
};

/* ───────── Control Table Row ───────── */

function ControlTableRow({ ctrl, meta, sevColor, isCtrlExpanded, hasEvidence, latestSnapshotId, onToggle, onIdentityClick, onExport }: {
  ctrl: IntelControl;
  meta: { label: string; color: string; badge: string };
  sevColor: string;
  isCtrlExpanded: boolean;
  hasEvidence: boolean;
  latestSnapshotId: number | null;
  onToggle: () => void;
  onIdentityClick: (id: number) => void;
  onExport: () => void;
}) {
  const C = { border: 'var(--border-default)', text: 'var(--text-primary)', textMuted: 'var(--text-secondary)', textDim: 'var(--text-tertiary)', accentBlue: '#3B82F6', critical: '#EF4444', warning: '#F59E0B', good: '#22C55E' };
  const mono = "'JetBrains Mono', 'Fira Code', monospace";

  return (
    <>
      <tr
        onClick={onToggle}
        style={{
          borderBottom: `1px solid ${C.border}`,
          cursor: hasEvidence && ctrl.status !== 'pass' ? 'pointer' : 'default',
          background: isCtrlExpanded ? 'var(--bg-hover)' : 'transparent',
          transition: 'background 0.1s',
        }}
      >
        {/* Control */}
        <td style={{ padding: '8px 10px', verticalAlign: 'top' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
            {hasEvidence && ctrl.status !== 'pass' && (
              <span style={{ fontSize: 8, color: C.textDim, marginTop: 3, transition: 'transform 0.2s', transform: isCtrlExpanded ? 'rotate(90deg)' : 'rotate(0deg)', flexShrink: 0 }}>&#9654;</span>
            )}
            <div>
              <div style={{ fontSize: 10, fontFamily: mono, fontWeight: 700, color: C.textMuted, marginBottom: 2 }}>{ctrl.control_id}</div>
              <div style={{ fontSize: 12, color: C.text, lineHeight: 1.3 }}>{ctrl.name}</div>
            </div>
          </div>
        </td>

        {/* Status */}
        <td style={{ padding: '8px 10px', verticalAlign: 'top' }}>
          <span style={{
            display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
            fontFamily: mono, color: meta.color, background: `${meta.color}12`, border: `1px solid ${meta.color}25`,
            textTransform: 'uppercase',
          }}>{meta.label}</span>
        </td>

        {/* Severity */}
        <td style={{ padding: '8px 10px', verticalAlign: 'top' }}>
          {ctrl.status !== 'pass' ? (
            <span style={{
              fontSize: 10, fontFamily: mono, fontWeight: 600, color: sevColor,
              textTransform: 'capitalize',
            }}>{ctrl.severity}</span>
          ) : (
            <span style={{ fontSize: 10, color: C.textDim }}>—</span>
          )}
        </td>

        {/* Evidence Source */}
        <td style={{ padding: '8px 10px', verticalAlign: 'top' }}>
          <span style={{ fontSize: 11, color: C.textMuted, textTransform: 'capitalize' }}>
            {evidenceSource(ctrl)}
          </span>
        </td>

        {/* Impacted */}
        <td style={{ padding: '8px 10px', verticalAlign: 'top' }}>
          {ctrl.evidence_count > 0 ? (
            <span style={{ fontSize: 12, fontFamily: mono, fontWeight: 700, color: meta.color }}>
              {ctrl.evidence_count}
            </span>
          ) : (
            <span style={{ fontSize: 10, color: C.textDim }}>—</span>
          )}
        </td>

        {/* Snapshot */}
        <td style={{ padding: '8px 10px', verticalAlign: 'top', textAlign: 'center' }}>
          {latestSnapshotId ? (
            <span style={{ fontSize: 10, fontFamily: mono, color: C.textDim }}>#{latestSnapshotId}</span>
          ) : (
            <span style={{ fontSize: 10, color: C.textDim }}>—</span>
          )}
        </td>

        {/* Export */}
        <td style={{ padding: '8px 10px', verticalAlign: 'top', textAlign: 'right' }}>
          <button
            onClick={e => { e.stopPropagation(); onExport(); }}
            style={{
              fontSize: 10, fontFamily: mono, color: C.accentBlue, background: 'none',
              border: 'none', cursor: 'pointer', textDecoration: 'underline', textUnderlineOffset: 2,
              padding: 0,
            }}
          >Export</button>
        </td>
      </tr>

      {/* Expanded: Evidence Identities */}
      {isCtrlExpanded && hasEvidence && (
        <tr>
          <td colSpan={7} style={{ padding: 0 }}>
            <div style={{
              margin: '0 10px 8px 10px', padding: '12px 14px',
              background: 'var(--bg-primary)', border: `1px solid ${C.border}`, borderRadius: 8,
            }}>
              {/* Detail */}
              <div style={{
                fontSize: 11, color: C.textMuted, marginBottom: 10, padding: '6px 10px',
                background: 'var(--bg-secondary)', borderRadius: 6, borderLeft: `3px solid ${meta.color}40`,
              }}>
                {ctrl.detail}
              </div>

              {/* Evidence header */}
              <div style={{
                fontSize: 9, fontFamily: mono, fontWeight: 700, color: C.textDim,
                textTransform: 'uppercase', letterSpacing: '1.2px', marginBottom: 6,
              }}>
                Impacted Identities ({ctrl.evidence_identities.length}{ctrl.evidence_count > ctrl.evidence_identities.length ? ` of ${ctrl.evidence_count}` : ''})
              </div>

              {/* Identity rows */}
              {ctrl.evidence_identities.slice(0, 8).map((eid, idx) => {
                const rColor = eid.risk_level === 'critical' ? C.critical : eid.risk_level === 'high' ? '#FF8C42' : eid.risk_level === 'medium' ? C.warning : C.good;
                return (
                  <div
                    key={eid.id || idx}
                    onClick={(e) => { e.stopPropagation(); onIdentityClick(eid.id); }}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 8, padding: '5px 8px',
                      borderRadius: 6, cursor: 'pointer', transition: 'background 0.15s',
                      fontSize: 11,
                    }}
                    onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-hover)'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = 'transparent'; }}
                  >
                    <span style={{
                      fontSize: 8, fontFamily: mono, fontWeight: 700, textTransform: 'uppercase',
                      padding: '1px 5px', borderRadius: 3, color: rColor, background: `${rColor}12`, border: `1px solid ${rColor}25`,
                      minWidth: 44, textAlign: 'center',
                    }}>{eid.risk_level}</span>
                    <span style={{ color: C.text, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{eid.display_name}</span>
                    <span style={{ fontSize: 9, fontFamily: mono, color: C.textDim }}>{eid.identity_category?.replace(/_/g, ' ')}</span>
                    <span style={{ fontSize: 12, fontFamily: mono, fontWeight: 800, color: rColor }}>{eid.risk_score}</span>
                    <span style={{ fontSize: 10, color: C.textDim }}>→</span>
                  </div>
                );
              })}

              {ctrl.evidence_identities.length > 8 && (
                <div style={{ fontSize: 10, fontFamily: mono, color: C.accentBlue, padding: '6px 8px', cursor: 'pointer' }}
                  onClick={(e) => { e.stopPropagation(); onIdentityClick(ctrl.evidence_identities[0]?.id); }}>
                  + {ctrl.evidence_identities.length - 8} more identities...
                </div>
              )}

              {ctrl.evidence_identities[0]?.reason && (
                <div style={{
                  fontSize: 10, fontFamily: mono, color: C.textDim, fontStyle: 'italic',
                  marginTop: 6, paddingTop: 6, borderTop: `1px solid ${C.border}`,
                }}>
                  Reason: {ctrl.evidence_identities[0].reason}
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
