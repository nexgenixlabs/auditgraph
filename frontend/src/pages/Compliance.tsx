import { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import DrillableNumber from '../components/DrillableNumber';

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

const TIER_CONFIG: Record<string, { icon: string; label: string; order: number }> = {
  core:      { icon: "\uD83C\uDFDB", label: "Core Governance", order: 0 },
  industry:  { icon: "\uD83C\uDFE5", label: "Industry Specific", order: 1 },
  privacy:   { icon: "\uD83C\uDF0D", label: "Privacy & Data Protection", order: 2 },
  benchmark: { icon: "\u2699", label: "Technical Benchmarks", order: 3 },
};

/* ───────── Sub-Components ───────── */

function ScoreRing({ pct, size = 88 }: { pct: number; size?: number }) {
  const r = (size - 10) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - pct / 100);
  const color = pct >= 80 ? C.good : pct >= 50 ? C.warning : C.critical;

  return (
    <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--bg-elevated)" strokeWidth="6" />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth="6"
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        style={{ transition: "stroke-dashoffset 0.8s ease" }} />
      <g transform={`rotate(90 ${size / 2} ${size / 2})`}>
        <text x={size / 2} y={size / 2 - 4} textAnchor="middle" fill={color}
          fontSize="18" fontWeight="800" fontFamily={mono}>{pct}%</text>
        <text x={size / 2} y={size / 2 + 12} textAnchor="middle" fill={C.textMuted}
          fontSize="9" fontFamily={mono}>passing</text>
      </g>
    </svg>
  );
}

function MiniBar({ value, color }: { value: number; color: string }) {
  return (
    <div style={{ height: 6, background: 'var(--bg-elevated)', borderRadius: 3, width: "100%" }}>
      <div style={{
        height: "100%", width: `${Math.min(value, 100)}%`, background: color,
        borderRadius: 3, transition: "width 0.8s ease",
      }} />
    </div>
  );
}

function FrameworkCard({ name, pct, identity, assessed, id, highlight, expanded, onClick }: {
  name: string; pct: number; identity: string; assessed: string; id?: string; highlight?: boolean;
  expanded?: boolean; onClick?: () => void;
}) {
  const color = pct >= 80 ? C.good : pct >= 50 ? C.warning : C.critical;
  return (
    <div
      id={id}
      onClick={onClick}
      title={`Click to ${expanded ? 'collapse' : 'expand'} ${name} controls`}
      style={{
        background: expanded ? 'var(--bg-hover)' : highlight ? 'var(--bg-hover)' : 'var(--bg-elevated)',
        border: `1px solid ${expanded ? `${color}50` : highlight ? `${color}60` : C.border}`,
        borderRadius: 12,
        padding: "20px 16px",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 12,
        minWidth: 140,
        flex: "1 1 160px",
        transition: "all 0.2s",
        cursor: "pointer",
        position: "relative",
        ...(highlight || expanded ? { boxShadow: `0 0 16px ${color}20` } : {}),
      }}
      onMouseEnter={e => {
        (e.currentTarget as HTMLDivElement).style.borderColor = `${color}40`;
        (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-hover)';
      }}
      onMouseLeave={e => {
        (e.currentTarget as HTMLDivElement).style.borderColor = expanded ? `${color}50` : highlight ? `${color}60` : C.border;
        (e.currentTarget as HTMLDivElement).style.background = expanded || highlight ? 'var(--bg-hover)' : 'var(--bg-elevated)';
      }}
    >
      <ScoreRing pct={pct} />
      <div style={{ textAlign: "center" }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: C.text, letterSpacing: "-0.2px", marginBottom: 4 }}>
          {name}
        </div>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', fontFamily: mono, marginBottom: 2 }}>
          {identity} controls
        </div>
        <div style={{ fontSize: 10, color: C.textMuted, fontFamily: mono }}>
          {assessed}
        </div>
      </div>
      {/* Expand indicator */}
      <div style={{
        position: "absolute", bottom: 6, right: 10, fontSize: 10,
        color: C.textDim, transition: "transform 0.2s",
        transform: expanded ? "rotate(180deg)" : "rotate(0deg)",
      }}>&#9660;</div>
    </div>
  );
}

function TierDivider({ icon, label, count }: { icon: string; label: string; count: number }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "28px 0 18px" }}>
      <div style={{ height: 1, width: 24, background: "linear-gradient(90deg, transparent, var(--border-default))" }} />
      <div style={{
        display: "flex", alignItems: "center", gap: 8, padding: "6px 14px",
        borderRadius: 6, background: 'var(--bg-hover)', border: `1px solid ${C.border}`,
      }}>
        <span style={{ fontSize: 13 }}>{icon}</span>
        <span style={{
          fontSize: 11, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: "1px",
          textTransform: "uppercase", fontFamily: mono,
        }}>{label}</span>
        <span style={{ fontSize: 10, fontWeight: 600, color: C.textDim, fontFamily: mono }}>({count})</span>
      </div>
      <div style={{ flex: 1, height: 1, background: "linear-gradient(90deg, var(--border-default), transparent)" }} />
    </div>
  );
}

/* ───────── Control Expansion ───────── */

const STATUS_ORDER: Record<string, number> = { fail: 0, warn: 1, pass: 2 };
const STATUS_META: Record<string, { label: string; color: string; icon: string }> = {
  fail: { label: 'Failing', color: C.critical, icon: '\u2716' },
  warn: { label: 'Warning', color: C.warning, icon: '\u26A0' },
  pass: { label: 'Passing', color: C.good, icon: '\u2714' },
};

function ControlExpansion({ fw, onIdentityClick }: { fw: IntelFramework; onIdentityClick: (id: number) => void }) {
  const [expandedCtrl, setExpandedCtrl] = useState<string | null>(null);

  const sorted = [...fw.controls].sort((a, b) =>
    (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9) || b.weight - a.weight
  );

  const groups: Record<string, IntelControl[]> = {};
  sorted.forEach(ctrl => {
    if (!groups[ctrl.status]) groups[ctrl.status] = [];
    groups[ctrl.status].push(ctrl);
  });

  return (
    <div style={{
      background: 'var(--bg-secondary)', border: `1px solid ${C.border}`, borderRadius: 12,
      padding: "16px 20px", marginTop: 12,
      animation: "fwExpandIn 0.25s ease",
    }}>
      <style>{`@keyframes fwExpandIn { from { opacity: 0; max-height: 0; } to { opacity: 1; max-height: 2000px; } }`}</style>

      {/* Summary strip */}
      <div style={{
        display: "flex", gap: 16, marginBottom: 14, padding: "8px 12px",
        background: 'var(--bg-elevated)', borderRadius: 8, border: `1px solid ${C.border}`,
      }}>
        {['fail', 'warn', 'pass'].map(s => {
          const meta = STATUS_META[s];
          const count = groups[s]?.length || 0;
          return (
            <div key={s} style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 11, color: meta.color }}>{meta.icon}</span>
              <span style={{ fontSize: 11, fontFamily: mono, fontWeight: 700, color: meta.color }}>{count}</span>
              <span style={{ fontSize: 10, fontFamily: mono, color: C.textDim }}>{meta.label}</span>
            </div>
          );
        })}
      </div>

      {/* Control groups */}
      {['fail', 'warn', 'pass'].map(status => {
        const ctrls = groups[status];
        if (!ctrls || ctrls.length === 0) return null;
        const meta = STATUS_META[status];
        const isPass = status === 'pass';

        return (
          <div key={status} style={{ marginBottom: 12 }}>
            <div style={{
              fontSize: 10, fontFamily: mono, fontWeight: 700, color: meta.color,
              textTransform: "uppercase", letterSpacing: 1.2, marginBottom: 6,
              display: "flex", alignItems: "center", gap: 6,
            }}>
              <span>{meta.icon}</span> {meta.label} ({ctrls.length})
            </div>

            {ctrls.map(ctrl => {
              const isExpanded = expandedCtrl === ctrl.control_id;
              const hasEvidence = ctrl.evidence_identities && ctrl.evidence_identities.length > 0;
              const severityColor = ctrl.severity === 'critical' ? C.critical
                : ctrl.severity === 'high' ? "#FF8C42" : ctrl.severity === 'medium' ? C.warning : C.textDim;

              return (
                <div key={ctrl.control_id} style={{ marginBottom: 4 }}>
                  {/* Control row */}
                  <div
                    onClick={() => !isPass && hasEvidence && setExpandedCtrl(isExpanded ? null : ctrl.control_id)}
                    style={{
                      display: "flex", alignItems: "center", gap: 10, padding: "8px 12px",
                      background: isExpanded ? 'var(--bg-hover)' : 'var(--bg-elevated)',
                      border: `1px solid ${isExpanded ? `${meta.color}30` : "transparent"}`,
                      borderRadius: 8, cursor: !isPass && hasEvidence ? "pointer" : "default",
                      transition: "all 0.15s",
                    }}
                    onMouseEnter={e => {
                      if (!isPass && hasEvidence) (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-hover)';
                    }}
                    onMouseLeave={e => {
                      if (!isExpanded) (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-elevated)';
                    }}
                    title={!isPass && hasEvidence ? `Click to see ${ctrl.evidence_count} impacted identities` : undefined}
                  >
                    {/* Status dot */}
                    <div style={{
                      width: 7, height: 7, borderRadius: "50%", background: meta.color,
                      flexShrink: 0, boxShadow: `0 0 6px ${meta.color}40`,
                    }} />

                    {/* Control ID */}
                    <span style={{
                      fontSize: 10, fontFamily: mono, fontWeight: 700, color: C.textMuted,
                      minWidth: 70, flexShrink: 0,
                    }}>{ctrl.control_id}</span>

                    {/* Name */}
                    <span style={{
                      fontSize: 12, color: 'var(--text-primary)', flex: 1,
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    }}>{ctrl.name}</span>

                    {/* Severity badge */}
                    {!isPass && (
                      <span style={{
                        fontSize: 8, fontFamily: mono, fontWeight: 700, textTransform: "uppercase",
                        padding: "1px 6px", borderRadius: 3, letterSpacing: 0.5,
                        color: severityColor, background: `${severityColor}15`,
                        border: `1px solid ${severityColor}30`,
                      }}>{ctrl.severity}</span>
                    )}

                    {/* Evidence count */}
                    {!isPass && ctrl.evidence_count > 0 && (
                      <span style={{
                        fontSize: 10, fontFamily: mono, fontWeight: 600, color: meta.color,
                        display: "flex", alignItems: "center", gap: 3,
                      }}>
                        {ctrl.evidence_count}
                        <span style={{ fontSize: 8, color: C.textDim }}>ids</span>
                      </span>
                    )}

                    {/* Expand arrow */}
                    {!isPass && hasEvidence && (
                      <span style={{
                        fontSize: 9, color: C.textDim, transition: "transform 0.2s",
                        transform: isExpanded ? "rotate(180deg)" : "rotate(0deg)",
                      }}>&#9660;</span>
                    )}
                  </div>

                  {/* Expanded: evidence identities */}
                  {isExpanded && hasEvidence && (
                    <div style={{
                      marginLeft: 20, marginTop: 4, marginBottom: 8,
                      padding: "10px 14px", background: 'var(--bg-primary)',
                      border: `1px solid ${C.border}`, borderRadius: 8,
                    }}>
                      <div style={{
                        fontSize: 9, fontFamily: mono, fontWeight: 700, color: C.textDim,
                        textTransform: "uppercase", letterSpacing: 1.2, marginBottom: 8,
                      }}>
                        Impacted Identities ({ctrl.evidence_identities.length}{ctrl.evidence_count > ctrl.evidence_identities.length ? ` of ${ctrl.evidence_count}` : ''})
                      </div>

                      {/* Detail text */}
                      <div style={{
                        fontSize: 11, color: C.textMuted, marginBottom: 10,
                        padding: "6px 10px", background: 'var(--bg-elevated)', borderRadius: 6,
                        borderLeft: `3px solid ${meta.color}40`,
                      }}>
                        {ctrl.detail}
                      </div>

                      {/* Identity rows */}
                      {ctrl.evidence_identities.slice(0, 8).map((eid, idx) => {
                        const rColor = eid.risk_level === 'critical' ? C.critical
                          : eid.risk_level === 'high' ? "#FF8C42"
                          : eid.risk_level === 'medium' ? C.warning : C.good;
                        return (
                          <div key={eid.id || idx}
                            onClick={() => onIdentityClick(eid.id)}
                            style={{
                              display: "flex", alignItems: "center", gap: 8, padding: "6px 8px",
                              borderRadius: 6, cursor: "pointer", transition: "background 0.15s",
                            }}
                            onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-hover)'; }}
                            onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = "transparent"; }}
                            title={`View ${eid.display_name} detail`}
                          >
                            {/* Risk badge */}
                            <span style={{
                              fontSize: 8, fontFamily: mono, fontWeight: 700, textTransform: "uppercase",
                              padding: "1px 5px", borderRadius: 3,
                              color: rColor, background: `${rColor}12`, border: `1px solid ${rColor}25`,
                              minWidth: 44, textAlign: "center",
                            }}>{eid.risk_level}</span>

                            {/* Name */}
                            <span style={{
                              fontSize: 11, color: 'var(--text-primary)', flex: 1,
                              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                            }}>{eid.display_name}</span>

                            {/* Category */}
                            <span style={{ fontSize: 9, fontFamily: mono, color: C.textDim }}>
                              {eid.identity_category?.replace(/_/g, ' ')}
                            </span>

                            {/* Score */}
                            <span style={{
                              fontSize: 12, fontFamily: mono, fontWeight: 800, color: rColor,
                            }}>{eid.risk_score}</span>

                            {/* Arrow */}
                            <span style={{ fontSize: 10, color: C.textDim }}>&#8594;</span>
                          </div>
                        );
                      })}

                      {/* "Show more" if truncated */}
                      {ctrl.evidence_identities.length > 8 && (
                        <div style={{
                          fontSize: 10, fontFamily: mono, color: C.accentBlue,
                          padding: "6px 8px", cursor: "pointer",
                        }}
                        onClick={(e) => {
                          e.stopPropagation();
                          onIdentityClick(ctrl.evidence_identities[0]?.id);
                        }}>
                          + {ctrl.evidence_identities.length - 8} more identities...
                        </div>
                      )}

                      {/* Reason summary */}
                      {ctrl.evidence_identities[0]?.reason && (
                        <div style={{
                          fontSize: 10, fontFamily: mono, color: C.textDim, fontStyle: "italic",
                          marginTop: 6, paddingTop: 6, borderTop: `1px solid ${C.border}`,
                        }}>
                          Reason: {ctrl.evidence_identities[0].reason}
                        </div>
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

/* ───────── Helpers ───────── */

function buildFrameworkCard(fw: IntelFramework) {
  const identityCount = fw.identity_controls_count ?? fw.total_controls;
  const totalFw = fw.total_framework_controls ?? fw.total_controls;
  const passCount = fw.pass_count;
  const identity = `${passCount}/${identityCount}`;
  const assessed = fw.scope_label || `${identityCount} of ${totalFw}`;
  return { name: fw.short_name || fw.name, pct: fw.score, identity, assessed };
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

  // Auto-scroll and auto-expand when navigating from Overview
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
      <div style={{ minHeight: "100vh", background: C.bg, color: C.text, padding: "28px 32px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <div style={{ height: 28, width: 240, borderRadius: 8, background: 'var(--bg-active)', marginBottom: 20 }} />
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
            {[1, 2, 3].map(i => (
              <div key={i} style={{
                height: 180, flex: "1 1 160px", borderRadius: 12,
                background: 'var(--bg-hover)', animation: "pulse 1.5s infinite",
              }} />
            ))}
          </div>
        </div>
      </div>
    );
  }

  /* Error */
  if (error || !data) {
    return (
      <div style={{ minHeight: "100vh", background: C.bg, color: C.text, padding: "28px 32px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <div style={{
            borderRadius: 12, padding: 24, textAlign: "center",
            background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)",
          }}>
            <p style={{ color: C.critical, fontWeight: 600 }}>{error || 'No compliance data available'}</p>
            <p style={{ color: C.textMuted, fontSize: 13, marginTop: 4 }}>
              Run a discovery scan to generate compliance posture data.
            </p>
          </div>
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

  /* Overall average (excluding benchmarks) */
  const scorableFws = Object.values(data.frameworks).filter(fw => fw.tier !== 'benchmark' && fw.score > 0);
  const overallAvg = scorableFws.length > 0
    ? Math.round(scorableFws.reduce((s, fw) => s + fw.score, 0) / scorableFws.length)
    : 0;

  /* Remediation counts from root causes */
  const totalRemediation = data.root_causes?.length || 0;

  /* SA Governance from tier_summary */
  const saGov = data.tier_summary?.['governance'] || null;

  return (
    <div style={{
      minHeight: "100vh", background: C.bg, color: C.text,
      fontFamily: "'Inter', -apple-system, system-ui, sans-serif",
      padding: "28px 32px",
    }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: C.text, letterSpacing: "-0.3px" }}>
          Compliance Posture
        </h1>
        <span style={{
          padding: "3px 10px", borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: mono,
          background: "rgba(239,68,68,0.12)", color: "#EF4444",
          border: "1px solid rgba(239,68,68,0.25)", letterSpacing: "0.5px", textTransform: "uppercase",
        }}>
          Identity Controls Only
        </span>
      </div>
      <p style={{ margin: "0 0 8px", fontSize: 13, color: 'var(--text-secondary)' }}>
        Assessing identity, access, and privilege controls only
      </p>

      {/* Main Card */}
      <div style={{
        background: C.card, border: `1px solid ${C.border}`,
        borderRadius: 14, padding: "8px 28px 28px",
      }}>

        {/* Tier Sections */}
        {sortedTiers.map(tier => {
          const cfg = TIER_CONFIG[tier] || { icon: "\u2699", label: tier, order: 99 };
          const fws = tierGroups[tier];
          return (
            <div key={tier}>
              <TierDivider icon={cfg.icon} label={cfg.label} count={fws.length} />
              {tier === 'benchmark' && (
                <div style={{ padding: "4px 12px 4px 0", marginBottom: 4 }}>
                  <span style={{ fontSize: 10, color: C.textDim, fontStyle: "italic" }}>
                    Shown in Risk Monitoring only — not included in executive posture score
                  </span>
                </div>
              )}
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                {fws.map((fw, i) => {
                  const card = buildFrameworkCard(fw);
                  const fwId = fw.short_name || fw.name || '';
                  return (
                    <FrameworkCard key={i} name={card.name} pct={card.pct}
                      identity={card.identity} assessed={card.assessed}
                      id={`fw-${fwId}`} highlight={highlightFramework === fwId}
                      expanded={expandedFw === fwId}
                      onClick={() => setExpandedFw(expandedFw === fwId ? null : fwId)} />
                  );
                })}
              </div>
              {/* Inline control expansion */}
              {fws.map(fw => {
                const fwId = fw.short_name || fw.name || '';
                if (expandedFw !== fwId) return null;
                return (
                  <ControlExpansion key={`exp-${fwId}`} fw={fw}
                    onIdentityClick={(id) => navigate(`/identities/${id}`)} />
                );
              })}
            </div>
          );
        })}

        {/* Bottom Section: Remediation + SA Governance */}
        <div style={{
          marginTop: 28, paddingTop: 20, borderTop: `1px solid ${C.border}`,
          display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20,
        }}>
          {/* Remediation Progress */}
          <button onClick={() => navigate('/dashboard?tab=governance')} style={{
            padding: "16px 20px", borderRadius: 10, textAlign: 'left' as const, width: '100%',
            background: 'var(--bg-elevated)', border: `1px solid ${C.border}`, cursor: 'pointer', transition: 'opacity 0.15s',
          }} className="hover:opacity-70">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Remediation Progress</span>
              <span style={{ fontSize: 14, fontWeight: 800, color: C.warning, fontFamily: mono }}>
                {data.passing > 0 ? Math.round((data.passing / data.total_controls) * 100) : 0}%
              </span>
            </div>
            <MiniBar value={data.passing > 0 ? Math.round((data.passing / data.total_controls) * 100) : 0} color={C.warning} />
            <div style={{ display: "flex", gap: 16, marginTop: 10, fontSize: 11, fontFamily: mono }}>
              <span style={{ color: C.textMuted }}>
                Passing: <span style={{ color: C.good, fontWeight: 600 }}>{data.passing}</span>
              </span>
              <span style={{ color: C.textMuted }}>
                Warnings: <span style={{ color: C.warning, fontWeight: 600 }}>{data.warnings}</span>
              </span>
              <span style={{ color: C.textMuted }}>
                Failing: <span style={{ color: C.critical, fontWeight: 600 }}>{data.failing}</span>
              </span>
              <span style={{ color: C.textMuted }}>
                Root Causes: <span style={{ color: C.text, fontWeight: 600 }}>{totalRemediation}</span>
              </span>
            </div>
          </button>

          {/* SA Governance — only show when tier_summary has governance data */}
          {saGov && (
          <button onClick={() => navigate('/service-accounts')} style={{
            padding: "16px 20px", borderRadius: 10, textAlign: 'left' as const, width: '100%',
            background: 'var(--bg-elevated)', border: `1px solid ${C.border}`, cursor: 'pointer', transition: 'opacity 0.15s',
          }} className="hover:opacity-70">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>SA Governance Compliance</span>
              <span style={{ fontSize: 14, fontWeight: 800, color: saGov.score >= 50 ? C.warning : C.critical, fontFamily: mono }}>
                {saGov.score}%
              </span>
            </div>
            <MiniBar value={saGov.score} color={saGov.score >= 50 ? C.warning : C.critical} />
            <div style={{ display: "flex", gap: 16, marginTop: 10, fontSize: 11, fontFamily: mono }}>
              <span style={{ color: C.textMuted }}>
                Passing: <span style={{ color: C.good, fontWeight: 600 }}>{saGov.passing}</span>
              </span>
              <span style={{ color: C.textMuted }}>
                Warnings: <span style={{ color: C.warning, fontWeight: 600 }}>{saGov.warnings}</span>
              </span>
              <span style={{ color: C.textMuted }}>
                Failing: <span style={{ color: C.critical, fontWeight: 600 }}>{saGov.failing}</span>
              </span>
            </div>
          </button>
          )}
        </div>

        {/* Overall Summary Bar */}
        <div style={{
          marginTop: 20, padding: "14px 20px", borderRadius: 10,
          background: 'var(--bg-hover)', border: `1px solid ${C.border}`,
          display: "flex", justifyContent: "space-between", alignItems: "center",
          flexWrap: "wrap", gap: 12,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>
              Overall Identity Controls Posture:
            </span>
            <DrillableNumber to="/compliance" format={false}>
              <span style={{
                fontSize: 16, fontWeight: 800,
                color: overallAvg >= 80 ? C.good : overallAvg >= 50 ? C.warning : C.critical,
                fontFamily: mono,
              }}>{overallAvg}%</span>
            </DrillableNumber>
            <span style={{
              padding: "2px 8px", borderRadius: 4, fontSize: 9, fontWeight: 700,
              background: overallAvg >= 80 ? "rgba(34,197,94,0.12)" : overallAvg >= 50 ? "rgba(245,158,11,0.12)" : "rgba(239,68,68,0.12)",
              color: overallAvg >= 80 ? C.good : overallAvg >= 50 ? C.warning : C.critical,
              border: `1px solid ${overallAvg >= 80 ? "rgba(34,197,94,0.25)" : overallAvg >= 50 ? "rgba(245,158,11,0.25)" : "rgba(239,68,68,0.25)"}`,
              fontFamily: mono,
            }}>
              {overallAvg >= 80 ? 'HEALTHY' : overallAvg >= 50 ? 'NEEDS WORK' : 'AT RISK'}
            </span>
          </div>
          <div style={{ display: "flex", gap: 14, fontSize: 10, fontFamily: mono, color: C.textMuted }}>
            <span>Frameworks Active: <DrillableNumber to="/compliance" format={false}><span style={{ color: C.text, fontWeight: 600 }}>
              {Object.keys(data.frameworks).length}
            </span></DrillableNumber></span>
            <span style={{ color: 'var(--border-default)' }}>|</span>
            <span>Total Identity Controls: <DrillableNumber to="/compliance" format={false}><span style={{ color: C.text, fontWeight: 600 }}>
              {data.total_controls}
            </span></DrillableNumber></span>
            <span style={{ color: 'var(--border-default)' }}>|</span>
            <span>Last Assessed: <span style={{ color: C.text, fontWeight: 600 }}>
              {new Date(data.generated_at).toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' })}
            </span></span>
          </div>
        </div>
      </div>
    </div>
  );
}
