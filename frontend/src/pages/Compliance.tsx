import { useState, useEffect } from 'react';
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
  bg: "#0a0f1a",
  card: "#1a2332",
  border: "#2a3444",
  critical: "#EF4444",
  warning: "#F59E0B",
  good: "#22C55E",
  text: "#F9FAFB",
  textMuted: "#9CA3AF",
  textDim: "#6B7280",
  accent: "#F59E0B",
  accentBlue: "#3B82F6",
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
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1F2937" strokeWidth="6" />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth="6"
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        style={{ transition: "stroke-dashoffset 0.8s ease" }} />
      <g transform={`rotate(90 ${size / 2} ${size / 2})`}>
        <text x={size / 2} y={size / 2 - 4} textAnchor="middle" fill={color}
          fontSize="18" fontWeight="800" fontFamily={mono}>{pct}%</text>
        <text x={size / 2} y={size / 2 + 12} textAnchor="middle" fill="#9CA3AF"
          fontSize="9" fontFamily={mono}>passing</text>
      </g>
    </svg>
  );
}

function MiniBar({ value, color }: { value: number; color: string }) {
  return (
    <div style={{ height: 6, background: "#1F2937", borderRadius: 3, width: "100%" }}>
      <div style={{
        height: "100%", width: `${Math.min(value, 100)}%`, background: color,
        borderRadius: 3, transition: "width 0.8s ease",
      }} />
    </div>
  );
}

function FrameworkCard({ name, pct, identity, assessed }: {
  name: string; pct: number; identity: string; assessed: string;
}) {
  const color = pct >= 80 ? C.good : pct >= 50 ? C.warning : C.critical;
  return (
    <div
      style={{
        background: "#111827",
        border: `1px solid ${C.border}`,
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
      }}
      onMouseEnter={e => {
        (e.currentTarget as HTMLDivElement).style.borderColor = `${color}40`;
        (e.currentTarget as HTMLDivElement).style.background = "#141c2b";
      }}
      onMouseLeave={e => {
        (e.currentTarget as HTMLDivElement).style.borderColor = C.border;
        (e.currentTarget as HTMLDivElement).style.background = "#111827";
      }}
    >
      <ScoreRing pct={pct} />
      <div style={{ textAlign: "center" }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: "#FFFFFF", letterSpacing: "-0.2px", marginBottom: 4 }}>
          {name}
        </div>
        <div style={{ fontSize: 11, fontWeight: 600, color: "#D1D5DB", fontFamily: mono, marginBottom: 2 }}>
          {identity} controls
        </div>
        <div style={{ fontSize: 10, color: "#9CA3AF", fontFamily: mono }}>
          {assessed}
        </div>
      </div>
    </div>
  );
}

function TierDivider({ icon, label, count }: { icon: string; label: string; count: number }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "28px 0 18px" }}>
      <div style={{ height: 1, width: 24, background: "linear-gradient(90deg, transparent, #374151)" }} />
      <div style={{
        display: "flex", alignItems: "center", gap: 8, padding: "6px 14px",
        borderRadius: 6, background: "rgba(255,255,255,0.03)", border: "1px solid #2a3444",
      }}>
        <span style={{ fontSize: 13 }}>{icon}</span>
        <span style={{
          fontSize: 11, fontWeight: 700, color: "#E5E7EB", letterSpacing: "1px",
          textTransform: "uppercase", fontFamily: mono,
        }}>{label}</span>
        <span style={{ fontSize: 10, fontWeight: 600, color: "#6B7280", fontFamily: mono }}>({count})</span>
      </div>
      <div style={{ flex: 1, height: 1, background: "linear-gradient(90deg, #374151, transparent)" }} />
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

  /* Loading */
  if (loading) {
    return (
      <div style={{ minHeight: "100vh", background: C.bg, color: C.text, padding: "28px 32px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <div style={{ height: 28, width: 240, borderRadius: 8, background: "rgba(255,255,255,0.05)", marginBottom: 20 }} />
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
            {[1, 2, 3].map(i => (
              <div key={i} style={{
                height: 180, flex: "1 1 160px", borderRadius: 12,
                background: "rgba(255,255,255,0.03)", animation: "pulse 1.5s infinite",
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
      fontFamily: "'DM Sans', -apple-system, system-ui, sans-serif",
      padding: "28px 32px",
    }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: "#FFFFFF", letterSpacing: "-0.3px" }}>
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
      <p style={{ margin: "0 0 8px", fontSize: 13, color: "#D1D5DB" }}>
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
                  <span style={{ fontSize: 10, color: "#6B7280", fontStyle: "italic" }}>
                    Shown in Risk Monitoring only — not included in executive posture score
                  </span>
                </div>
              )}
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                {fws.map((fw, i) => {
                  const card = buildFrameworkCard(fw);
                  return (
                    <FrameworkCard key={i} name={card.name} pct={card.pct}
                      identity={card.identity} assessed={card.assessed} />
                  );
                })}
              </div>
            </div>
          );
        })}

        {/* Bottom Section: Remediation + SA Governance */}
        <div style={{
          marginTop: 28, paddingTop: 20, borderTop: "1px solid #2a3444",
          display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20,
        }}>
          {/* Remediation Progress */}
          <div style={{
            padding: "16px 20px", borderRadius: 10,
            background: "#111827", border: `1px solid ${C.border}`,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: "#FFFFFF" }}>Remediation Progress</span>
              <span style={{ fontSize: 14, fontWeight: 800, color: C.warning, fontFamily: mono }}>
                {data.passing > 0 ? Math.round((data.passing / data.total_controls) * 100) : 0}%
              </span>
            </div>
            <MiniBar value={data.passing > 0 ? Math.round((data.passing / data.total_controls) * 100) : 0} color={C.warning} />
            <div style={{ display: "flex", gap: 16, marginTop: 10, fontSize: 11, fontFamily: mono }}>
              <span style={{ color: "#9CA3AF" }}>
                Passing: <span style={{ color: C.good, fontWeight: 600 }}>{data.passing}</span>
              </span>
              <span style={{ color: "#9CA3AF" }}>
                Warnings: <span style={{ color: C.warning, fontWeight: 600 }}>{data.warnings}</span>
              </span>
              <span style={{ color: "#9CA3AF" }}>
                Failing: <span style={{ color: C.critical, fontWeight: 600 }}>{data.failing}</span>
              </span>
              <span style={{ color: "#9CA3AF" }}>
                Root Causes: <span style={{ color: "#FFFFFF", fontWeight: 600 }}>{totalRemediation}</span>
              </span>
            </div>
          </div>

          {/* SA Governance */}
          <div style={{
            padding: "16px 20px", borderRadius: 10,
            background: "#111827", border: `1px solid ${C.border}`,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: "#FFFFFF" }}>SA Governance Compliance</span>
              <span style={{ fontSize: 14, fontWeight: 800, color: saGov ? (saGov.score >= 50 ? C.warning : C.critical) : C.critical, fontFamily: mono }}>
                {saGov?.score ?? 0}%
              </span>
            </div>
            <MiniBar value={saGov?.score ?? 0} color={saGov && saGov.score >= 50 ? C.warning : C.critical} />
            <div style={{ display: "flex", gap: 16, marginTop: 10, fontSize: 11, fontFamily: mono }}>
              <span style={{ color: "#9CA3AF" }}>
                Passing: <span style={{ color: C.good, fontWeight: 600 }}>{saGov?.passing ?? 0}</span>
              </span>
              <span style={{ color: "#9CA3AF" }}>
                Warnings: <span style={{ color: C.warning, fontWeight: 600 }}>{saGov?.warnings ?? 0}</span>
              </span>
              <span style={{ color: "#9CA3AF" }}>
                Failing: <span style={{ color: C.critical, fontWeight: 600 }}>{saGov?.failing ?? 0}</span>
              </span>
            </div>
          </div>
        </div>

        {/* Overall Summary Bar */}
        <div style={{
          marginTop: 20, padding: "14px 20px", borderRadius: 10,
          background: "rgba(255,255,255,0.02)", border: `1px solid ${C.border}`,
          display: "flex", justifyContent: "space-between", alignItems: "center",
          flexWrap: "wrap", gap: 12,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: "#D1D5DB" }}>
              Overall Identity Controls Posture:
            </span>
            <span style={{
              fontSize: 16, fontWeight: 800,
              color: overallAvg >= 80 ? C.good : overallAvg >= 50 ? C.warning : C.critical,
              fontFamily: mono,
            }}>{overallAvg}%</span>
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
          <div style={{ display: "flex", gap: 14, fontSize: 10, fontFamily: mono, color: "#9CA3AF" }}>
            <span>Frameworks Active: <span style={{ color: "#FFFFFF", fontWeight: 600 }}>
              {Object.keys(data.frameworks).length}
            </span></span>
            <span style={{ color: "#374151" }}>|</span>
            <span>Total Identity Controls: <span style={{ color: "#FFFFFF", fontWeight: 600 }}>
              {data.total_controls}
            </span></span>
            <span style={{ color: "#374151" }}>|</span>
            <span>Last Assessed: <span style={{ color: "#FFFFFF", fontWeight: 600 }}>
              {new Date(data.generated_at).toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' })}
            </span></span>
          </div>
        </div>
      </div>
    </div>
  );
}
