import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useToast } from '../components/ToastProvider';

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
}

interface RootCause {
  id: number;
  code: string;
  title: string;
  description: string | null;
  category: string | null;
  recommendation: string | null;
  impact_score: number;
  linked_controls: { control_id: string; name: string; framework: string; severity: string }[];
  frameworks_impacted: number;
  affected_entities: number;
}

interface TopDriver {
  control_id: string;
  name: string;
  framework: string;
  severity: string;
  weight: number;
  value: number;
}

interface TrendPoint {
  run_id: number;
  date: string | null;
  overall_score: number;
}

interface IntelligenceData {
  overall_score: number;
  risk_weighted_score: number;
  total_controls: number;
  passing: number;
  warnings: number;
  failing: number;
  cloud_failures: Record<string, number>;
  top_risk_drivers: TopDriver[];
  frameworks: Record<string, IntelFramework>;
  root_causes: RootCause[];
  trend_mini: TrendPoint[];
  generated_at: string;
}

/* ───────── Dark Theme Constants ───────── */

const CI = {
  bg: 'var(--bg-primary)',
  surface: 'var(--bg-secondary)',
  surfaceBorder: 'var(--border-default)',
  surfaceHover: 'var(--bg-hover)',
  text: 'var(--text-primary)',
  textSecondary: 'var(--text-secondary)',
  textMuted: 'var(--text-tertiary)',
  severity: { critical: '#FF1744', high: '#FF6D00', medium: '#FFB300', low: '#42A5F5' } as Record<string, string>,
  pass: '#4ADE80',
  fail: '#FF1744',
  warn: '#FFB300',
  cloud: { azure: '#0078D4', aws: '#FF9900', gcp: '#4285F4' } as Record<string, string>,
  accent: '#8B5CF6',
  mono: "'JetBrains Mono', monospace",
};

const SEV_COLORS: Record<string, { bg: string; text: string }> = {
  critical: { bg: 'rgba(255,23,68,0.15)', text: '#FF1744' },
  high: { bg: 'rgba(255,109,0,0.15)', text: '#FF6D00' },
  medium: { bg: 'rgba(255,179,0,0.12)', text: '#FFB300' },
  low: { bg: 'rgba(66,165,245,0.12)', text: '#42A5F5' },
};

const STATUS_COLORS: Record<string, { bg: string; text: string; dot: string }> = {
  pass: { bg: 'rgba(74,222,128,0.15)', text: '#4ADE80', dot: '#4ADE80' },
  warn: { bg: 'rgba(255,179,0,0.15)', text: '#FFB300', dot: '#FFB300' },
  fail: { bg: 'rgba(255,23,68,0.20)', text: '#FF1744', dot: '#FF1744' },
};

/* ───────── RiskGauge (animated semi-circle) ───────── */

function RiskGauge({ score, label, size = 120 }: { score: number; label?: string; size?: number }) {
  const [animScore, setAnimScore] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setAnimScore(score), 100);
    return () => clearTimeout(t);
  }, [score]);

  const r = (size - 12) / 2;
  const half = Math.PI * r; // semicircle arc length
  const offset = half - (animScore / 100) * half;
  const color = score >= 80 ? CI.pass : score >= 50 ? CI.warn : CI.fail;
  const sevLabel = score >= 80 ? 'HEALTHY' : score >= 50 ? 'AT RISK' : 'CRITICAL';

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size / 2 + 16 }}>
        <svg width={size} height={size / 2 + 8} viewBox={`0 0 ${size} ${size / 2 + 8}`}>
          {/* Track */}
          <path
            d={`M 6 ${size / 2 + 2} A ${r} ${r} 0 0 1 ${size - 6} ${size / 2 + 2}`}
            fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={8} strokeLinecap="round"
          />
          {/* Value arc */}
          <path
            d={`M 6 ${size / 2 + 2} A ${r} ${r} 0 0 1 ${size - 6} ${size / 2 + 2}`}
            fill="none" stroke={color} strokeWidth={8} strokeLinecap="round"
            strokeDasharray={half} strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 1.2s ease-out, stroke 0.4s' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-end" style={{ paddingBottom: 4 }}>
          <span style={{ fontFamily: CI.mono, fontSize: size * 0.28, fontWeight: 700, color }}>{animScore}</span>
        </div>
      </div>
      <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: 1.5, color, marginTop: -4 }}>{sevLabel}</span>
      {label && <span style={{ fontSize: 11, color: CI.textMuted, marginTop: 2 }}>{label}</span>}
    </div>
  );
}

/* ───────── Stat Card ───────── */

function StatCard({ value, label, color, delay = 0 }: { value: string | number; label: string; color: string; delay?: number }) {
  return (
    <div
      className="ci-fade-up rounded-xl px-5 py-4 flex flex-col items-center justify-center"
      style={{
        background: CI.surface,
        border: `1px solid ${CI.surfaceBorder}`,
        animationDelay: `${delay}ms`,
      }}
    >
      <span style={{ fontFamily: CI.mono, fontSize: 28, fontWeight: 700, color }}>{value}</span>
      <span style={{ fontSize: 11, color: CI.textMuted, marginTop: 4, textAlign: 'center' }}>{label}</span>
    </div>
  );
}

/* ───────── Main Component ───────── */

export default function Compliance() {
  const [data, setData] = useState<IntelligenceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'controls' | 'rootcause'>('overview');
  const [fwFilter, setFwFilter] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string | null>(null);
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  const [expandedRC, setExpandedRC] = useState<number | null>(null);
  const [exporting, setExporting] = useState(false);
  const { addToast } = useToast();

  /* Export */
  async function handleExport(format: 'csv' | 'json') {
    setExporting(true);
    try {
      if (format === 'csv') {
        const res = await fetch('/api/compliance/gap-analysis?format=csv');
        if (!res.ok) throw new Error(`Export failed (${res.status})`);
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `compliance-intelligence-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const res = await fetch('/api/compliance/intelligence');
        if (!res.ok) throw new Error(`Export failed (${res.status})`);
        const exportData = await res.json();
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `compliance-intelligence-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
      addToast(`Exported as ${format.toUpperCase()}`, 'success');
    } catch (e: any) {
      addToast(e?.message || 'Export failed', 'error');
    } finally {
      setExporting(false);
    }
  }

  /* Fetch */
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('/api/compliance/intelligence');
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        const json: IntelligenceData = await res.json();
        setData(json);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : 'Failed to load compliance data');
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  /* Loading */
  if (loading) {
    return (
      <div style={{ background: CI.bg }} className="min-h-screen -m-4 -mt-4 p-8">
        <div className="max-w-7xl mx-auto space-y-6">
          <div className="h-8 rounded w-64" style={{ background: 'rgba(255,255,255,0.05)' }} />
          <div className="grid grid-cols-5 gap-4">
            {[1, 2, 3, 4, 5].map(i => (
              <div key={i} className="h-32 rounded-xl animate-pulse" style={{ background: 'rgba(255,255,255,0.03)' }} />
            ))}
          </div>
          <div className="h-64 rounded-xl animate-pulse" style={{ background: 'rgba(255,255,255,0.03)' }} />
        </div>
      </div>
    );
  }

  /* Error */
  if (error || !data) {
    return (
      <div style={{ background: CI.bg }} className="min-h-screen -m-4 -mt-4 p-8">
        <div className="max-w-7xl mx-auto">
          <div className="rounded-xl p-6 text-center" style={{ background: 'rgba(255,23,68,0.08)', border: '1px solid rgba(255,23,68,0.2)' }}>
            <p style={{ color: CI.fail, fontWeight: 600 }}>{error || 'No compliance data available'}</p>
            <p style={{ color: CI.textMuted, fontSize: 13, marginTop: 4 }}>Run a discovery scan to generate compliance posture data.</p>
          </div>
        </div>
      </div>
    );
  }

  const frameworks = Object.entries(data.frameworks);
  const totalCloudFails = Object.values(data.cloud_failures).reduce((s, n) => s + n, 0);

  return (
    <div style={{ background: CI.bg, color: CI.text }} className="min-h-screen -m-4 -mt-4 p-8">
      {/* Inline animation styles */}
      <style>{`
        @keyframes ci-fade-up {
          from { opacity: 0; transform: translateY(12px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        .ci-fade-up {
          animation: ci-fade-up 0.5s ease-out both;
        }
      `}</style>

      <div className="max-w-7xl mx-auto space-y-6">
        {/* ═══ Header ═══ */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <span
              className="px-3 py-1 rounded-md text-xs font-bold tracking-widest"
              style={{ background: 'rgba(139,92,246,0.15)', color: CI.accent, letterSpacing: 2 }}
            >
              COMPLIANCE INTELLIGENCE
            </span>
            {/* Cloud failure pills */}
            {totalCloudFails > 0 && (
              <div className="flex gap-2">
                {Object.entries(data.cloud_failures).map(([cloud, count]) => (
                  <span
                    key={cloud}
                    className="px-2.5 py-1 rounded-full text-[10px] font-semibold uppercase flex items-center gap-1.5"
                    style={{ background: `${CI.cloud[cloud] || '#666'}20`, color: CI.cloud[cloud] || '#aaa' }}
                  >
                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: CI.cloud[cloud] || '#666' }} />
                    {cloud} {count}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => handleExport('csv')}
              disabled={exporting}
              className="px-3 py-1.5 rounded-lg text-xs font-medium transition hover:opacity-80 disabled:opacity-40"
              style={{ background: 'rgba(74,222,128,0.1)', color: CI.pass, border: `1px solid rgba(74,222,128,0.2)` }}
            >
              CSV
            </button>
            <button
              onClick={() => handleExport('json')}
              disabled={exporting}
              className="px-3 py-1.5 rounded-lg text-xs font-medium transition hover:opacity-80 disabled:opacity-40"
              style={{ background: 'rgba(139,92,246,0.1)', color: CI.accent, border: `1px solid rgba(139,92,246,0.2)` }}
            >
              JSON
            </button>
          </div>
        </div>

        {/* ═══ Top Summary Row ═══ */}
        <div className="grid grid-cols-5 gap-4">
          {/* Risk Gauge */}
          <div
            className="ci-fade-up rounded-xl flex items-center justify-center"
            style={{ background: CI.surface, border: `1px solid ${CI.surfaceBorder}`, padding: '20px 8px 12px' }}
          >
            <RiskGauge score={data.risk_weighted_score} label="Risk-Weighted" size={140} />
          </div>

          {/* Control % */}
          <StatCard
            value={`${data.overall_score}%`}
            label="Controls Passing"
            color={data.overall_score >= 80 ? CI.pass : data.overall_score >= 50 ? CI.warn : CI.fail}
            delay={80}
          />

          {/* Weighted % */}
          <StatCard
            value={`${data.risk_weighted_score}%`}
            label="Weighted Score"
            color={data.risk_weighted_score >= 80 ? CI.pass : data.risk_weighted_score >= 50 ? CI.warn : CI.fail}
            delay={160}
          />

          {/* Top Risk Drivers */}
          <div
            className="ci-fade-up rounded-xl px-5 py-4"
            style={{ background: CI.surface, border: `1px solid ${CI.surfaceBorder}`, animationDelay: '240ms' }}
          >
            <span style={{ fontSize: 10, color: CI.textMuted, fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase' }}>
              Top Risk Drivers
            </span>
            <div className="mt-2 space-y-1.5">
              {data.top_risk_drivers.slice(0, 3).map((d, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span
                    className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                    style={{ background: CI.severity[d.severity] || '#888' }}
                  />
                  <span className="text-xs truncate" style={{ color: CI.textSecondary }}>
                    <span style={{ fontFamily: CI.mono, color: CI.textMuted, fontSize: 10 }}>{d.control_id}</span>
                    {' '}{d.name}
                  </span>
                </div>
              ))}
              {data.top_risk_drivers.length === 0 && (
                <span className="text-xs" style={{ color: CI.pass }}>All controls passing</span>
              )}
            </div>
          </div>

          {/* Trend Mini */}
          <div
            className="ci-fade-up rounded-xl px-5 py-4"
            style={{ background: CI.surface, border: `1px solid ${CI.surfaceBorder}`, animationDelay: '320ms' }}
          >
            <span style={{ fontSize: 10, color: CI.textMuted, fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase' }}>
              Score Trend
            </span>
            {data.trend_mini.length > 1 ? (
              <div className="mt-2 flex items-end gap-1" style={{ height: 48 }}>
                {data.trend_mini.map((t, i) => {
                  const h = Math.max(4, (t.overall_score / 100) * 44);
                  const color = t.overall_score >= 80 ? CI.pass : t.overall_score >= 50 ? CI.warn : CI.fail;
                  return (
                    <div
                      key={i}
                      className="flex-1 rounded-sm transition-all"
                      style={{ height: h, background: color, opacity: 0.5 + (i / data.trend_mini.length) * 0.5 }}
                      title={`${t.date ? new Date(t.date).toLocaleDateString() : `Run ${t.run_id}`}: ${t.overall_score}%`}
                    />
                  );
                })}
              </div>
            ) : (
              <div className="mt-3 text-xs" style={{ color: CI.textMuted }}>Not enough data</div>
            )}
          </div>
        </div>

        {/* ═══ Tab Bar ═══ */}
        <div className="flex gap-1 rounded-lg p-1" style={{ background: 'rgba(255,255,255,0.03)' }}>
          {(['overview', 'controls', 'rootcause'] as const).map(tab => {
            const labels = { overview: 'Overview', controls: 'Controls', rootcause: 'Root Cause' };
            const active = activeTab === tab;
            return (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className="flex-1 py-2 rounded-md text-sm font-medium transition-all"
                style={{
                  background: active ? 'rgba(255,255,255,0.08)' : 'transparent',
                  color: active ? CI.text : CI.textMuted,
                }}
              >
                {labels[tab]}
              </button>
            );
          })}
        </div>

        {/* ═══ Tab Content ═══ */}
        <div className="ci-fade-up" key={activeTab}>
          {activeTab === 'overview' && <OverviewTab data={data} onNavigate={(fw) => { setFwFilter(fw); setActiveTab('controls'); }} />}
          {activeTab === 'controls' && (
            <ControlsTab
              data={data}
              fwFilter={fwFilter} setFwFilter={setFwFilter}
              sevFilter={sevFilter} setSevFilter={setSevFilter}
              statusFilter={statusFilter} setStatusFilter={setStatusFilter}
              expandedControl={expandedControl} setExpandedControl={setExpandedControl}
            />
          )}
          {activeTab === 'rootcause' && (
            <RootCauseTab
              rootCauses={data.root_causes}
              expandedRC={expandedRC}
              setExpandedRC={setExpandedRC}
            />
          )}
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════
   Overview Tab
   ═══════════════════════════════════════════════ */

function OverviewTab({ data, onNavigate }: { data: IntelligenceData; onNavigate: (fw: string) => void }) {
  const frameworks = Object.entries(data.frameworks);
  return (
    <div className="space-y-6">
      {/* Framework Grid */}
      <div className="grid grid-cols-2 gap-4">
        {frameworks.map(([key, fw]) => {
          const pct = fw.total_controls ? Math.round((fw.pass_count / fw.total_controls) * 100) : 0;
          const barColor = pct >= 80 ? CI.pass : pct >= 50 ? CI.warn : CI.fail;
          return (
            <button
              key={key}
              onClick={() => onNavigate(key)}
              className="ci-fade-up rounded-xl p-5 text-left transition-all hover:scale-[1.01]"
              style={{
                background: CI.surface,
                border: `1px solid ${CI.surfaceBorder}`,
                cursor: 'pointer',
              }}
            >
              <div className="flex items-center justify-between mb-3">
                <div>
                  <span className="text-sm font-semibold" style={{ color: CI.text }}>{fw.name}</span>
                  {fw.version && (
                    <span className="ml-2 px-1.5 py-0.5 rounded text-[10px] font-medium" style={{ background: 'rgba(255,255,255,0.06)', color: CI.textMuted }}>
                      {fw.version}
                    </span>
                  )}
                </div>
                <span style={{ fontFamily: CI.mono, fontSize: 18, fontWeight: 700, color: barColor }}>
                  {fw.risk_weighted_score}%
                </span>
              </div>
              {/* Progress bar */}
              <div className="w-full h-1.5 rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
                <div
                  className="h-full rounded-full"
                  style={{ width: `${pct}%`, background: barColor, transition: 'width 0.6s ease-out' }}
                />
              </div>
              <div className="flex gap-4 mt-3 text-[11px]" style={{ color: CI.textMuted }}>
                <span><span style={{ color: CI.pass, fontWeight: 600 }}>{fw.pass_count}</span> pass</span>
                <span><span style={{ color: CI.warn, fontWeight: 600 }}>{fw.warn_count}</span> warn</span>
                <span><span style={{ color: CI.fail, fontWeight: 600 }}>{fw.fail_count}</span> fail</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Top Root Causes Summary */}
      {data.root_causes.length > 0 && (
        <div className="rounded-xl p-5" style={{ background: CI.surface, border: `1px solid ${CI.surfaceBorder}` }}>
          <span style={{ fontSize: 10, color: CI.textMuted, fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase' }}>
            Top Root Causes
          </span>
          <div className="mt-3 space-y-3">
            {data.root_causes.slice(0, 3).map(rc => (
              <div key={rc.id} className="flex items-center gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-medium" style={{ color: CI.text }}>{rc.title}</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-medium" style={{ background: 'rgba(139,92,246,0.12)', color: CI.accent }}>
                      {rc.frameworks_impacted} fw
                    </span>
                  </div>
                  <div className="w-full h-1 rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${rc.impact_score}%`,
                        background: rc.impact_score >= 75 ? CI.fail : rc.impact_score >= 40 ? CI.warn : CI.pass,
                        transition: 'width 0.6s ease-out',
                      }}
                    />
                  </div>
                </div>
                <span style={{ fontFamily: CI.mono, fontSize: 14, fontWeight: 700, color: rc.impact_score >= 75 ? CI.fail : rc.impact_score >= 40 ? CI.warn : CI.pass }}>
                  {rc.impact_score}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Pass/Warn/Fail Summary */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard value={data.passing} label="Controls Passing" color={CI.pass} delay={0} />
        <StatCard value={data.warnings} label="Warnings" color={CI.warn} delay={80} />
        <StatCard value={data.failing} label="Failing" color={CI.fail} delay={160} />
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════
   Controls Tab
   ═══════════════════════════════════════════════ */

function ControlsTab({
  data, fwFilter, setFwFilter, sevFilter, setSevFilter, statusFilter, setStatusFilter,
  expandedControl, setExpandedControl,
}: {
  data: IntelligenceData;
  fwFilter: string | null; setFwFilter: (v: string | null) => void;
  sevFilter: string | null; setSevFilter: (v: string | null) => void;
  statusFilter: string | null; setStatusFilter: (v: string | null) => void;
  expandedControl: string | null; setExpandedControl: (v: string | null) => void;
}) {
  const frameworks = Object.entries(data.frameworks);

  // Collect all controls with framework context
  const allControls: (IntelControl & { fw_key: string; fw_name: string })[] = [];
  for (const [key, fw] of frameworks) {
    for (const ctrl of fw.controls) {
      allControls.push({ ...ctrl, fw_key: key, fw_name: fw.name });
    }
  }

  // Apply filters
  let filtered = allControls;
  if (fwFilter) filtered = filtered.filter(c => c.fw_key === fwFilter);
  if (sevFilter) filtered = filtered.filter(c => c.severity === sevFilter);
  if (statusFilter) filtered = filtered.filter(c => c.status === statusFilter);

  return (
    <div className="space-y-4">
      {/* Filter Bar */}
      <div className="flex flex-wrap gap-2 items-center">
        {/* Framework pills */}
        <div className="flex gap-1">
          <FilterPill label="All" active={!fwFilter} onClick={() => setFwFilter(null)} />
          {frameworks.map(([key, fw]) => (
            <FilterPill key={key} label={fw.name.split(' ')[0]} active={fwFilter === key} onClick={() => setFwFilter(fwFilter === key ? null : key)} />
          ))}
        </div>
        <div className="w-px h-5" style={{ background: CI.surfaceBorder }} />
        {/* Severity toggles */}
        <div className="flex gap-1">
          {['critical', 'high', 'medium', 'low'].map(s => (
            <FilterPill key={s} label={s} active={sevFilter === s} onClick={() => setSevFilter(sevFilter === s ? null : s)} color={CI.severity[s]} />
          ))}
        </div>
        <div className="w-px h-5" style={{ background: CI.surfaceBorder }} />
        {/* Status filter */}
        <div className="flex gap-1">
          {['pass', 'warn', 'fail'].map(s => (
            <FilterPill key={s} label={s} active={statusFilter === s} onClick={() => setStatusFilter(statusFilter === s ? null : s)} color={STATUS_COLORS[s].dot} />
          ))}
        </div>
        <span className="ml-auto text-xs" style={{ color: CI.textMuted }}>
          {filtered.length} of {allControls.length} controls
        </span>
      </div>

      {/* Controls List */}
      <div className="space-y-2">
        {filtered.map(ctrl => {
          const controlKey = `${ctrl.fw_key}-${ctrl.control_id}`;
          const isExpanded = expandedControl === controlKey;
          const sev = SEV_COLORS[ctrl.severity] || SEV_COLORS.medium;
          const st = STATUS_COLORS[ctrl.status];

          return (
            <div key={controlKey}>
              <button
                onClick={() => setExpandedControl(isExpanded ? null : controlKey)}
                className="w-full text-left rounded-xl px-5 py-3.5 transition-all"
                style={{
                  background: CI.surface,
                  border: `1px solid ${CI.surfaceBorder}`,
                  borderLeftWidth: 3,
                  borderLeftColor: CI.severity[ctrl.severity] || '#888',
                  boxShadow: isExpanded ? `0 0 12px ${CI.severity[ctrl.severity]}20` : 'none',
                }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: st.dot }} />
                    <span style={{ fontFamily: CI.mono, fontSize: 11, color: CI.textMuted, flexShrink: 0 }}>{ctrl.control_id}</span>
                    <span className="text-sm font-medium truncate" style={{ color: CI.text }}>{ctrl.name}</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-medium" style={{ background: sev.bg, color: sev.text }}>
                      {ctrl.severity}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0 ml-3">
                    {ctrl.status !== 'pass' && ctrl.evidence_count > 0 && (
                      <span className="text-[10px] font-medium" style={{ color: CI.textMuted }}>
                        {ctrl.evidence_count} entit{ctrl.evidence_count === 1 ? 'y' : 'ies'}
                      </span>
                    )}
                    <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: CI.cloud[ctrl.cloud] || '#666' }} title={ctrl.cloud} />
                    <span style={{ fontFamily: CI.mono, fontSize: 11, color: CI.textMuted }}>w{ctrl.weight}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase" style={{ background: st.bg, color: st.text }}>
                      {ctrl.status}
                    </span>
                    <svg
                      className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                      fill="none" viewBox="0 0 24 24" stroke="currentColor"
                      style={{ color: CI.textMuted }}
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </div>
                </div>
                <div className="mt-1 text-xs" style={{ color: CI.textMuted, paddingLeft: 28 }}>{ctrl.detail}</div>
              </button>

              {/* Expanded detail */}
              {isExpanded && (
                <div
                  className="ci-fade-up rounded-b-xl mx-2 px-5 py-4 space-y-4"
                  style={{ background: 'rgba(255,255,255,0.015)', border: `1px solid ${CI.surfaceBorder}`, borderTop: 'none' }}
                >
                  {/* Framework context */}
                  <div className="flex gap-4 text-xs" style={{ color: CI.textMuted }}>
                    <span>Framework: <span style={{ color: CI.text }}>{ctrl.fw_name}</span></span>
                    <span>Metric: <span style={{ fontFamily: CI.mono, color: CI.textSecondary }}>{ctrl.metric}</span></span>
                    <span>Threshold: <span style={{ fontFamily: CI.mono, color: CI.textSecondary }}>{ctrl.pass_threshold}</span></span>
                    <span>Current: <span style={{ fontFamily: CI.mono, color: st.text }}>{ctrl.value}</span></span>
                  </div>

                  {/* Evaluation logic */}
                  <div className="rounded-lg p-3" style={{ background: 'rgba(0,0,0,0.3)', border: `1px solid ${CI.surfaceBorder}` }}>
                    <span className="text-[10px] font-semibold uppercase" style={{ color: CI.textMuted, letterSpacing: 1 }}>Evaluation</span>
                    <div className="mt-1" style={{ fontFamily: CI.mono, fontSize: 12, color: CI.textSecondary }}>
                      {ctrl.metric}({ctrl.value}) {ctrl.status === 'pass' ? '✓' : '✗'} threshold({ctrl.pass_threshold})
                    </div>
                  </div>

                  {/* Evidence identities */}
                  {ctrl.evidence_identities && ctrl.evidence_identities.length > 0 && (
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-medium" style={{ color: CI.textSecondary }}>
                          Evidence: {ctrl.evidence_count} identit{ctrl.evidence_count === 1 ? 'y' : 'ies'}
                        </span>
                        {ctrl.drilldown_url && (
                          <Link to={ctrl.drilldown_url} className="text-xs font-medium hover:underline" style={{ color: CI.accent }}>
                            View All
                          </Link>
                        )}
                      </div>
                      <div className="rounded-lg overflow-hidden" style={{ border: `1px solid ${CI.surfaceBorder}` }}>
                        <table className="w-full text-xs">
                          <thead>
                            <tr style={{ background: 'rgba(255,255,255,0.03)' }}>
                              <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase" style={{ color: CI.textMuted }}>Identity</th>
                              <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase" style={{ color: CI.textMuted }}>Category</th>
                              <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase" style={{ color: CI.textMuted }}>Risk</th>
                              <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase" style={{ color: CI.textMuted }}>Score</th>
                              <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase" style={{ color: CI.textMuted }}>Reason</th>
                            </tr>
                          </thead>
                          <tbody>
                            {ctrl.evidence_identities.slice(0, 10).map(ev => (
                              <tr key={ev.id} className="transition" style={{ borderTop: `1px solid ${CI.surfaceBorder}` }}>
                                <td className="px-3 py-2">
                                  <Link to={`/identities/${ev.identity_id}`} className="hover:underline font-medium" style={{ color: CI.accent }}>
                                    {ev.display_name}
                                  </Link>
                                </td>
                                <td className="px-3 py-2" style={{ color: CI.textMuted }}>
                                  {(ev.identity_category || 'unknown').replace(/_/g, ' ')}
                                </td>
                                <td className="px-3 py-2">
                                  <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase"
                                    style={{ background: SEV_COLORS[ev.risk_level]?.bg || 'rgba(255,255,255,0.06)', color: SEV_COLORS[ev.risk_level]?.text || CI.textMuted }}>
                                    {ev.risk_level}
                                  </span>
                                </td>
                                <td className="px-3 py-2" style={{ fontFamily: CI.mono, color: CI.textSecondary }}>{ev.risk_score}</td>
                                <td className="px-3 py-2" style={{ color: CI.textMuted }}>{ev.reason}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        {ctrl.evidence_identities.length > 10 && (
                          <div className="px-4 py-2 text-xs text-center" style={{ color: CI.textMuted, borderTop: `1px solid ${CI.surfaceBorder}` }}>
                            Showing 10 of {ctrl.evidence_count}
                            {ctrl.drilldown_url && (
                              <Link to={ctrl.drilldown_url} className="ml-1 hover:underline" style={{ color: CI.accent }}>View all</Link>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
        {filtered.length === 0 && (
          <div className="text-center py-8 text-sm" style={{ color: CI.textMuted }}>No controls match the current filters.</div>
        )}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════
   Root Cause Tab
   ═══════════════════════════════════════════════ */

function RootCauseTab({
  rootCauses, expandedRC, setExpandedRC,
}: {
  rootCauses: RootCause[];
  expandedRC: number | null;
  setExpandedRC: (v: number | null) => void;
}) {
  if (rootCauses.length === 0) {
    return (
      <div className="text-center py-12 text-sm" style={{ color: CI.pass }}>
        No root cause clusters — all controls passing.
      </div>
    );
  }

  const PRIORITY_LABELS: Record<string, { label: string; color: string }> = {
    privilege: { label: 'PRIVILEGE', color: CI.severity.critical },
    credential: { label: 'CREDENTIAL', color: CI.severity.high },
    governance: { label: 'GOVERNANCE', color: CI.severity.medium },
    usage: { label: 'USAGE', color: '#42A5F5' },
    authentication: { label: 'AUTH', color: CI.severity.high },
    trust: { label: 'TRUST', color: CI.accent },
  };

  return (
    <div className="space-y-3">
      {rootCauses.map((rc, idx) => {
        const isExpanded = expandedRC === rc.id;
        const prio = PRIORITY_LABELS[rc.category || ''] || { label: rc.category?.toUpperCase() || 'OTHER', color: CI.textMuted };
        const barColor = rc.impact_score >= 75 ? CI.fail : rc.impact_score >= 40 ? CI.warn : CI.pass;

        return (
          <div key={rc.id} className="ci-fade-up" style={{ animationDelay: `${idx * 60}ms` }}>
            <button
              onClick={() => setExpandedRC(isExpanded ? null : rc.id)}
              className="w-full text-left rounded-xl px-5 py-4 transition-all"
              style={{
                background: CI.surface,
                border: `1px solid ${CI.surfaceBorder}`,
                boxShadow: isExpanded ? `0 0 16px ${barColor}15` : 'none',
              }}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-semibold" style={{ color: CI.text }}>{rc.title}</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold" style={{ background: `${prio.color}20`, color: prio.color }}>
                    {prio.label}
                  </span>
                  <span className="text-[10px]" style={{ color: CI.textMuted }}>{rc.frameworks_impacted} framework{rc.frameworks_impacted !== 1 ? 's' : ''}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span style={{ fontFamily: CI.mono, fontSize: 18, fontWeight: 700, color: barColor }}>
                    {rc.impact_score}
                  </span>
                  <svg
                    className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                    fill="none" viewBox="0 0 24 24" stroke="currentColor"
                    style={{ color: CI.textMuted }}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>
              {/* Impact bar */}
              <div className="w-full h-1 rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
                <div className="h-full rounded-full" style={{ width: `${rc.impact_score}%`, background: barColor, transition: 'width 0.6s ease-out' }} />
              </div>
            </button>

            {isExpanded && (
              <div
                className="ci-fade-up mx-2 rounded-b-xl px-5 py-4 space-y-3"
                style={{ background: 'rgba(255,255,255,0.015)', border: `1px solid ${CI.surfaceBorder}`, borderTop: 'none' }}
              >
                {rc.description && (
                  <p className="text-xs leading-relaxed" style={{ color: CI.textSecondary }}>{rc.description}</p>
                )}
                {rc.recommendation && (
                  <div className="rounded-lg p-3" style={{ background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.12)' }}>
                    <span className="text-[10px] font-semibold uppercase" style={{ color: CI.accent, letterSpacing: 1 }}>Recommendation</span>
                    <p className="text-xs mt-1" style={{ color: CI.textSecondary }}>{rc.recommendation}</p>
                  </div>
                )}
                {/* Linked controls */}
                <div>
                  <span className="text-[10px] font-semibold uppercase" style={{ color: CI.textMuted, letterSpacing: 1 }}>Linked Controls</span>
                  <div className="mt-2 space-y-1">
                    {rc.linked_controls.map((lc, i) => (
                      <div key={i} className="flex items-center gap-2 px-3 py-1.5 rounded-lg" style={{ background: 'rgba(255,255,255,0.02)' }}>
                        <span className="w-1.5 h-1.5 rounded-full" style={{ background: CI.severity[lc.severity] || '#888' }} />
                        <span style={{ fontFamily: CI.mono, fontSize: 10, color: CI.textMuted }}>{lc.control_id}</span>
                        <span className="text-xs" style={{ color: CI.textSecondary }}>{lc.name}</span>
                        <span className="ml-auto text-[10px]" style={{ color: CI.textMuted }}>{lc.framework}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ───────── Filter Pill ───────── */

function FilterPill({ label, active, onClick, color }: { label: string; active: boolean; onClick: () => void; color?: string }) {
  return (
    <button
      onClick={onClick}
      className="px-2.5 py-1 rounded-md text-[11px] font-medium transition-all capitalize"
      style={{
        background: active ? (color ? `${color}20` : 'rgba(255,255,255,0.1)') : 'transparent',
        color: active ? (color || CI.text) : CI.textMuted,
        border: `1px solid ${active ? (color ? `${color}30` : 'rgba(255,255,255,0.15)') : 'transparent'}`,
      }}
    >
      {label}
    </button>
  );
}
