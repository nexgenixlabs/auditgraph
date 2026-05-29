/**
 * AuditGraph — CISO Executive Posture Dashboard (v3.1)
 *
 * Two-phase loading via /api/dashboard/posture:
 *   Phase 1 (?include=core): Blocks 0-3 render immediately
 *   Phase 2 (?include=full): Blocks 4-7 hydrate in background
 *
 * Falls back to legacy /api/ciso/summary when v3.1 API unavailable.
 *
 * P0: Exclusive phase-state rendering — only ONE view at a time.
 */
import React, { useState, useEffect, useRef } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import { mapSummaryToViewModel, buildEmptyCISOViewModel, type CISOViewModel, type PostureV31Response } from '../utils/cisoViewModel';
import { DN } from '../components/dashboard/ciso-shared';
import { IdentityDrawerProvider } from '../contexts/IdentityDrawerContext';
import { IdentityContextDrawer } from '../components/dashboard/IdentityContextDrawer';
import { usePostureDashboard, type PosturePhase } from '../hooks/usePostureDashboard';

// Legacy VM components
import { NarrativePanel, RiskScorePanel, ConfidencePanel } from '../components/ciso/ExecutiveSummaryHero';
import { useInventorySummary } from '../hooks/useInventorySummary';
import { BlastRadiusCard, AttackPathCard, IdentityRiskCard } from '../components/ciso/BlastRadiusSection';
import { AnomalyWidget } from '../components/ciso/ActiveThreatsSection';
import { BusinessImpactWidget } from '../components/ciso/BusinessImpactSection';
import { DriftWidget } from '../components/ciso/ActivityDriftSection';
import { TopActionsPanel } from '../components/ciso/RemediationImpactSection';
import { ImmediateRisksPanel } from '../components/ciso/ImmediateRisksSection';

// v3.1 components
import { NarrativeBanner, PostureScoreHero } from '../components/ciso/ExecutiveSummaryHero';
import { BlastRadiusCardV31, AttackPathCardV31, IdentityRiskCardV31 } from '../components/ciso/BlastRadiusSection';
import { AIIdentityRiskCard } from '../components/ciso/AIIdentityRiskCard';
import { AnomalyWidgetV31 } from '../components/ciso/ActiveThreatsSection';
import { BusinessImpactWidgetV31 } from '../components/ciso/BusinessImpactSection';
import { DriftWidgetV31 } from '../components/ciso/ActivityDriftSection';
import { PriorityActionsPanelV31 } from '../components/ciso/RemediationImpactSection';
import { ImmediateRisksPanelV31 } from '../components/ciso/ImmediateRisksSection';
import { DataIntegrityFooter } from '../components/ciso/DataIntegrityFooter';
import { IdentityLegend } from '../components/ciso/IdentityLegend';
import { POSTURE_CONFIDENCE_COLOR, CONFIDENCE_DISPLAY_LABEL, CONFIDENCE_TOOLTIP } from '../constants/cisoColors';

// ─── Backend status values (SSOT — no frontend derivation) ──

type BackendStatus = 'DISCOVERY_REQUIRED' | 'PARTIAL' | 'READY' | 'ERROR';
type FrontendStatus = 'LOADING' | 'NOT_CONNECTED';
type CISOStatus = BackendStatus | FrontendStatus;

// ─── Legacy Data Hook (fallback for /api/ciso/summary) ──────

function useCISOSummary() {
  const { withConnection, selectedConnectionId, connections, loading: connectionLoading } = useConnection();
  const { activeOrgId } = useAuth();
  const [vm, setVm] = useState<CISOViewModel>(buildEmptyCISOViewModel);
  const [status, setStatus] = useState<CISOStatus>('LOADING');
  const [primaryGap, setPrimaryGap] = useState<string | null>(null);
  const [usableSources, setUsableSources] = useState(0);
  const [totalSources, setTotalSources] = useState(6);

  const prevDepsRef = useRef<string>('');
  const depsKey = `${selectedConnectionId ?? ''}|${activeOrgId ?? ''}`;
  if (prevDepsRef.current !== '' && prevDepsRef.current !== depsKey) {
    setStatus('LOADING');
  }
  prevDepsRef.current = depsKey;

  useEffect(() => {
    let cancelled = false;
    if (connectionLoading) return;
    if (connections.length === 0) { setStatus('NOT_CONNECTED'); return; }
    setStatus('LOADING');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    (async () => {
      try {
        const url = withConnection('/api/ciso/summary');
        const res = await fetch(url, { signal: controller.signal });
        const text = await res.text();
        if (!res.ok) throw new Error(`API returned ${res.status}`);
        let json: any;
        try { json = JSON.parse(text); } catch { throw new Error('Invalid JSON'); }
        if (cancelled) return;

        const backendStatus: string = json.status;
        const sources: number = json.usableSources ?? 0;
        setPrimaryGap(json.primaryGap || null);
        setUsableSources(sources);
        setTotalSources(json.totalSources ?? 6);

        if (backendStatus === 'ERROR') {
          setStatus('ERROR');
          setVm(buildEmptyCISOViewModel());
        } else if (sources === 0 || backendStatus === 'DISCOVERY_REQUIRED') {
          setStatus('DISCOVERY_REQUIRED');
          setVm(buildEmptyCISOViewModel());
        } else {
          setStatus(backendStatus as BackendStatus);
          setVm(mapSummaryToViewModel(json));
        }
      } catch {
        if (!cancelled) { setStatus('ERROR'); setVm(buildEmptyCISOViewModel()); }
      } finally {
        clearTimeout(timeout);
      }
    })();

    return () => { cancelled = true; controller.abort(); };
  }, [withConnection, selectedConnectionId, activeOrgId, connectionLoading, connections.length]);

  const activeConnection = connections.length > 0
    ? (() => {
        const selected = selectedConnectionId ? connections.find(c => c.id === selectedConnectionId) : null;
        const conn = selected || connections[0];
        return { label: conn.label, cloud: conn.cloud };
      })()
    : null;

  return { vm, status, primaryGap, usableSources, totalSources, activeConnection };
}

// ─── Skeleton Block ──────────────────────────────────────────

function SkeletonBlock() {
  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full animate-pulse">
      <div className="h-3 w-24 bg-white/5 rounded mb-2" />
      <div className="h-2 w-32 bg-white/5 rounded mb-1" />
      <div className="h-2 w-20 bg-white/5 rounded" />
    </div>
  );
}

// ─── P1 Fix 1: Unavailable block for full-failure ────────────

function UnavailableBlock() {
  return (
    <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col items-center justify-center gap-1">
      <span className="text-xs text-gray-400">No additional insights for this period</span>
      <span className="text-[10px] text-gray-500">Core posture data is up to date</span>
    </div>
  );
}

// ─── Legacy Partial-Visibility Banner ────────────────────────

const GAP_ACTIONS: Record<string, string> = {
  RISK_SUMMARY_FAILED: 'Run a discovery scan to complete your risk assessment',
  ANOMALY_DISABLED: 'Enable anomaly detection to monitor for suspicious activity',
  DRIFT_NOT_ENABLED: 'Run a second scan to track configuration changes over time',
  DRIFT_NEEDS_SECOND_SCAN: 'Run a second scan to track configuration changes over time',
  REMEDIATION_UNAVAILABLE: 'Configure remediation playbooks to enable automated fixes',
  SPN_UNAVAILABLE: 'Service principal data pending next discovery scan',
};

function PartialVisibilityBanner({ primaryGap, usableSources, totalSources }: {
  primaryGap: string | null; usableSources: number; totalSources: number;
}) {
  const gapMessage = primaryGap ? GAP_ACTIONS[primaryGap] : null;
  return (
    <div className="mx-3 mt-1 p-3 rounded-md bg-[rgba(245,158,11,0.06)] border border-[rgba(245,158,11,0.12)] flex items-center gap-3 flex-shrink-0">
      <svg className="w-3.5 h-3.5 text-amber-500/70 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" />
      </svg>
      <div className="min-w-0">
        <p className="text-xs text-amber-400/80 truncate">Partial visibility: {usableSources}/{totalSources} data sources active</p>
        <p className="text-xs text-gray-400 truncate">{gapMessage || 'Complete data collection to unlock full risk coverage'}</p>
      </div>
    </div>
  );
}

// ─── Timezone helper ─────────────────────────────────────────

function getTimezoneLabel(): string {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const offset = new Date().getTimezoneOffset();
    const sign = offset <= 0 ? '+' : '-';
    const h = Math.floor(Math.abs(offset) / 60);
    const m = Math.abs(offset) % 60;
    return `${tz} (UTC${sign}${h}${m > 0 ? ':' + String(m).padStart(2, '0') : ''})`;
  } catch {
    return 'UTC';
  }
}

// ─── P2 Pre-Scan Modal ────────────────────────────────────────

function P2PreScanModal({ onEnableAndScan, onScanWithout, onClose }: {
  onEnableAndScan: () => void; onScanWithout: () => void; onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-[#111827] border border-white/10 rounded-xl shadow-2xl w-[480px] max-w-[90vw] p-6"
           onClick={e => e.stopPropagation()}>
        <h3 className="text-sm font-semibold text-gray-100 mb-2">Enhanced Intelligence Available</h3>
        <p className="text-xs text-gray-400 mb-4 leading-relaxed">
          Your Azure connector supports activity log collection (Entra P2 detected).
          Enabling behavioral intelligence adds:
        </p>
        <ul className="space-y-2 mb-5">
          {[
            'Confirms dormant account verdicts with real sign-in data',
            'Detects active ghost identities missed by static analysis',
            'Validates orphaned SPN inactivity',
            'Surfaces behavioral anomalies and suspicious access patterns',
          ].map((item, i) => (
            <li key={i} className="flex items-start gap-2 text-xs text-gray-300">
              <span className="w-1 h-1 rounded-full bg-[#24A2A1] mt-1.5 flex-shrink-0" />
              {item}
            </li>
          ))}
        </ul>
        <div className="flex items-center justify-end gap-3">
          <button onClick={onScanWithout}
            className="px-4 py-2 rounded-lg text-xs font-medium text-gray-400 bg-[#0d1117] border border-white/5 hover:border-white/10 transition cursor-pointer">
            Scan without logs
          </button>
          <button onClick={onEnableAndScan}
            className="px-4 py-2 rounded-lg text-xs font-medium text-white bg-[#24A2A1] hover:bg-[#1d8a89] transition cursor-pointer">
            Enable &amp; Scan
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Page header (shared between v3.1 and error) ─────────────

function PageHeader() {
  const [showP2Modal, setShowP2Modal] = useState(false);
  const { activeOrgId } = useAuth();
  const navigate = React.useCallback((path: string) => {
    // DN navigateTo doesn't return a function we can call programmatically,
    // so we use window.location for the scan trigger
    window.location.href = path;
  }, []);

  const handleRescanClick = async () => {
    // Check if P2 prompt already shown for this org
    const storageKey = `p2_prompt_shown_${activeOrgId}`;
    const alreadyShown = localStorage.getItem(storageKey) === 'true';

    if (alreadyShown) {
      navigate('/settings');
      return;
    }

    try {
      const res = await fetch('/api/connections/p2-status');
      if (!res.ok) { navigate('/settings'); return; }
      const status = await res.json();

      if (status.p2_capable && !status.p2_enabled) {
        setShowP2Modal(true);
        return;
      }
    } catch {
      // On error, just navigate to settings
    }
    navigate('/settings');
  };

  const handleEnableAndScan = async () => {
    try {
      await fetch('/api/connections/p2-enable', { method: 'POST' });
    } catch { /* best-effort */ }
    const storageKey = `p2_prompt_shown_${activeOrgId}`;
    localStorage.setItem(storageKey, 'true');
    setShowP2Modal(false);
    navigate('/settings');
  };

  const handleScanWithout = () => {
    const storageKey = `p2_prompt_shown_${activeOrgId}`;
    localStorage.setItem(storageKey, 'true');
    setShowP2Modal(false);
    navigate('/settings');
  };

  return (
    <>
      <header className="flex items-center justify-between p-3 flex-shrink-0">
        <div className="flex items-baseline gap-3">
          <h1 className="text-sm font-semibold text-gray-200">Executive Posture</h1>
          <span className="text-xs text-gray-400">{getTimezoneLabel()}</span>
        </div>
        <div className="flex gap-3 flex-shrink-0">
          <DN navigateTo="/reports/executive">
            <button className="px-3 py-1.5 rounded text-xs font-medium text-gray-400 bg-[#111827] border border-white/5 hover:border-white/10 transition cursor-pointer">
              Export
            </button>
          </DN>
          <button onClick={handleRescanClick}
            className="px-3 py-1.5 rounded text-xs font-medium text-gray-400 bg-[#111827] border border-white/5 hover:border-white/10 transition cursor-pointer">
            Rescan
          </button>
          <DN navigateTo="/remediation">
            <button className="px-3 py-1.5 rounded text-xs font-medium text-white bg-[#24A2A1] border border-transparent cursor-pointer">
              + Remediate
            </button>
          </DN>
        </div>
      </header>
      {showP2Modal && (
        <P2PreScanModal
          onEnableAndScan={handleEnableAndScan}
          onScanWithout={handleScanWithout}
          onClose={() => setShowP2Modal(false)}
        />
      )}
    </>
  );
}

// ─── Start Here Banner ───────────────────────────────────────

interface StartHereData {
  unowned_identities: number;
  ghost_identities: number;
  dormant_privileged: number;
  risk_reduction_if_fixed: number;
  total_identities: number;
  open_remediations: number;
  critical_remediations: number;
  unowned_delta: number | null;
  ghost_delta: number | null;
  dormant_delta: number | null;
}

function DeltaBadge({ delta }: { delta: number | null }) {
  if (delta === null || delta === undefined) return null;
  if (delta < 0) return <span className="text-[10px] font-semibold text-[#1D9E75] ml-1">&darr;{Math.abs(delta)}</span>;
  if (delta > 0) return <span className="text-[10px] font-semibold text-[#E24B4A] ml-1">&uarr;{delta}</span>;
  return <span className="text-[10px] text-gray-500 ml-1">&mdash;</span>;
}

function StartHereBanner() {
  const [data, setData] = useState<StartHereData | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetch('/api/posture/start-here-summary')
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => setData(d))
      .catch(() => setError(true));
  }, []);

  // Hide while loading, or on error
  if (!data || error) return null;

  const { unowned_identities, ghost_identities, dormant_privileged,
          risk_reduction_if_fixed, total_identities, open_remediations,
          critical_remediations } = data;

  const hasIssues = unowned_identities > 0 || ghost_identities > 0 || dormant_privileged > 0;

  // Clean environment — green success banner
  if (!hasIssues) {
    return (
      <div className="mx-3 mt-1 flex-shrink-0 rounded-lg border-l-[3px] px-4 py-3"
           style={{ backgroundColor: '#111827', borderLeftColor: '#1D9E75', borderTopColor: '#1a2332', borderRightColor: '#1a2332', borderBottomColor: '#1a2332' }}>
        <p className="text-[13px] font-semibold text-gray-200 leading-tight">Your identity environment is clean.</p>
        <p className="text-xs text-gray-400 mt-0.5">No governance gaps, ghost accounts, or dormant privileged access detected.</p>
      </div>
    );
  }

  // Issues found — teal action banner
  return (
    <div className="mx-3 mt-1 flex-shrink-0 rounded-lg border-l-[3px] px-4 py-3 flex items-center gap-5"
         style={{ backgroundColor: '#111827', borderLeftColor: '#24A2A1', borderTopColor: '#1a2332', borderRightColor: '#1a2332', borderBottomColor: '#1a2332' }}>
      {/* Left: Lines 1-3 */}
      <div className="flex-1 min-w-0">
        {/* Line 1 — Static executive headline */}
        <p className="text-[13px] font-semibold text-gray-200 leading-tight">
          Critical identity governance gaps detected across your environment.
        </p>

        {/* Line 2 — Metric pills */}
        <div className="flex items-center gap-2 mt-1.5">
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-white/[0.04] text-xs">
            <span className="font-bold text-[#24A2A1] text-sm leading-none">{unowned_identities.toLocaleString()}</span>
            <span className="text-gray-400">unowned identities</span>
            <DeltaBadge delta={data.unowned_delta} />
          </span>
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-white/[0.04] text-xs">
            <span className="font-bold text-[#24A2A1] text-sm leading-none">{ghost_identities.toLocaleString()}</span>
            <span className="text-gray-400">ghost accounts</span>
            <DeltaBadge delta={data.ghost_delta} />
          </span>
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-white/[0.04] text-xs">
            <span className="font-bold text-[#24A2A1] text-sm leading-none">{dormant_privileged.toLocaleString()}</span>
            <span className="text-gray-400">dormant privileged</span>
            <DeltaBadge delta={data.dormant_delta} />
          </span>
        </div>

        {/* Line 3 — Risk reduction */}
        <p className="text-[11px] text-gray-500 mt-1">
          Resolving these eliminates your top 3 identity attack vectors and reduces critical identity exposure by{' '}
          <span className="font-bold text-[#24A2A1]">{risk_reduction_if_fixed}%</span>.
        </p>
      </div>

      {/* Right: CTA */}
      <DN navigateTo="/remediation">
        <span className="inline-flex items-center px-4 py-1.5 rounded-md bg-[#24A2A1] text-white text-xs font-semibold cursor-pointer hover:brightness-110 transition flex-shrink-0 whitespace-nowrap">
          Start Remediation &rarr;
        </span>
      </DN>
    </div>
  );
}

// ─── v3.1 Dashboard Grid ─────────────────────────────────────

function V31DashboardGrid({ data, coreOnly }: { data: PostureV31Response; coreOnly: boolean }) {
  const isFull = !coreOnly && !!(data.immediate_risks || data.priority_actions || data.anomalies || data.business_impact || data.drift);
  const coverage = data.coverage || { active_sources: 0, total_sources: 0, sub_count: 0, cloud_label: 'None', confidence_level: 'low' as const, coverage_pct: 0 };
  const scanMeta = data.scan_metadata || { last_scan_at: null, scan_duration_seconds: null, scan_count: 0, tenant_domain: null };
  const identityRisk = data.identity_risk || { dormant: 0, ghost: 0, unowned_nhi: 0, machine_pct: 0, total: 0 };

  // P2 Fix 5: Only show when coverage < 50%
  const lowCoverage = coverage.coverage_pct < 50 && coverage.total_sources > 0;
  const missingCount = Math.max(0, (coverage.total_sources || 0) - (coverage.active_sources || 0));

  // P1 Fix 1: Blocks 4-7 placeholder when full unavailable
  const FullBlockOrPlaceholder = coreOnly ? UnavailableBlock : SkeletonBlock;

  const confColor = POSTURE_CONFIDENCE_COLOR[coverage.confidence_level] || '#4a6080';

  return (
    <>
      <PageHeader />
      <StartHereBanner />

      {/* P2 Fix 5: Partial visibility banner — ONLY when coverage_pct < 50 */}
      {lowCoverage && (
        <div className="mx-3 mt-1 p-3 rounded-md bg-[rgba(245,158,11,0.06)] border border-[rgba(245,158,11,0.12)] flex items-center gap-3 flex-shrink-0">
          <svg className="w-3.5 h-3.5 text-amber-500/70 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" />
          </svg>
          <div className="min-w-0">
            <p className="text-xs text-amber-400/80">
              Partial visibility: {coverage.active_sources}/{coverage.total_sources} identity sources active
            </p>
            <p className="text-[10px] text-amber-500/60">
              {missingCount} source{missingCount !== 1 ? 's' : ''} missing — risk may be underestimated
            </p>
            <DN navigateTo="/settings/connectors">
              <span className="text-[10px] text-[#24A2A1] cursor-pointer">Connect now &rarr;</span>
            </DN>
          </div>
        </div>
      )}

      {/* ── Main Grid ── */}
      <div className="flex-1 px-3 pb-0 overflow-hidden grid grid-cols-12 gap-3" style={{ gridTemplateRows: '120px 140px 1fr' }}>

        {/* ━━━ ROW 1 — Block 1 (Narrative) + Block 2 (Score Hero) + Coverage ━━━ */}
        <div className="col-span-5">
          <NarrativeBanner data={data} />
        </div>
        <div className="col-span-4">
          <PostureScoreHero data={data} />
        </div>
        <div className="col-span-3">
          {/* P1 Fix 4: Coverage block */}
          <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col justify-center overflow-hidden">
            {/* Line 1: active/total identity sources */}
            <p className="text-sm font-medium text-gray-200 truncate">
              {coverage.active_sources}/{coverage.total_sources} identity sources active
            </p>
            {/* Line 2: cloud + subs */}
            <p className="text-[11px] text-gray-400 truncate">
              {coverage.cloud_label} &middot; {coverage.sub_count} subscription{coverage.sub_count !== 1 ? 's' : ''}
            </p>
            {/* Line 3: Confidence + visibility qualifier */}
            <p className="text-[10px] mt-0.5" style={{ color: confColor }} title={CONFIDENCE_TOOLTIP}>
              Confidence: {CONFIDENCE_DISPLAY_LABEL[coverage.confidence_level] || 'Improving'}{' '}
              ({coverage.coverage_pct >= 100 ? 'all sources active'
                : coverage.coverage_pct >= 80 ? 'most sources active'
                : coverage.coverage_pct >= 50 ? 'some sources inactive'
                : 'limited coverage'})
            </p>
            {/* Progress bar (% implicit from fill width) */}
            <div className="h-1 bg-[#1e2d4a] rounded-full mt-1.5 mb-1">
              <div className="h-1 rounded-full bg-[#24A2A1] transition-all" style={{ width: `${coverage.coverage_pct}%` }} />
            </div>
            {/* Missing source warning */}
            {missingCount > 0 && (
              <>
                <p className="text-[10px] text-amber-500/70 truncate">
                  {missingCount} source{missingCount !== 1 ? 's' : ''} not yet connected — risk may be underestimated
                </p>
                <DN navigateTo="/settings/connectors">
                  <span className="text-[10px] text-[#24A2A1] cursor-pointer">Connect now &rarr;</span>
                </DN>
              </>
            )}
          </div>
        </div>

        {/* ━━━ ROW 2 — Block 3 (Intel Row) — 4 peer tiles in a sub-grid so the
            AI Identity Risk pillar sits with Blast/Attack/Identity (the
            differentiator surfaces at the CISO level, not buried in AI Security).
            Right rail (col-span-3, row-span-2) is preserved. ━━━ */}
        <div className="col-span-9 grid grid-cols-4 gap-3">
          <BlastRadiusCardV31 data={data} />
          <AttackPathCardV31 data={data} />
          <IdentityRiskCardV31 data={data} />
          <AIIdentityRiskCard />
        </div>

        {/* Right Rail — spans row 2 + row 3 */}
        <div className="col-span-3 row-span-2 flex flex-col gap-3 overflow-hidden">
          {isFull ? (
            <>
              <AnomalyWidgetV31 data={data} />
              <BusinessImpactWidgetV31 data={data} />
              <DriftWidgetV31 data={data} />
            </>
          ) : (
            <>
              <FullBlockOrPlaceholder />
              <FullBlockOrPlaceholder />
              <FullBlockOrPlaceholder />
            </>
          )}
        </div>

        {/* ━━━ ROW 3 — Blocks 4-5 (Action Center) ━━━ */}
        <div className="col-span-5">
          {isFull ? <PriorityActionsPanelV31 data={data} /> : <FullBlockOrPlaceholder />}
        </div>
        <div className="col-span-4">
          {isFull ? <ImmediateRisksPanelV31 data={data} /> : <FullBlockOrPlaceholder />}
        </div>
      </div>

      {/* Data Integrity Footer */}
      <DataIntegrityFooter data={data} />

      {/* Identity Terminology Legend */}
      <IdentityLegend />
    </>
  );
}

// ─── Legacy Dashboard Grid ───────────────────────────────────

function LegacyDashboardGrid({ vm, status, primaryGap, usableSources, totalSources, inventorySubtitle, inventorySubscriptions, inventoryLastScan }: {
  vm: CISOViewModel; status: CISOStatus; primaryGap: string | null;
  usableSources: number; totalSources: number; inventorySubtitle: string;
  inventorySubscriptions?: number; inventoryLastScan?: string;
}) {
  return (
    <>
      <header className="flex items-center justify-between p-3 flex-shrink-0">
        <div className="flex items-baseline gap-3">
          <h1 className="text-sm font-semibold text-gray-200">Executive Posture</h1>
          <span className="text-xs text-gray-400">{inventorySubtitle}</span>
        </div>
        <div className="flex gap-3 flex-shrink-0">
          <button className="px-3 py-1.5 rounded text-xs font-medium text-gray-400 bg-[#111827] border border-white/5 hover:border-white/10 transition">
            Export
          </button>
          <DN navigateTo="/remediation">
            <button className="px-3 py-1.5 rounded text-xs font-medium text-white bg-[#24A2A1] border border-transparent cursor-pointer">
              + Remediate
            </button>
          </DN>
        </div>
      </header>
      {status === 'PARTIAL' && (
        <PartialVisibilityBanner primaryGap={primaryGap} usableSources={usableSources} totalSources={totalSources} />
      )}
      <div className="flex-1 px-3 pb-3 overflow-hidden grid grid-cols-12 gap-3" style={{ gridTemplateRows: '120px 140px 1fr' }}>
        <div className="col-span-5"><NarrativePanel vm={vm} /></div>
        <div className="col-span-4"><RiskScorePanel vm={vm} /></div>
        <div className="col-span-3"><ConfidencePanel vm={vm} inventorySubscriptions={inventorySubscriptions} inventoryLastScan={inventoryLastScan} /></div>
        <div className="col-span-3"><BlastRadiusCard vm={vm} /></div>
        <div className="col-span-3"><AttackPathCard vm={vm} /></div>
        <div className="col-span-3"><IdentityRiskCard vm={vm} /></div>
        <div className="col-span-3 row-span-2 flex flex-col gap-3 overflow-hidden">
          <AnomalyWidget vm={vm} />
          <BusinessImpactWidget vm={vm} />
          <DriftWidget vm={vm} />
        </div>
        <div className="col-span-5"><TopActionsPanel vm={vm} /></div>
        <div className="col-span-4"><ImmediateRisksPanel vm={vm} /></div>
      </div>

      {/* Identity Terminology Legend */}
      <IdentityLegend />
    </>
  );
}

// ─── Main Component (P0: exclusive phase-state rendering) ────

export default function CISODashboard() {
  const { data: v31Data, phase: v31Phase, refetch } = usePostureDashboard();
  const { vm, status: legacyStatus, primaryGap, usableSources, totalSources, activeConnection } = useCISOSummary();
  const { headerSubtitle: inventorySubtitle, totalInventorySubscriptions, lastDiscoveryFormatted } = useInventorySummary();
  const { connections, loading: connectionLoading } = useConnection();

  // P0: Determine EXCLUSIVE render path — exactly one branch renders
  const hasCoreData = v31Data != null && v31Data.coverage != null;

  return (
    <IdentityDrawerProvider>
      <div className="h-[calc(100vh-56px)] bg-[#0B1220] rounded-tl-card overflow-hidden flex flex-col">

        {/* ── 1. LOADING ── */}
        {connectionLoading ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="flex items-center gap-3">
              <div className="w-5 h-5 border-2 border-[#24A2A1] border-t-transparent rounded-full animate-spin" />
              <span className="text-xs text-gray-400">Loading executive briefing…</span>
            </div>
          </div>

        /* ── 2. NOT_CONNECTED ── */
        ) : connections.length === 0 ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="max-w-[460px] bg-[#111827] border border-white/5 rounded-xl p-4 text-center">
              <div className="w-12 h-12 mx-auto mb-3 rounded-full bg-[#1e2d4a] flex items-center justify-center">
                <svg className="w-6 h-6 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m9.293-9.293a4.5 4.5 0 00-6.364 0l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
                </svg>
              </div>
              <h3 className="text-base font-semibold text-gray-200 mb-1">No cloud tenant connected</h3>
              <p className="text-xs text-gray-400 mb-4">Connect your Azure tenant to start monitoring identity security posture.</p>
              <DN navigateTo="/settings">
                <span className="inline-flex items-center px-4 py-2 rounded-lg bg-[#24A2A1] text-white text-sm font-semibold cursor-pointer hover:brightness-110 transition">
                  Configure Connection
                </span>
              </DN>
            </div>
          </div>

        /* ── 3. P0: v3.1 core succeeded — show dashboard (partial or full) ── */
        ) : hasCoreData && v31Data ? (
          <V31DashboardGrid
            data={v31Data}
            coreOnly={v31Phase === 'core' || v31Phase === 'core_only'}
          />

        /* ── 4. Legacy: DISCOVERY_REQUIRED ── */
        ) : legacyStatus === 'DISCOVERY_REQUIRED' ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="w-[460px] bg-[#111827] border border-white/5 rounded-xl overflow-hidden">
              {activeConnection && (
                <div className="p-3 border-b border-white/5 flex items-center justify-between bg-[#0f1a2e]">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="text-xs text-gray-400 uppercase tracking-wider font-medium flex-shrink-0">Tenant</span>
                    <span className="text-xs font-medium text-gray-300 truncate">{activeConnection.label}</span>
                  </div>
                  <div className="flex items-center gap-1.5 flex-shrink-0">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    <span className="text-xs text-emerald-400 font-medium">Connected</span>
                  </div>
                </div>
              )}
              <div className="p-4 text-center">
                <div className="w-11 h-11 mx-auto mb-3 rounded-full bg-[#1e2d4a] flex items-center justify-center">
                  <svg className="w-5 h-5 text-[#24A2A1]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5" />
                  </svg>
                </div>
                <h3 className="text-base font-semibold text-gray-200 mb-1">Your environment has not been analyzed yet</h3>
                <p className="text-xs text-gray-400 max-w-[340px] mx-auto">Run a discovery scan to assess identity risk and build your executive posture view.</p>
              </div>
              <div className="px-4 pb-4 flex items-center justify-center gap-3">
                <DN navigateTo="/settings">
                  <span className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#24A2A1] text-white text-xs font-semibold cursor-pointer hover:brightness-110 transition">
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
                    </svg>
                    Run Discovery
                  </span>
                </DN>
                <DN navigateTo="/settings">
                  <span className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-transparent text-gray-400 text-xs font-medium border border-white/10 cursor-pointer hover:border-white/20 hover:text-gray-300 transition">
                    View Connection
                  </span>
                </DN>
              </div>
            </div>
          </div>

        /* ── 6. Legacy: PARTIAL / READY ── */
        ) : legacyStatus === 'PARTIAL' || legacyStatus === 'READY' ? (
          <LegacyDashboardGrid vm={vm} status={legacyStatus} primaryGap={primaryGap} usableSources={usableSources} totalSources={totalSources} inventorySubtitle={inventorySubtitle} inventorySubscriptions={totalInventorySubscriptions} inventoryLastScan={lastDiscoveryFormatted} />

        /* ── 7. Still loading v3.1 (legacy not ready either) ── */
        ) : v31Phase === 'loading' || legacyStatus === 'LOADING' ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="flex items-center gap-3">
              <div className="w-5 h-5 border-2 border-[#24A2A1] border-t-transparent rounded-full animate-spin" />
              <span className="text-xs text-gray-400">Loading executive briefing…</span>
            </div>
          </div>

        /* ── 8. Both v3.1 AND legacy failed — full-page error ── */
        ) : (
          <>
            <PageHeader />
            <div className="flex-1 flex items-center justify-center">
              <div className="max-w-[500px] bg-[#111827] border border-white/5 rounded-xl p-6 text-center">
                <div className="w-12 h-12 mx-auto mb-3 rounded-full bg-[#2d1e1e] flex items-center justify-center">
                  <svg className="w-6 h-6 text-red-400/70" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" />
                  </svg>
                </div>
                <h3 className="text-base font-semibold text-gray-200 mb-1">Posture data unavailable</h3>
                <p className="text-xs text-gray-400 mb-4">Last successful scan: {lastDiscoveryFormatted || 'Unknown'}</p>
                <button
                  onClick={() => refetch()}
                  className="inline-flex items-center px-4 py-2 rounded-lg bg-[#24A2A1] text-white text-sm font-semibold cursor-pointer hover:brightness-110 transition"
                >
                  Retry
                </button>
              </div>
            </div>
          </>
        )}

      </div>
      <IdentityContextDrawer />
    </IdentityDrawerProvider>
  );
}
