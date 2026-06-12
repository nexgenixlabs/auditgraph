/**
 * Lock-V2 (2026-06-11) — Human Identity bucket page.
 *
 * Exact replica of the founder reference comp (Human_identities.png):
 *   Header (title + subtitle + period + Filters)
 *   Tabs: Overview · Inventory · Access · Trust · Lifecycle · Governance
 *         · Privilege · Ownership · Attack Paths
 *   Overview tab content:
 *     5 KPI hero cards (Total / Active / High Risk / Critical Violations / Attack Paths)
 *     3 panels (Risk Distribution donut · Top Risk Reasons bar · Identities Over Time line)
 *     Recently Risky Identities table (Identity · Department · Risk · Reasons · Last Seen · Actions)
 *
 * Non-Overview tabs delegate to existing screens (Phase C wires those in).
 * For now non-Overview tabs render a stub that links to the legacy page.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import {
  BucketPageShell, BucketTabs, KpiHeroCard, RiskDistributionDonut,
  TopRiskReasonsBar, RecentlyRiskyTable, PanelCard,
  deriveRiskDistribution, deriveRiskReasons,
  type RecentlyRiskyRow,
} from '../components/identity-bucket/BucketShared';
import Identities from './Identities';
// Lock-V2 (2026-06-11) — embed existing per-tab content pages
import HumanAccess from './HumanAccess';
import HumanGovernance from './HumanGovernance';
import IdentityTrust from './IdentityTrust';
import LifecycleJml from './LifecycleJml';
import PIMOverprivilege from './PIMOverprivilege';
import OwnershipCenter from './OwnershipCenter';
import AttackPaths from './AttackPaths';

const ACCENT = '#3b82f6';

const HUMAN_ICON = (
  <svg viewBox="0 0 24 24" fill="none" stroke={ACCENT} strokeWidth="2" className="w-6 h-6">
    <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
  </svg>
);

// ─── Page ──────────────────────────────────────────────────────────

export default function HumanIdentityPage() {
  const navigate = useNavigate();
  const { withConnection, selectedConnectionId } = useConnection();
  const [summary, setSummary] = useState<any>(null);
  const [identities, setIdentities] = useState<any[]>([]);
  const [attackPaths, setAttackPaths] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch('/api/identity-summary').then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/identities?identity_category=human_user&limit=200')).then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/attack-paths?limit=50')).then(r => r.ok ? r.json() : null),
    ]).then(([sum, ids, atk]) => {
      if (cancelled) return;
      setSummary(sum || null);
      const list = Array.isArray(ids?.identities) ? ids.identities : [];
      setIdentities(list);
      const paths = Array.isArray(atk?.paths) ? atk.paths : Array.isArray(atk?.attack_paths) ? atk.attack_paths : [];
      setAttackPaths(paths);
      setLoading(false);
    }).catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  const cats = summary?.categories || {};
  const humanCat = useMemo(() => {
    const h = cats.human_user || {};
    const g = cats.guest || {};
    return {
      total: (h.total || 0) + (g.total || 0),
      critical: (h.critical || 0) + (g.critical || 0),
      high: (h.high || 0) + (g.high || 0),
      medium: (h.medium || 0) + (g.medium || 0),
      low: (h.low || 0) + (g.low || 0),
      info: (h.info || 0) + (g.info || 0),
    };
  }, [cats]);

  const active = identities.filter(i => String(i.status || '').toLowerCase() === 'active').length;
  const highRisk = humanCat.critical + humanCat.high;
  const criticalViolations = identities.filter(i => i.governance_state === 'Policy Violation' && (i.risk_level === 'critical' || i.risk_level === 'high')).length;
  // Lock-V2 fix (2026-06-11) — count ONLY genuinely human-sourced paths.
  // Earlier `|| attackPaths.length` fallback showed every path as Human's,
  // inflating the tab badge. Now if source typing is absent the badge stays
  // 0 (BucketTabs hides the chip below 1).
  const humanAttackPaths = attackPaths.filter(p => {
    const t = String(p.source_entity_type || p.source_type || '').toLowerCase();
    return t.includes('human') || t.includes('user') || t.includes('guest');
  }).length;

  const riskDist = deriveRiskDistribution(humanCat);
  const topReasons = deriveRiskReasons(identities, 5);

  const recentlyRisky: RecentlyRiskyRow[] = identities
    .filter(i => ['critical', 'high', 'medium'].includes(String(i.risk_level || '').toLowerCase()))
    .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
    .slice(0, 8)
    .map(i => ({
      identity_id: i.identity_id,
      display_name: i.display_name,
      secondary: i.department || '—',
      risk_level: i.risk_level,
      risk_reasons: Array.isArray(i.risk_reasons) ? i.risk_reasons.slice(0, 2).join(', ') : (i.risk_reasons || ''),
      last_seen: i.last_seen_auth || i.last_sign_in || i.created_datetime || null,
    }));

  const tabs = [
    { key: 'overview',     label: 'Overview' },
    { key: 'inventory',    label: 'Inventory', count: humanCat.total },
    { key: 'access',       label: 'Access' },
    { key: 'trust',        label: 'Trust' },
    { key: 'lifecycle',    label: 'Lifecycle' },
    { key: 'governance',   label: 'Governance' },
    { key: 'privilege',    label: 'Privilege' },
    { key: 'ownership',    label: 'Ownership' },
    { key: 'attack-paths', label: 'Attack Paths', count: humanAttackPaths },
  ];

  const { activeTab, tabStrip } = BucketTabs({ tabs, defaultTab: 'overview', accent: ACCENT });

  return (
    <BucketPageShell
      title="Human Identity"
      subtitle="Manage and secure human identities including employees, contractors, and guests."
      icon={HUMAN_ICON}
      accent={ACCENT}
    >
      {tabStrip}

      {activeTab === 'overview' && (
        <OverviewTab
          loading={loading}
          navigate={navigate}
          totalHumans={humanCat.total}
          active={active}
          highRisk={highRisk}
          criticalViolations={criticalViolations}
          attackPaths={humanAttackPaths}
          riskDist={riskDist}
          topReasons={topReasons}
          totalReasons={identities.length}
          recentlyRisky={recentlyRisky}
        />
      )}

      {activeTab === 'inventory'    && <TabFrame><Identities tabScope="humans" /></TabFrame>}
      {activeTab === 'access'       && <TabFrame><HumanAccess /></TabFrame>}
      {activeTab === 'trust'        && <TabFrame><IdentityTrust forceType="human" /></TabFrame>}
      {activeTab === 'lifecycle'    && <TabFrame><LifecycleJml forceType="human" /></TabFrame>}
      {activeTab === 'governance'   && <TabFrame><HumanGovernance /></TabFrame>}
      {activeTab === 'privilege'    && <TabFrame><PIMOverprivilege /></TabFrame>}
      {activeTab === 'ownership'    && <TabFrame><OwnershipCenter forceScope="human" /></TabFrame>}
      {activeTab === 'attack-paths' && <TabFrame><AttackPaths forceSourceType="human" /></TabFrame>}
    </BucketPageShell>
  );
}

// ─── Overview tab content ──────────────────────────────────────────

function OverviewTab({
  loading, totalHumans, active, highRisk, criticalViolations, attackPaths,
  riskDist, topReasons, totalReasons, recentlyRisky, navigate,
}: {
  loading: boolean;
  totalHumans: number; active: number; highRisk: number; criticalViolations: number; attackPaths: number;
  riskDist: any; topReasons: any[]; totalReasons: number;
  recentlyRisky: RecentlyRiskyRow[];
  navigate: (path: string) => void;  // V2.8 (2026-06-11) — passed through for KPI drill-in
}) {
  if (loading) {
    return <div className="flex items-center justify-center py-16"><div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" /></div>;
  }
  return (
    <div className="space-y-4 mt-4">
      {/* 5 KPI hero cards.
          V2.4 (2026-06-11) — deltaPct stripped pending a real 30-day-prior
          snapshot endpoint. Fake "+4.2%" on a fresh tenant was misleading.
          KpiHeroCard renders "No prior-period baseline yet" when undefined. */}
      {/* V2.8 (2026-06-11) — KPI tiles now drill into filtered views per
          peer review. Total → Inventory, Active → Inventory?status=active,
          High Risk → Inventory?risk_level=high+critical, etc. */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
        <KpiHeroCard label="Total Humans" value={totalHumans}
          onClick={() => navigate('/human?tab=inventory')}
          icon={<UserIcon />} iconColor="#3b82f6" valueColor="#e2e8f0" />
        <KpiHeroCard label="Active" value={active}
          onClick={() => navigate('/identities?identity_category=human_user&status=active')}
          icon={<CheckIcon />} iconColor="#34d399" valueColor="#34d399" />
        <KpiHeroCard label="High Risk" value={highRisk}
          onClick={() => navigate('/identities?identity_category=human_user&risk_level=critical,high')}
          icon={<AlertIcon />} iconColor="#f87171" valueColor="#f87171" />
        <KpiHeroCard label="Critical Violations" value={criticalViolations}
          onClick={() => navigate('/identities?identity_category=human_user&risk_level=critical&pillar=ownership-governance')}
          icon={<ShieldIcon />} iconColor="#ef4444" valueColor="#ef4444" />
        <KpiHeroCard label="Attack Paths" value={attackPaths}
          onClick={() => navigate('/human?tab=attack-paths')}
          icon={<PathIcon />} iconColor="#a78bfa" valueColor="#a78bfa" />
      </div>

      {/* 3 panels row */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <RiskDistributionDonut entries={riskDist} total={riskDist.reduce((a: number, e: any) => a + e.value, 0)} />
        <TopRiskReasonsBar entries={topReasons} total={totalReasons} subtitle="Why humans are at risk" />
        <IdentitiesOverTime total={totalHumans} />
      </div>

      {/* Recently Risky */}
      <RecentlyRiskyTable rows={recentlyRisky} secondaryHeader="Department" lastHeader="Last Seen" />
    </div>
  );
}

// ─── Identities Over Time (right-panel for Human bucket) ───────────

function IdentitiesOverTime({ total }: { total: number }) {
  // V2.5 (2026-06-11) — was painting a fake sin-wave curve on every tenant,
  // including fresh ones with 0 identities. Now: only render the curve when
  // we have real history (i.e., total > 0 AND a real trend endpoint exists).
  // Until that endpoint lands, all tenants show the honest empty state.
  const hasRealHistory = false;  // TODO: wire when /api/identities/trend?days=30 lands
  const W = 320, H = 140;
  return (
    <PanelCard title="Identities Over Time" subtitle="Count over time">
      {total === 0 || !hasRealHistory ? (
        <div className="h-[140px] flex flex-col items-center justify-center">
          <p className="text-[11px] text-slate-500">No trend history yet</p>
          <p className="text-[10px] text-slate-600 mt-1">Curve appears after the first scan</p>
        </div>
      ) : (
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-[140px]" />
      )}
      <div className="flex items-center justify-between text-[10px] text-slate-500 mt-2">
        <span>30 days ago</span>
        <span>Today</span>
      </div>
    </PanelCard>
  );
}

// ─── Tab placeholder helpers ───────────────────────────────────────

function TabFrame({ children }: { children: React.ReactNode }) {
  return <div className="mt-4 rounded-xl bg-[#0f172a]/80 border border-white/5 overflow-hidden">{children}</div>;
}

function TabPending({ label }: { label: string }) {
  return (
    <div className="mt-4 rounded-xl bg-[#0f172a]/80 border border-white/5 p-12 text-center">
      <p className="text-sm text-slate-300 font-medium mb-1">{label}</p>
      <p className="text-xs text-slate-500">This tab is being wired in Phase C. Existing content remains reachable at the legacy URL.</p>
      <Link to="/identity-explorer" className="inline-block mt-3 text-xs text-violet-400 hover:text-violet-300">Open All Identities →</Link>
    </div>
  );
}

// ─── Icons ─────────────────────────────────────────────────────────

const UserIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>;
const CheckIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>;
const AlertIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>;
const ShieldIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 2L4 6v6c0 5.5 3.6 10.7 8 12 4.4-1.3 8-6.5 8-12V6l-8-4z"/></svg>;
const PathIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684z"/></svg>;
