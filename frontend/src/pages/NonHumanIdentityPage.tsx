/**
 * Lock-V2 (2026-06-11) — Non-Human Identity bucket page.
 *
 * Exact replica of the founder reference comp (NHI_identities.png):
 *   Tabs: Overview · Inventory · Access · Trust · Lifecycle · Governance
 *         · Ownership · Secrets · Attack Paths
 *   Overview tab right-panel = Identity Types (count bars per NHI type),
 *   not Identities Over Time. Recently Risky table uses "Last Used".
 */
import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import {
  BucketPageShell, BucketTabs, KpiHeroCard, RiskDistributionDonut,
  TopRiskReasonsBar, RecentlyRiskyTable, PanelCard,
  deriveRiskDistribution, deriveRiskReasons,
  type RecentlyRiskyRow,
} from '../components/identity-bucket/BucketShared';
import Identities from './Identities';
// Lock-V2 (2026-06-11) — per-tab content embeds
import NHIAccess from './NHIAccess';
import NHIGovernance from './NHIGovernance';
import NHISecrets from './NHISecrets';
import IdentityTrust from './IdentityTrust';
import LifecycleJml from './LifecycleJml';
import OwnershipCenter from './OwnershipCenter';
import AttackPaths from './AttackPaths';

const ACCENT = '#f97316';

const NHI_ICON = (
  <svg viewBox="0 0 24 24" fill="none" stroke={ACCENT} strokeWidth="2" className="w-6 h-6">
    <path strokeLinecap="round" strokeLinejoin="round" d="M21 16.5c0 .38-.21.71-.53.88l-7.9 4.44c-.16.12-.36.18-.57.18s-.41-.06-.57-.18l-7.9-4.44A.991.991 0 013 16.5v-9c0-.38.21-.71.53-.88l7.9-4.44c.16-.12.36-.18.57-.18s.41.06.57.18l7.9 4.44c.32.17.53.5.53.88v9zM12 4.15L6.04 7.5 12 10.85l5.96-3.35L12 4.15zM5 15.91l6 3.38v-6.71L5 9.21v6.7zm14 0v-6.7l-6 3.37v6.71l6-3.38z" />
  </svg>
);

export default function NonHumanIdentityPage() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [summary, setSummary] = useState<any>(null);
  const [identities, setIdentities] = useState<any[]>([]);
  const [categorySum, setCategorySum] = useState<any>({});
  const [attackPaths, setAttackPaths] = useState<any[]>([]);
  // V2.12 (2026-06-12) — pull ownership summary so we can show the
  // owned/unowned split alongside the Risk Distribution. Without this, the
  // founder sees "100% critical" on the donut + "13% owned" on Ownership
  // Center and reads them as contradictory.
  const [ownershipSummary, setOwnershipSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch('/api/identity-summary').then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/identities?limit=500')).then(r => r.ok ? r.json() : null),
      fetch('/api/identities/category-summary').then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/attack-paths?limit=50')).then(r => r.ok ? r.json() : null),
      fetch('/api/ownership/summary').then(r => r.ok ? r.json() : null),
    ]).then(([sum, ids, catSum, atk, ownSum]) => {
      if (cancelled) return;
      setSummary(sum || null);
      const list = Array.isArray(ids?.identities) ? ids.identities.filter((i: any) =>
        ['service_principal', 'managed_identity_system', 'managed_identity_user', 'workload'].includes(i.identity_category)
      ) : [];
      setIdentities(list);
      setCategorySum(catSum || {});
      const paths = Array.isArray(atk?.paths) ? atk.paths : Array.isArray(atk?.attack_paths) ? atk.attack_paths : [];
      setAttackPaths(paths);
      setOwnershipSummary(ownSum || null);
      setLoading(false);
    }).catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  const cats = summary?.categories || {};
  const nhiCat = useMemo(() => {
    const keys = ['service_principal', 'managed_identity_system', 'managed_identity_user', 'workload'];
    return keys.reduce((acc, k) => {
      const c = cats[k] || {};
      return {
        total: acc.total + (c.total || 0),
        critical: acc.critical + (c.critical || 0),
        high: acc.high + (c.high || 0),
        medium: acc.medium + (c.medium || 0),
        low: acc.low + (c.low || 0),
        info: acc.info + (c.info || 0),
      };
    }, { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  }, [cats]);

  const active = identities.filter(i => String(i.status || '').toLowerCase() === 'active').length;
  const highRisk = nhiCat.critical + nhiCat.high;
  const criticalViolations = identities.filter(i => i.governance_state === 'Policy Violation' && (i.risk_level === 'critical' || i.risk_level === 'high')).length;
  // Lock-V2 fix (2026-06-11) — no fabricated fallback. If source typing is
  // absent the badge stays 0; BucketTabs hides the chip when count < 1.
  const nhiPaths = attackPaths.filter(p => {
    const t = String(p.source_entity_type || p.source_type || '').toLowerCase();
    return t.includes('spn') || t.includes('service_principal') || t.includes('managed_identity') || t.includes('nhi');
  }).length;

  const riskDist = deriveRiskDistribution(nhiCat);
  const topReasons = deriveRiskReasons(identities, 5);

  // NHI types breakdown
  const typeEntries = [
    { label: 'Service Accounts',   value: cats.service_principal?.total || 0,        color: '#f97316' },
    { label: 'Managed Identities', value: (cats.managed_identity_system?.total || 0) + (cats.managed_identity_user?.total || 0), color: '#3b82f6' },
    { label: 'Workload Identities', value: cats.workload?.total || 0,                color: '#a78bfa' },
    { label: 'API Keys / Tokens',  value: identities.filter(i => (i as any).is_federated || (i as any).has_federated_credentials).length, color: '#34d399' },
  ];

  const recentlyRisky: RecentlyRiskyRow[] = identities
    .filter(i => ['critical', 'high', 'medium'].includes(String(i.risk_level || '').toLowerCase()))
    .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
    .slice(0, 8)
    .map(i => ({
      identity_id: i.identity_id,
      display_name: i.display_name,
      secondary: nhiTypeLabel(i.identity_category),
      risk_level: i.risk_level,
      risk_reasons: Array.isArray(i.risk_reasons) ? i.risk_reasons.slice(0, 2).join(', ') : (i.risk_reasons || ''),
      last_seen: i.last_seen_auth || i.last_sign_in || null,
    }));

  const tabs = [
    { key: 'overview',     label: 'Overview' },
    { key: 'inventory',    label: 'Inventory', count: nhiCat.total },
    { key: 'access',       label: 'Access' },
    { key: 'trust',        label: 'Trust' },
    { key: 'lifecycle',    label: 'Lifecycle' },
    { key: 'governance',   label: 'Governance' },
    { key: 'ownership',    label: 'Ownership' },
    { key: 'secrets',      label: 'Secrets' },
    { key: 'attack-paths', label: 'Attack Paths', count: nhiPaths },
  ];

  const { activeTab, tabStrip } = BucketTabs({ tabs, defaultTab: 'overview', accent: ACCENT });

  return (
    <BucketPageShell
      title="Non-Human Identity"
      subtitle="Secure machine identities, service accounts, and workloads."
      icon={NHI_ICON}
      accent={ACCENT}
    >
      {tabStrip}

      {activeTab === 'overview' && (
        <OverviewTab
          loading={loading}
          totalNhi={nhiCat.total}
          active={active}
          highRisk={highRisk}
          criticalViolations={criticalViolations}
          attackPaths={nhiPaths}
          riskDist={riskDist}
          topReasons={topReasons}
          totalReasons={identities.length}
          recentlyRisky={recentlyRisky}
          typeEntries={typeEntries}
          ownershipSummary={ownershipSummary}
        />
      )}

      {activeTab === 'inventory'    && <TabFrame><Identities tabScope="nhi" /></TabFrame>}
      {activeTab === 'access'       && <TabFrame><NHIAccess /></TabFrame>}
      {activeTab === 'trust'        && <TabFrame><IdentityTrust forceType="nhi" /></TabFrame>}
      {activeTab === 'lifecycle'    && <TabFrame><LifecycleJml forceType="nhi" /></TabFrame>}
      {activeTab === 'governance'   && <TabFrame><NHIGovernance /></TabFrame>}
      {activeTab === 'ownership'    && <TabFrame><OwnershipCenter forceScope="nhi" /></TabFrame>}
      {activeTab === 'secrets'      && <TabFrame><NHISecrets /></TabFrame>}
      {activeTab === 'attack-paths' && <TabFrame><AttackPaths forceSourceType="nhi" /></TabFrame>}
    </BucketPageShell>
  );
}

function nhiTypeLabel(cat: string): string {
  switch (cat) {
    case 'service_principal': return 'Service Account';
    case 'managed_identity_system':
    case 'managed_identity_user': return 'Managed Identity';
    case 'workload': return 'Workload Identity';
    default: return 'NHI';
  }
}

function OverviewTab({
  loading, totalNhi, active, highRisk, criticalViolations, attackPaths,
  riskDist, topReasons, totalReasons, recentlyRisky, typeEntries, ownershipSummary,
}: any) {
  if (loading) {
    return <div className="flex items-center justify-center py-16"><div className="animate-spin h-8 w-8 border-2 border-orange-500 border-t-transparent rounded-full" /></div>;
  }
  return (
    <div className="space-y-4 mt-4">
      {/* V2.4 (2026-06-11) — deltaPct stripped pending real prior-period
          snapshot endpoint. KpiHeroCard shows "No prior-period baseline yet". */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
        <KpiHeroCard label="Total Non-Human" value={totalNhi}
          icon={<NhiIcon />} iconColor="#f97316" valueColor="#e2e8f0" />
        <KpiHeroCard label="Active" value={active}
          icon={<CheckIcon />} iconColor="#34d399" valueColor="#34d399" />
        <KpiHeroCard label="High Risk" value={highRisk}
          icon={<AlertIcon />} iconColor="#f87171" valueColor="#f87171" />
        <KpiHeroCard label="Critical Violations" value={criticalViolations}
          icon={<ShieldIcon />} iconColor="#ef4444" valueColor="#ef4444" />
        <KpiHeroCard label="Attack Paths" value={attackPaths}
          icon={<PathIcon />} iconColor="#a78bfa" valueColor="#a78bfa" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* V2.12 (2026-06-12) — explainer now reconciles with Ownership
            Center. Founder saw "100% critical" + "13% owned" as a
            contradiction; both numbers are correct but live in separate
            mental models. This block shows the alignment: of the critical
            NHIs, N are owned-but-failing-other-checks vs M are unowned. */}
        <RiskDistributionDonut entries={riskDist} total={riskDist.reduce((a: number, e: any) => a + e.value, 0)}
          explainer={
            <>
              <span className="font-semibold text-slate-300">Why is the bar mostly critical?</span>{' '}
              NHIs default to <strong className="text-red-300">CRITICAL</strong> until evidence proves them safe (owned, recently used, scope-bounded). This default-deny posture follows the{' '}
              <span className="text-slate-300">CSA NHI Risk Framework (2024)</span> and Wiz's Service Account Risk Profile. As owners are assigned, last-used data lands, and scope tightens, identities migrate down to High → Medium → Low.
              {ownershipSummary && ownershipSummary.total_nhi > 0 && (
                <span className="block mt-2 pt-2 border-t border-slate-700/50">
                  <span className="text-slate-300 font-semibold">Ownership context:</span>{' '}
                  Of the {ownershipSummary.total_nhi.toLocaleString()} NHIs flagged critical,{' '}
                  <strong className="text-emerald-300">{ownershipSummary.active_assigned.toLocaleString()} have ownership signals</strong>{' '}
                  but still fail other safety checks (expired creds, no recent activity, ungated auth) ·{' '}
                  <strong className="text-rose-300">{ownershipSummary.unowned.toLocaleString()} are unowned</strong> entirely.
                  {' '}<Link to="/ownership" className="text-violet-400 hover:text-violet-300">Open Ownership Center →</Link>
                </span>
              )}
            </>
          }
        />
        <TopRiskReasonsBar entries={topReasons} total={totalReasons} subtitle="Why NHIs are at risk" />
        <PanelCard title="Identity Types" subtitle="By type">
          <ul className="space-y-3">
            {typeEntries.map((e: any) => (
              <li key={e.label}>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="text-slate-300">{e.label}</span>
                  <span className="font-mono text-slate-200">{e.value.toLocaleString()}</span>
                </div>
                <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                  <div className="h-full rounded-full" style={{ width: `${Math.min(100, (e.value / Math.max(1, typeEntries[0].value)) * 100)}%`, background: e.color }} />
                </div>
              </li>
            ))}
          </ul>
        </PanelCard>
      </div>

      <RecentlyRiskyTable rows={recentlyRisky} secondaryHeader="Type" lastHeader="Last Used" title="Recently Risky Non-Human Identities" />
    </div>
  );
}

function TabFrame({ children }: { children: React.ReactNode }) {
  return <div className="mt-4 rounded-xl bg-[#0f172a]/80 border border-white/5 overflow-hidden">{children}</div>;
}
function TabPending({ label }: { label: string }) {
  return (
    <div className="mt-4 rounded-xl bg-[#0f172a]/80 border border-white/5 p-12 text-center">
      <p className="text-sm text-slate-300 font-medium mb-1">{label}</p>
      <p className="text-xs text-slate-500">This tab is being wired in Phase C.</p>
      <Link to="/identity-explorer" className="inline-block mt-3 text-xs text-violet-400 hover:text-violet-300">Open All Identities →</Link>
    </div>
  );
}

const NhiIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M21 16.5c0 .38-.21.71-.53.88l-7.9 4.44a1.06 1.06 0 01-1.14 0l-7.9-4.44A.991.991 0 013 16.5v-9c0-.38.21-.71.53-.88l7.9-4.44a1.06 1.06 0 011.14 0l7.9 4.44c.32.17.53.5.53.88v9z"/></svg>;
const CheckIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>;
const AlertIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>;
const ShieldIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 2L4 6v6c0 5.5 3.6 10.7 8 12 4.4-1.3 8-6.5 8-12V6l-8-4z"/></svg>;
const PathIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684z"/></svg>;
