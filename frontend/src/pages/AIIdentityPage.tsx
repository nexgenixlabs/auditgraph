/**
 * Lock-V2 (2026-06-11) — AI Identity bucket page.
 *
 * Exact replica of the founder reference comp (AI_indentities.png):
 *   Tabs: Overview · Inventory · Access · Lifecycle · Governance
 *         · Privilege · Ownership · Attack Paths
 *   AI bucket drops Trust + Secrets, keeps Privilege.
 *   Right panel = AI Identity Types breakdown.
 *   Recently Risky uses "Last Active".
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
import AIInventory from './AIInventory';
// Lock-V2 (2026-06-11) — per-tab content embeds (AI now mirrors NHI structure
// per founder revision: no Privilege tab, has Trust + Secrets like NHI)
import AIAccess from './AIAccess';
import AIGovernance from './AIGovernance';
import AILifecycle from './AILifecycle';
import IdentityTrust from './IdentityTrust';
import OwnershipCenter from './OwnershipCenter';
import NHISecrets from './NHISecrets';
import AttackPaths from './AttackPaths';

const ACCENT = '#a78bfa';

const AI_ICON = (
  <svg viewBox="0 0 24 24" fill="none" stroke={ACCENT} strokeWidth="2" className="w-6 h-6">
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 2a2 2 0 012 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 017 7h1a1 1 0 011 1v3a1 1 0 01-1 1h-1v1a2 2 0 01-2 2H5a2 2 0 01-2-2v-1H2a1 1 0 01-1-1v-3a1 1 0 011-1h1a7 7 0 017-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 012-2z" />
  </svg>
);

// AI-specific risk reasons (per reference comp)
const AI_RISK_REASONS = [
  { label: 'Unrestricted Tools',     value: 36, color: '#a78bfa' },
  { label: 'Over-Permissive Prompts', value: 25, color: '#60a5fa' },
  { label: 'Excessive Data Access',   value: 18, color: '#fb923c' },
  { label: 'No Human Oversight',      value: 13, color: '#f87171' },
  { label: 'Other',                   value: 8,  color: '#94a3b8' },
];

export default function AIIdentityPage() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [summary, setSummary] = useState<any>(null);
  const [identities, setIdentities] = useState<any[]>([]);
  const [categorySum, setCategorySum] = useState<any>({});
  const [attackPaths, setAttackPaths] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch('/api/identity-summary').then(r => r.ok ? r.json() : null),
      // V2.8 (2026-06-11) — wire to /api/agent-identities (the purpose-
      // built AI endpoint) instead of filtering /api/identities client-side.
      // Peer review found AI Identity page showing 77/0/0/0 because the
      // generic /api/identities endpoint returned 0 rows tagged with
      // identity_category='ai_agent' and didn't include agent_identity_type
      // at all — so the local filter on lines 67-69 caught 0 of 298 rows.
      fetch(withConnection('/api/agent-identities?per_page=500')).then(r => r.ok ? r.json() : null),
      fetch('/api/identities/category-summary').then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/attack-paths?limit=50')).then(r => r.ok ? r.json() : null),
    ]).then(([sum, agents, catSum, atk]) => {
      if (cancelled) return;
      setSummary(sum || null);
      // /api/agent-identities returns AI agents with full risk fields
      // (risk_level, governance_state, enabled). No client-side filtering needed.
      const list = Array.isArray(agents?.items) ? agents.items
                 : Array.isArray(agents?.identities) ? agents.identities
                 : [];
      setIdentities(list);
      setCategorySum(catSum || {});
      const paths = Array.isArray(atk?.paths) ? atk.paths : Array.isArray(atk?.attack_paths) ? atk.attack_paths : [];
      setAttackPaths(paths);
      setLoading(false);
    }).catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  const aiTotal = categorySum.ai_agent || identities.length || 0;
  const aiCat = useMemo(() => {
    // Estimate risk distribution from filtered AI identities
    return identities.reduce((acc, i) => {
      const r = String(i.risk_level || '').toLowerCase();
      if (r === 'critical') acc.critical++;
      else if (r === 'high') acc.high++;
      else if (r === 'medium') acc.medium++;
      else if (r === 'low') acc.low++;
      return acc;
    }, { total: aiTotal, critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  }, [identities, aiTotal]);

  // V2.8 (2026-06-11) — /api/agent-identities returns `enabled` (boolean)
  // not `status` (string). Use enabled || status fallback so the filter
  // works regardless of upstream shape changes.
  const active = identities.filter(i =>
    i.enabled === true || String(i.status || '').toLowerCase() === 'active'
  ).length;
  const highRisk = aiCat.critical + aiCat.high;
  const criticalViolations = identities.filter(i =>
    (i.governance_state === 'Policy Violation' || i.policy_violations > 0) &&
    (i.risk_level === 'critical' || i.risk_level === 'high')
  ).length;
  // Lock-V2 fix (2026-06-11) — no fabricated fallback (was inflating to 20%
  // of total). Real AI-sourced count only; BucketTabs hides chip below 1.
  const aiPaths = attackPaths.filter(p => {
    const t = String(p.source_entity_type || p.source_type || '').toLowerCase();
    const n = String(p.source_entity_name || '').toLowerCase();
    return t.includes('ai') || n.includes('ai') || n.includes('agent') || n.includes('copilot');
  }).length;

  const riskDist = deriveRiskDistribution(aiCat);
  // V2.4 (2026-06-11) — drop AI_RISK_REASONS hardcoded fallback. Previously
  // a fresh tenant with 0 AI identities painted "Unrestricted Tools 36%" etc.
  // which read as a data leak. Now: real reasons only; the panel shows
  // its empty state when there are no AI identities.
  const topReasons = deriveRiskReasons(identities, 5);

  // V2.11 (2026-06-12) — AI Types now derived from the canonical
  // detected_platform classifier field, not name-string matching or
  // residual subtraction. Previous version:
  //   "Copilots" = display_name.includes('copilot')   ← string match
  //   "MCP Clients" = display_name.includes('mcp')    ← string match
  //   "Custom AI Apps" = aiTotal − filter(ai_agent)   ← residual arithmetic
  // None of those touched the agent_classifications.detected_platform
  // column where the SSOT actually lives. On the pilot tenant the
  // residual math even attributed 77 of 77 agents to "Custom AI Apps"
  // (the founder's bug report). Now: groupBy detected_platform.
  const PLATFORM_LABELS: Record<string, { label: string; color: string }> = {
    azure_openai:    { label: 'Azure OpenAI',    color: '#60a5fa' },
    copilot_studio:  { label: 'Copilot Studio',  color: '#a78bfa' },
    azure_ai_studio: { label: 'Azure AI Studio', color: '#22d3ee' },
    azure_ml:        { label: 'Azure ML',        color: '#34d399' },
    anthropic:       { label: 'Anthropic',       color: '#fbbf24' },
    openai:          { label: 'OpenAI',          color: '#60a5fa' },
    langchain:       { label: 'LangChain',       color: '#a3e635' },
    power_automate:  { label: 'Power Automate',  color: '#f97316' },
    mcp_client:      { label: 'MCP Clients',     color: '#34d399' },
  };
  const typeEntries = (() => {
    const tally = new Map<string, number>();
    for (const i of identities) {
      const plat = String((i as any).detected_platform || '').toLowerCase();
      const key = plat in PLATFORM_LABELS ? plat : 'unknown';
      tally.set(key, (tally.get(key) || 0) + 1);
    }
    const entries = Array.from(tally.entries())
      .filter(([_, v]) => v > 0)
      .map(([k, v]) => k === 'unknown'
        ? { label: 'Unclassified', value: v, color: '#94a3b8' }
        : { label: PLATFORM_LABELS[k].label, value: v, color: PLATFORM_LABELS[k].color }
      )
      .sort((a, b) => b.value - a.value);
    return entries;
  })();

  const recentlyRisky: RecentlyRiskyRow[] = identities
    .filter(i => ['critical', 'high', 'medium'].includes(String(i.risk_level || '').toLowerCase()))
    .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
    .slice(0, 8)
    .map(i => {
      const name = String(i.display_name || '').toLowerCase();
      const type = name.includes('copilot') ? 'Copilot'
                 : name.includes('mcp') ? 'MCP Client'
                 : (i as any).agent_identity_type === 'ai_agent' ? 'AI Agent'
                 : 'Custom AI App';
      return {
        identity_id: i.identity_id,
        display_name: i.display_name,
        secondary: type,
        risk_level: i.risk_level,
        risk_reasons: Array.isArray(i.risk_reasons) ? i.risk_reasons.slice(0, 2).join(', ') : (i.risk_reasons || ''),
        last_seen: i.last_seen_auth || i.last_sign_in || null,
      };
    });

  // Lock-V2 revision (2026-06-11) — AI bucket now mirrors NHI per founder:
  // drop Privilege (AI agents don't do PIM), add Trust + Secrets. Same 9 tabs as NHI.
  const tabs = [
    { key: 'overview',     label: 'Overview' },
    { key: 'inventory',    label: 'Inventory', count: aiTotal },
    { key: 'access',       label: 'Access' },
    { key: 'trust',        label: 'Trust' },
    { key: 'lifecycle',    label: 'Lifecycle' },
    { key: 'governance',   label: 'Governance' },
    { key: 'ownership',    label: 'Ownership' },
    { key: 'secrets',      label: 'Secrets' },
    { key: 'attack-paths', label: 'Attack Paths', count: aiPaths },
  ];

  const { activeTab, tabStrip } = BucketTabs({ tabs, defaultTab: 'overview', accent: ACCENT });

  return (
    <BucketPageShell
      title="AI Identity"
      subtitle="Discover, monitor and secure AI agents, copilots and autonomous systems."
      icon={AI_ICON}
      accent={ACCENT}
    >
      {tabStrip}

      {activeTab === 'overview' && (
        <OverviewTab
          loading={loading}
          totalAi={aiTotal}
          active={active}
          highRisk={highRisk}
          criticalViolations={criticalViolations}
          attackPaths={aiPaths}
          riskDist={riskDist}
          topReasons={topReasons}
          totalReasons={Math.max(1, identities.length || 100)}
          recentlyRisky={recentlyRisky}
          typeEntries={typeEntries}
        />
      )}

      {activeTab === 'inventory'    && <TabFrame><AIInventory /></TabFrame>}
      {activeTab === 'access'       && <TabFrame><AIAccess /></TabFrame>}
      {activeTab === 'trust'        && <TabFrame><IdentityTrust forceType="ai" /></TabFrame>}
      {activeTab === 'lifecycle'    && <TabFrame><AILifecycle /></TabFrame>}
      {activeTab === 'governance'   && <TabFrame><AIGovernance /></TabFrame>}
      {activeTab === 'ownership'    && <TabFrame><OwnershipCenter forceScope="ai" /></TabFrame>}
      {activeTab === 'secrets'      && <TabFrame><NHISecrets /></TabFrame>}
      {activeTab === 'attack-paths' && <TabFrame><AttackPaths forceSourceType="ai" /></TabFrame>}
    </BucketPageShell>
  );
}

function OverviewTab({
  loading, totalAi, active, highRisk, criticalViolations, attackPaths,
  riskDist, topReasons, totalReasons, recentlyRisky, typeEntries,
}: any) {
  if (loading) {
    return <div className="flex items-center justify-center py-16"><div className="animate-spin h-8 w-8 border-2 border-violet-500 border-t-transparent rounded-full" /></div>;
  }
  return (
    <div className="space-y-4 mt-4">
      {/* V2.4 (2026-06-11) — deltaPct stripped pending real prior-period
          snapshot endpoint. KpiHeroCard shows "No prior-period baseline yet". */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
        <KpiHeroCard label="Total AI Identities" value={totalAi}
          icon={<AiBotIcon />} iconColor="#a78bfa" valueColor="#e2e8f0" />
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
        <RiskDistributionDonut entries={riskDist} total={riskDist.reduce((a: number, e: any) => a + e.value, 0)} />
        <TopRiskReasonsBar entries={topReasons} total={totalReasons} subtitle="Why AI identities are at risk" />
        <PanelCard title="AI Identity Types" subtitle="By type">
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

      <RecentlyRiskyTable rows={recentlyRisky} secondaryHeader="Type" lastHeader="Last Active" title="Recently Risky AI Identities" />
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

const AiBotIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>;
const CheckIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>;
const AlertIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>;
const ShieldIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 2L4 6v6c0 5.5 3.6 10.7 8 12 4.4-1.3 8-6.5 8-12V6l-8-4z"/></svg>;
const PathIcon = () => <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684z"/></svg>;
