import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Identities from './Identities';
import AIAgents from './AIAgents';
import ServiceAccountGovernance from './ServiceAccountGovernance';
import IdentityGraph from './IdentityGraph';

// ── Tab definitions ─────────────────────────────────────────────────
// Order matters — rendered left to right, with "All Identities" at the end.

// 'graph' tab removed — Identity Graph now lives in sidebar (ACCESS
// EXPLAINABILITY group) to avoid duplicate nav entries. Visiting
// /identity-explorer/graph redirects to /identity-graph (handled in switchTab).
type TabKey = 'humans' | 'nhi' | 'ai-agents' | 'privileged' | 'graph' | 'all';

interface TabDef {
  key: TabKey;
  label: string;
  right?: boolean; // push to right side of bar
}

const TABS: TabDef[] = [
  { key: 'humans', label: 'Humans' },
  { key: 'nhi', label: 'Non-Human Identities' },
  { key: 'ai-agents', label: 'AI Agents' },
  { key: 'privileged', label: 'Privileged Access' },
  { key: 'all', label: 'All Identities', right: true },
];

// ── Theme constants (AuditGraph dark theme) ──────────────────────────
const TEAL = '#24A2A1';

// ── Tab → component mapping ──────────────────────────────────────────

const HumansTab: React.FC = () => <Identities tabScope="humans" />;
const NHITab: React.FC = () => <Identities tabScope="nhi" />;
const AllTab: React.FC = () => <Identities tabScope="all" />;

const TAB_COMPONENT: Record<TabKey, React.FC> = {
  humans: HumansTab,
  nhi: NHITab,
  'ai-agents': AIAgents,
  privileged: ServiceAccountGovernance,
  graph: IdentityGraph,
  all: AllTab,
};

// ── Main component ────────────────────────────────────────────────────

const IdentityExplorer: React.FC = () => {
  const { tab } = useParams<{ tab?: string }>();
  const navigate = useNavigate();
  // Legacy redirect: /identity-explorer/graph → /identity-graph
  React.useEffect(() => {
    if (tab === 'graph') navigate('/identity-graph', { replace: true });
  }, [tab, navigate]);
  const activeTab: TabKey = (tab as TabKey) || 'humans';
  const ActiveComponent = TAB_COMPONENT[activeTab] || TAB_COMPONENT.humans;

  const switchTab = (key: TabKey) => {
    navigate(`/identity-explorer/${key}`, { replace: true });
  };

  const leftTabs = TABS.filter(t => !t.right);
  const rightTabs = TABS.filter(t => t.right);

  return (
    <div className="space-y-4">
      <div className="flex items-center border-b border-slate-700/50 pb-0">
        <div className="flex gap-1.5">
          {leftTabs.map(t => (
            <button
              key={t.key}
              onClick={() => switchTab(t.key)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px ${
                activeTab === t.key
                  ? 'text-white'
                  : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-600'
              }`}
              style={activeTab === t.key ? { borderBottomColor: TEAL, color: TEAL } : undefined}
            >
              {t.label}
            </button>
          ))}
        </div>
        <div className="ml-auto flex gap-1.5">
          {rightTabs.map(t => (
            <button
              key={t.key}
              onClick={() => switchTab(t.key)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px ${
                activeTab === t.key
                  ? 'text-white'
                  : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-600'
              }`}
              style={activeTab === t.key ? { borderBottomColor: TEAL, color: TEAL } : undefined}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>
      <ActiveComponent />
    </div>
  );
};

export default IdentityExplorer;
