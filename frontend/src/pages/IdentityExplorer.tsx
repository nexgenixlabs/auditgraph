import React from 'react';
import { useSearchParams } from 'react-router-dom';
import Identities from './Identities';
import AIAgents from './AIAgents';
import ServiceAccountGovernance from './ServiceAccountGovernance';
import IdentityGraph from './IdentityGraph';

const TABS = [
  { key: 'all', label: 'All Identities' },
  { key: 'ai', label: 'AI / Non-Human' },
  { key: 'privileged', label: 'Privileged Access' },
  { key: 'graph', label: 'Identity Graph' },
] as const;

type TabKey = (typeof TABS)[number]['key'];

const TAB_COMPONENT: Record<TabKey, React.FC> = {
  all: Identities,
  ai: AIAgents,
  privileged: ServiceAccountGovernance,
  graph: IdentityGraph,
};

const IdentityExplorer: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = (searchParams.get('tab') as TabKey) || 'all';
  const ActiveComponent = TAB_COMPONENT[activeTab] || Identities;

  const switchTab = (key: TabKey) => {
    setSearchParams({ tab: key }, { replace: true });
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-1.5 border-b border-slate-700/50 pb-0">
        {TABS.map(tab => (
          <button
            key={tab.key}
            onClick={() => switchTab(tab.key)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px ${
              activeTab === tab.key
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-600'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <ActiveComponent />
    </div>
  );
};

export default IdentityExplorer;
