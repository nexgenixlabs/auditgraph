import React, { useCallback, useEffect, useState } from 'react';
import { ReactFlow, Background, Controls, MiniMap, type Node, type Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { RISK_BADGE, safeLower } from '../../constants/metrics';

// ─── Props ────────────────────────────────────────────────────────

interface ExposureGraphProps {
  identityIds: string[];
  onNodeClick?: (identityId: string) => void;
}

type Preset = 'all' | 'privileged' | 'external' | 'non_human' | 'zombie' | 'secret_risk';

const PRESETS: { value: Preset; label: string }[] = [
  { value: 'all', label: 'Current Filter' },
  { value: 'privileged', label: 'Privileged Paths' },
  { value: 'external', label: 'External Access' },
  { value: 'non_human', label: 'Non-Human' },
  { value: 'zombie', label: 'Zombie Identities' },
  { value: 'secret_risk', label: 'Secret Risks' },
];

// ─── Custom node types ────────────────────────────────────────────

function IdentityNode({ data }: { data: Record<string, unknown> }) {
  const risk = safeLower(data.risk_level as string);
  const riskBadge = RISK_BADGE[risk] || 'bg-gray-100 text-gray-600';
  return (
    <div className="bg-white border-2 border-blue-300 rounded-lg px-3 py-2 shadow-sm min-w-[140px] max-w-[180px]">
      <div className="text-xs font-medium text-gray-900 truncate">{String(data.label)}</div>
      <div className="flex items-center gap-1 mt-1">
        <span className={`px-1 py-0.5 rounded text-[9px] font-semibold uppercase ${riskBadge}`}>{risk}</span>
        {!!data.risk_score && <span className="text-[9px] text-gray-400 font-mono">{String(data.risk_score)}</span>}
      </div>
    </div>
  );
}

function RoleNode({ data }: { data: Record<string, unknown> }) {
  const isEntra = String(data.role_type) === 'entra';
  return (
    <div className={`rounded-lg px-3 py-1.5 shadow-sm border ${isEntra ? 'bg-purple-50 border-purple-200' : 'bg-blue-50 border-blue-200'}`}>
      <div className={`text-[10px] font-semibold ${isEntra ? 'text-purple-700' : 'text-blue-700'}`}>{String(data.label)}</div>
      <div className="text-[9px] text-gray-400">{isEntra ? 'Entra' : 'RBAC'}</div>
    </div>
  );
}

function ScopeNode({ data }: { data: Record<string, unknown> }) {
  return (
    <div className="bg-gray-50 border border-gray-200 rounded-lg px-3 py-1.5 shadow-sm">
      <div className="text-[10px] font-medium text-gray-700">{String(data.label)}</div>
    </div>
  );
}

const nodeTypes = {
  identity: IdentityNode,
  role: RoleNode,
  scope: ScopeNode,
};

// ─── Component ────────────────────────────────────────────────────

export default function ExposureGraph({ identityIds, onNodeClick }: ExposureGraphProps) {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [loading, setLoading] = useState(false);
  const [preset, setPreset] = useState<Preset>('all');
  const [totalIdentities, setTotalIdentities] = useState(0);

  useEffect(() => {
    setLoading(true);
    const body: any = {};
    if (preset !== 'all') {
      body.preset = preset;
    } else {
      body.identity_ids = identityIds.slice(0, 50);
    }

    fetch('/api/identities/exposure-graph', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
      .then(r => r.ok ? r.json() : { nodes: [], edges: [] })
      .then(data => {
        setNodes(data.nodes || []);
        setEdges(data.edges || []);
        setTotalIdentities(data.total_identities || 0);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [identityIds, preset]);

  const handleNodeClick = useCallback((_: any, node: Node) => {
    if (node.type === 'identity' && !!node.data.identity_id && onNodeClick) {
      onNodeClick(String(node.data.identity_id));
    }
  }, [onNodeClick]);

  return (
    <div className="bg-white border rounded-xl overflow-hidden shadow-sm" style={{ height: '600px' }}>
      {/* Toolbar */}
      <div className="flex items-center gap-2 p-2 border-b bg-gray-50">
        <span className="text-[10px] text-gray-500 uppercase font-semibold">Preset:</span>
        {PRESETS.map(p => (
          <button
            key={p.value}
            onClick={() => setPreset(p.value)}
            className={`px-2.5 py-1 text-xs font-medium rounded-lg transition-colors ${
              preset === p.value
                ? 'bg-blue-600 text-white'
                : 'text-gray-600 bg-white border border-gray-200 hover:bg-gray-100'
            }`}
          >
            {p.label}
          </button>
        ))}
        <span className="ml-auto text-[10px] text-gray-400">
          {loading ? 'Loading…' : `${totalIdentities} identities, ${nodes.length} nodes`}
        </span>
      </div>

      {/* Graph */}
      {loading ? (
        <div className="flex items-center justify-center h-[540px] text-gray-400">
          <svg className="animate-spin w-5 h-5 mr-2" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Building exposure graph…
        </div>
      ) : nodes.length === 0 ? (
        <div className="flex items-center justify-center h-[540px] text-gray-400 text-sm">
          No identities match this preset.
        </div>
      ) : (
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodeClick={handleNodeClick}
          fitView
          minZoom={0.3}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
        >
          <Background gap={20} size={1} />
          <Controls showInteractive={false} />
          <MiniMap zoomable pannable />
        </ReactFlow>
      )}
    </div>
  );
}
