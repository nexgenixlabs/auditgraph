import React, { useMemo } from 'react';
import { ReactFlow, Controls, Background } from '@xyflow/react';
import '@xyflow/react/dist/style.css';

interface PathStep {
  node_type: string;
  node_id: string;
  node_label: string;
  description: string;
}

interface AttackPath {
  type: string;
  risk_level: string;
  steps: PathStep[];
  impact: string;
  narrative: string;
}

const NODE_STYLES: Record<string, { bg: string; border: string; text: string }> = {
  identity:  { bg: '#EFF6FF', border: '#3B82F6', text: '#1E40AF' },
  permission: { bg: '#FFF7ED', border: '#F97316', text: '#9A3412' },
  role:      { bg: '#FFF7ED', border: '#F97316', text: '#9A3412' },
  owned_spn: { bg: '#FFF7ED', border: '#F97316', text: '#9A3412' },
  pim:       { bg: '#FEF3C7', border: '#F59E0B', text: '#92400E' },
  target:    { bg: '#FEF2F2', border: '#EF4444', text: '#991B1B' },
};

const CLOUD_ICONS: Record<string, { label: string; bg: string; text: string }> = {
  azure: { label: 'AZ', bg: '#DBEAFE', text: '#1D4ED8' },
  aws:   { label: 'AWS', bg: '#FEF3C7', text: '#92400E' },
  gcp:   { label: 'GCP', bg: '#FEE2E2', text: '#991B1B' },
};

function AttackNode({ data }: { data: Record<string, unknown> }) {
  const nodeType = (data.nodeType as string) || 'identity';
  const style = NODE_STYLES[nodeType] || NODE_STYLES.identity;
  const isTarget = nodeType === 'target';
  const cloud = (data.cloud as string) || 'azure';
  const cloudIcon = CLOUD_ICONS[cloud] || CLOUD_ICONS.azure;

  return (
    <div
      className={`rounded-xl shadow-md border-2 px-4 py-3 min-w-[160px] max-w-[220px] ${isTarget ? 'animate-pulse' : ''}`}
      style={{ backgroundColor: style.bg, borderColor: style.border }}
    >
      <div className="flex items-center gap-1.5 mb-0.5">
        <span
          className="px-1 py-px rounded text-[8px] font-bold uppercase"
          style={{ backgroundColor: cloudIcon.bg, color: cloudIcon.text }}
        >
          {cloudIcon.label}
        </span>
        <span className="text-xs font-bold truncate flex-1" style={{ color: style.text }}>
          {data.label as string}
        </span>
      </div>
      <div className="text-[10px] text-gray-600 line-clamp-2">
        {data.description as string}
      </div>
    </div>
  );
}

const attackNodeTypes = { attack_node: AttackNode };

const RISK_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-green-100 text-green-700 border-green-200',
};

const TYPE_LABELS: Record<string, string> = {
  direct_escalation: 'Direct Escalation',
  ownership_chain: 'Ownership Chain',
  pim_abuse: 'PIM Abuse',
  lateral_movement: 'Lateral Movement',
  credential_exposure: 'Credential Exposure',
  CROSS_CLOUD_ESCALATION: 'Cross-Cloud Escalation',
  AWS_TRUST_ABUSE: 'AWS Trust Abuse',
  GCP_SA_IMPERSONATION: 'GCP SA Impersonation',
};

export default function AttackPathView({
  paths,
  summary,
}: {
  paths: AttackPath[];
  summary: { total_paths: number; critical_paths: number; max_blast_radius: string };
}) {
  const [selectedIdx, setSelectedIdx] = React.useState(0);
  const selectedPath = paths[selectedIdx] || null;

  const { nodes, edges } = useMemo(() => {
    if (!selectedPath) return { nodes: [], edges: [] };

    const spacing = 220;
    return {
      nodes: selectedPath.steps.map((step, i) => ({
        id: `step-${i}`,
        type: 'attack_node',
        position: { x: i * spacing, y: 80 },
        data: {
          label: step.node_label,
          description: step.description,
          nodeType: step.node_type,
          cloud: (step as any).cloud || 'azure',
        },
      })),
      edges: selectedPath.steps.slice(0, -1).map((_, i) => ({
        id: `edge-${i}`,
        source: `step-${i}`,
        target: `step-${i + 1}`,
        animated: true,
        style: {
          stroke: selectedPath.risk_level === 'critical' ? '#EF4444' : '#F97316',
          strokeWidth: 2,
        },
        markerEnd: { type: 'arrowclosed' as const, color: selectedPath.risk_level === 'critical' ? '#EF4444' : '#F97316' },
      })),
    };
  }, [selectedPath]);

  if (paths.length === 0) {
    return (
      <div className="bg-green-50 border border-green-200 rounded-xl p-6 text-center">
        <svg className="w-10 h-10 text-green-500 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <div className="text-sm font-semibold text-green-800">No Privilege Escalation Paths Detected</div>
        <div className="text-xs text-green-600 mt-1">This identity has a good security posture with no identified attack chains.</div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="flex items-center gap-4 px-4 py-3 rounded-lg bg-red-50 border border-red-200">
        <svg className="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div>
          <div className="text-xs font-bold text-red-800 uppercase">Attack Path Analysis</div>
          <div className="text-sm text-gray-700">
            {summary.total_paths} escalation paths found ({summary.critical_paths} critical)
          </div>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Path list sidebar */}
        <div className="col-span-4 space-y-1.5 max-h-[500px] overflow-y-auto pr-1">
          {paths.map((path, idx) => (
            <button
              key={idx}
              onClick={() => setSelectedIdx(idx)}
              className={`w-full text-left rounded-lg border px-3 py-2.5 transition ${
                idx === selectedIdx
                  ? 'border-indigo-300 bg-indigo-50 ring-1 ring-indigo-200'
                  : 'border-gray-200 bg-white hover:bg-gray-50'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-medium text-gray-500 uppercase">
                  {TYPE_LABELS[path.type] || path.type}
                </span>
                <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${RISK_BADGE[path.risk_level] || RISK_BADGE.medium}`}>
                  {path.risk_level}
                </span>
              </div>
              <div className="text-xs text-gray-800 line-clamp-2">{path.impact}</div>
            </button>
          ))}
        </div>

        {/* Graph area */}
        <div className="col-span-8">
          <div className="border rounded-xl overflow-hidden bg-gray-50" style={{ height: 250 }}>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={attackNodeTypes}
              fitView
              fitViewOptions={{ padding: 0.4 }}
              minZoom={0.5}
              maxZoom={1.5}
              proOptions={{ hideAttribution: true }}
            >
              <Controls position="bottom-right" showInteractive={false} />
              <Background gap={16} size={1} color="#e2e8f0" />
            </ReactFlow>
          </div>

          {/* Path narrative */}
          {selectedPath && (
            <div className="mt-3 bg-white border rounded-lg p-3">
              <div className="text-xs font-semibold text-gray-700 mb-1">Attack Narrative</div>
              <p className="text-xs text-gray-600">{selectedPath.narrative}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
