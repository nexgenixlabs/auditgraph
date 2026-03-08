import React, { useEffect, useState, useCallback, useRef } from 'react';

interface GraphNode {
  id: string;
  label: string;
  type: string;
  external_id?: string;
  risk_level?: string;
  metadata?: Record<string, unknown>;
}

interface GraphEdge {
  source: string;
  target: string;
  type: string;
}

interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  node_count: number;
  edge_count: number;
  truncated?: boolean;
}

const NODE_COLOR: Record<string, string> = {
  identity: '#60a5fa',
  service_principal: '#c084fc',
  managed_identity: '#22d3ee',
  role: '#fbbf24',
  resource: '#34d399',
  subscription: '#f87171',
};

const NODE_SIZE: Record<string, number> = {
  identity: 24,
  service_principal: 22,
  managed_identity: 20,
  role: 18,
  resource: 16,
  subscription: 28,
};

const EDGE_COLOR: Record<string, string> = {
  assigned_role: '#64748b',
  grants_access: '#22d3ee',
  contains_resource: '#6b7280',
  escalation_path: '#ef4444',
};

const IdentityGraph: React.FC = () => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [highlightedNode, setHighlightedNode] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'identity' | 'attack'>('identity');
  const [simulationId, setSimulationId] = useState('');
  const [connectionId, setConnectionId] = useState('');
  const [identityId, setIdentityId] = useState('');
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [dragging, setDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});

  const computeLayout = useCallback((data: GraphData) => {
    const positions: Record<string, { x: number; y: number }> = {};
    const width = 1200;
    const height = 800;
    const nodes = data.nodes;

    // Group by type
    const groups: Record<string, GraphNode[]> = {};
    for (const node of nodes) {
      const t = node.type || 'identity';
      if (!groups[t]) groups[t] = [];
      groups[t].push(node);
    }

    const typeOrder = ['subscription', 'identity', 'service_principal', 'managed_identity', 'role', 'resource'];
    let yOffset = 80;
    for (const type of typeOrder) {
      const group = groups[type] || [];
      const cols = Math.max(Math.ceil(Math.sqrt(group.length * 2)), 1);
      group.forEach((node, i) => {
        const col = i % cols;
        const row = Math.floor(i / cols);
        positions[node.id] = {
          x: 100 + col * (width / (cols + 1)),
          y: yOffset + row * 60,
        };
      });
      yOffset += Math.ceil(group.length / Math.max(Math.ceil(Math.sqrt(group.length * 2)), 1)) * 60 + 40;
    }

    setNodePositions(positions);
  }, []);

  const fetchIdentityGraph = async () => {
    if (!connectionId) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/graph/visualization?connection_id=${connectionId}`);
      if (res.ok) {
        const data = await res.json();
        setGraphData(data);
        computeLayout(data);
      }
    } catch (err) {
      console.error('Failed to fetch graph:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchNeighborhood = async () => {
    if (!identityId) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/graph/identity/${encodeURIComponent(identityId)}`);
      if (res.ok) {
        const data = await res.json();
        setGraphData(data);
        computeLayout(data);
      }
    } catch (err) {
      console.error('Failed to fetch neighborhood:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchAttackGraph = async () => {
    if (!simulationId) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/graph/attack-path/${simulationId}`);
      if (res.ok) {
        const data = await res.json();
        setGraphData(data);
        computeLayout(data);
      }
    } catch (err) {
      console.error('Failed to fetch attack graph:', err);
    } finally {
      setLoading(false);
    }
  };

  // Canvas rendering
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !graphData) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.offsetWidth * dpr;
    canvas.height = canvas.offsetHeight * dpr;
    ctx.scale(dpr, dpr);

    ctx.clearRect(0, 0, canvas.offsetWidth, canvas.offsetHeight);
    ctx.save();
    ctx.translate(pan.x, pan.y);
    ctx.scale(zoom, zoom);

    // Draw edges
    for (const edge of graphData.edges) {
      const src = nodePositions[edge.source];
      const tgt = nodePositions[edge.target];
      if (!src || !tgt) continue;

      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.strokeStyle = EDGE_COLOR[edge.type] || '#475569';
      ctx.lineWidth = edge.type === 'escalation_path' ? 2 : 1;
      ctx.globalAlpha = highlightedNode
        ? (edge.source === highlightedNode || edge.target === highlightedNode ? 1 : 0.15)
        : 0.5;
      ctx.stroke();
    }

    ctx.globalAlpha = 1;

    // Draw nodes
    for (const node of graphData.nodes) {
      const pos = nodePositions[node.id];
      if (!pos) continue;

      const size = NODE_SIZE[node.type] || 16;
      const color = NODE_COLOR[node.type] || '#94a3b8';
      const isHighlighted = highlightedNode === node.id;
      const isSearchMatch = searchTerm && node.label.toLowerCase().includes(searchTerm.toLowerCase());

      ctx.globalAlpha = highlightedNode ? (isHighlighted ? 1 : 0.3) : 1;

      // Node circle
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, size / 2, 0, Math.PI * 2);
      ctx.fillStyle = isSearchMatch ? '#f59e0b' : color;
      ctx.fill();
      if (isHighlighted || isSearchMatch) {
        ctx.lineWidth = 2;
        ctx.strokeStyle = '#ffffff';
        ctx.stroke();
      }

      // Label
      ctx.fillStyle = '#e2e8f0';
      ctx.font = '10px sans-serif';
      ctx.textAlign = 'center';
      const label = node.label.length > 20 ? node.label.slice(0, 18) + '...' : node.label;
      ctx.fillText(label, pos.x, pos.y + size / 2 + 12);
    }

    ctx.restore();
  }, [graphData, nodePositions, pan, zoom, highlightedNode, searchTerm]);

  // Mouse handlers for pan
  const handleMouseDown = (e: React.MouseEvent) => {
    setDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!dragging) return;
    setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
  };

  const handleMouseUp = () => setDragging(false);

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom(z => Math.max(0.1, Math.min(5, z * delta)));
  };

  // Click to highlight node
  const handleCanvasClick = (e: React.MouseEvent) => {
    if (!graphData || !canvasRef.current) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const mx = (e.clientX - rect.left - pan.x) / zoom;
    const my = (e.clientY - rect.top - pan.y) / zoom;

    for (const node of graphData.nodes) {
      const pos = nodePositions[node.id];
      if (!pos) continue;
      const size = NODE_SIZE[node.type] || 16;
      const dx = mx - pos.x;
      const dy = my - pos.y;
      if (dx * dx + dy * dy < (size / 2) * (size / 2) * 4) {
        setHighlightedNode(prev => prev === node.id ? null : node.id);
        return;
      }
    }
    setHighlightedNode(null);
  };

  const filteredNodes = graphData?.nodes.filter(n =>
    searchTerm ? n.label.toLowerCase().includes(searchTerm.toLowerCase()) : true
  ) || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Identity Graph</h1>
          <p className="text-sm text-slate-400 mt-1">Interactive visualization of IAM relationships and attack paths</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setViewMode('identity')}
            className={`px-3 py-1.5 text-sm rounded ${viewMode === 'identity' ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-800 text-slate-400'}`}
          >
            Identity Graph
          </button>
          <button
            onClick={() => setViewMode('attack')}
            className={`px-3 py-1.5 text-sm rounded ${viewMode === 'attack' ? 'bg-red-500/20 text-red-400' : 'bg-slate-800 text-slate-400'}`}
          >
            Attack Paths
          </button>
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-4 bg-slate-800/50 border border-slate-700/50 rounded-lg p-3">
        {viewMode === 'identity' ? (
          <>
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-400">Connection ID:</label>
              <input
                type="text"
                value={connectionId}
                onChange={e => setConnectionId(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-white w-24"
                placeholder="1"
              />
              <button
                onClick={fetchIdentityGraph}
                disabled={loading || !connectionId}
                className="px-3 py-1 text-xs bg-blue-500/20 text-blue-400 rounded hover:bg-blue-500/30 disabled:opacity-50"
              >
                Load Graph
              </button>
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-400">Identity ID:</label>
              <input
                type="text"
                value={identityId}
                onChange={e => setIdentityId(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-white w-48"
                placeholder="identity-uuid"
              />
              <button
                onClick={fetchNeighborhood}
                disabled={loading || !identityId}
                className="px-3 py-1 text-xs bg-cyan-500/20 text-cyan-400 rounded hover:bg-cyan-500/30 disabled:opacity-50"
              >
                Neighborhood
              </button>
            </div>
          </>
        ) : (
          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-400">Simulation ID:</label>
            <input
              type="text"
              value={simulationId}
              onChange={e => setSimulationId(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-white w-64"
              placeholder="simulation-uuid"
            />
            <button
              onClick={fetchAttackGraph}
              disabled={loading || !simulationId}
              className="px-3 py-1 text-xs bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 disabled:opacity-50"
            >
              Load Attack Graph
            </button>
          </div>
        )}

        <div className="ml-auto flex items-center gap-2">
          <input
            type="text"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-white w-48"
            placeholder="Search nodes..."
          />
          <button
            onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}
            className="px-2 py-1 text-xs bg-slate-700 text-slate-300 rounded hover:bg-slate-600"
          >
            Reset View
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-slate-400">
        {Object.entries(NODE_COLOR).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1">
            <span className="w-3 h-3 rounded-full inline-block" style={{ backgroundColor: color }} />
            <span>{type.replace(/_/g, ' ')}</span>
          </div>
        ))}
        <span className="text-slate-600">|</span>
        {Object.entries(EDGE_COLOR).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1">
            <span className="w-4 h-0.5 inline-block" style={{ backgroundColor: color }} />
            <span>{type.replace(/_/g, ' ')}</span>
          </div>
        ))}
      </div>

      {/* Graph Canvas */}
      <div className="bg-slate-900/50 border border-slate-700/50 rounded-lg overflow-hidden" style={{ height: '600px' }}>
        {loading ? (
          <div className="flex items-center justify-center h-full text-slate-400">Loading graph...</div>
        ) : !graphData ? (
          <div className="flex items-center justify-center h-full text-slate-400">
            Select a connection or simulation to visualize
          </div>
        ) : graphData.nodes.length === 0 ? (
          <div className="flex items-center justify-center h-full text-slate-400">No graph data available</div>
        ) : (
          <canvas
            ref={canvasRef}
            className="w-full h-full cursor-grab active:cursor-grabbing"
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            onWheel={handleWheel}
            onClick={handleCanvasClick}
          />
        )}
      </div>

      {/* Stats bar */}
      {!!graphData && (
        <div className="flex items-center gap-6 text-xs text-slate-400">
          <span>Nodes: {graphData.node_count}</span>
          <span>Edges: {graphData.edge_count}</span>
          {!!graphData.truncated && (
            <span className="text-amber-400">Graph truncated to 2000 nodes</span>
          )}
          {searchTerm && (
            <span>Search matches: {filteredNodes.length}</span>
          )}
          <span>Zoom: {Math.round(zoom * 100)}%</span>
        </div>
      )}

      {/* Node list for search results */}
      {searchTerm && filteredNodes.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50 max-h-48 overflow-y-auto">
          {filteredNodes.slice(0, 20).map(node => (
            <div
              key={node.id}
              className="px-4 py-2 flex items-center justify-between cursor-pointer hover:bg-slate-700/30"
              onClick={() => setHighlightedNode(node.id)}
            >
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: NODE_COLOR[node.type] || '#94a3b8' }} />
                <span className="text-sm text-white">{node.label}</span>
              </div>
              <span className="text-xs text-slate-500">{node.type.replace(/_/g, ' ')}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default IdentityGraph;
