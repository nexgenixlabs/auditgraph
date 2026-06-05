/**
 * WhatIfSimulator (AG-190) — Argus Layer 6 UI.
 *
 * Lets the user pick an AI agent + one of its role assignments and
 * projects the CVSS-aligned score WITHOUT that role. The role is NOT
 * deleted — this is a read-only architectural projection.
 *
 * Endpoints:
 *   GET  /api/ai-agents/enriched     — agent picker
 *   GET  /api/ai-agents/<id>/permissions — role-assignment picker (with ra.id)
 *   POST /api/argus/what-if/role-removal — projection
 *
 * The backend carries `confidence='projected'` + a `warning` string —
 * we render both verbatim so the UI never claims a "measured" result.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { useConnection } from '../../contexts/ConnectionContext';

// ─── Backend contracts ─────────────────────────────────────────────────

interface AgentOption {
  identity_id: string;
  display_name: string;
}

interface RoleAssignmentOption {
  id: number;
  role_name: string;
  scope: string;
  scope_type?: string | null;
  resource_type?: string | null;
  resource_name?: string | null;
}

interface PermissionsResponse {
  identity_id: string;
  display_name: string;
  roles?: RoleAssignmentOption[] | null;
}

interface SignalRef {
  signal: string;
  weight?: number | null;
  title?: string | null;
}

interface RemovedPath {
  path_id?: number | null;
  path_type?: string | null;
  target_resource_type?: string | null;
  severity?: string | null;
  risk_score?: number | null;
  description?: string | null;
}

interface WhatIfResult {
  identity_id: string;
  display_name: string;
  role_assignment: {
    id: number;
    role_name: string;
    scope: string;
    scope_type?: string;
  };
  current_score: number;
  projected_score: number;
  reduction_pct: number;
  current_severity?: string;
  projected_severity?: string;
  removed_signals?: SignalRef[] | null;
  remaining_signals?: SignalRef[] | null;
  removed_paths?: RemovedPath[] | null;
  confidence?: string;
  warning?: string;
  generated_at?: string;
}

// ─── Helpers ───────────────────────────────────────────────────────────

function sevTone(sev: string | undefined | null) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return { fg: '#f87171', bg: 'rgba(239,68,68,0.10)', border: 'rgba(239,68,68,0.40)' };
  if (s === 'high')     return { fg: '#fb923c', bg: 'rgba(249,115,22,0.10)', border: 'rgba(249,115,22,0.40)' };
  if (s === 'medium')   return { fg: '#facc15', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.40)' };
  if (s === 'low')      return { fg: '#4ade80', bg: 'rgba(34,197,94,0.10)', border: 'rgba(34,197,94,0.40)' };
  return { fg: '#94a3b8', bg: 'rgba(148,163,184,0.10)', border: 'rgba(148,163,184,0.30)' };
}

// ─── Component ─────────────────────────────────────────────────────────

export default function WhatIfSimulator() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [agents, setAgents] = useState<AgentOption[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<string>('');

  const [roles, setRoles] = useState<RoleAssignmentOption[]>([]);
  const [rolesLoading, setRolesLoading] = useState(false);
  const [rolesError, setRolesError] = useState<string | null>(null);
  const [selectedRoleId, setSelectedRoleId] = useState<number | null>(null);

  const [result, setResult] = useState<WhatIfResult | null>(null);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);

  // 1) Agent list
  useEffect(() => {
    let cancelled = false;
    setAgentsLoading(true);
    fetch(withConnection('/api/ai-agents/enriched?per_page=200&include_possible=false'))
      .then(r => (r.ok ? r.json() : null))
      .then(data => {
        if (cancelled || !data) return;
        const list =
          (data?.identities as AgentOption[]) ||
          (data?.agents as AgentOption[]) ||
          (data?.items as AgentOption[]) ||
          [];
        setAgents(
          list
            .filter(a => a.identity_id && a.display_name)
            .sort((a, b) => a.display_name.localeCompare(b.display_name))
        );
      })
      .catch(() => { /* empty-state UX covers it */ })
      .finally(() => { if (!cancelled) setAgentsLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  // 2) Roles for selected agent
  useEffect(() => {
    setRoles([]);
    setSelectedRoleId(null);
    setRolesError(null);
    setResult(null);
    if (!selectedAgent) return;

    let cancelled = false;
    setRolesLoading(true);
    fetch(withConnection(`/api/ai-agents/${encodeURIComponent(selectedAgent)}/permissions`))
      .then(async r => {
        if (!r.ok) throw new Error(`Failed to load roles (${r.status})`);
        return r.json() as Promise<PermissionsResponse>;
      })
      .then(d => {
        if (cancelled) return;
        const list = (d.roles || []).filter(r => typeof r.id === 'number');
        setRoles(list);
      })
      .catch((e: Error) => { if (!cancelled) setRolesError(e.message); })
      .finally(() => { if (!cancelled) setRolesLoading(false); });
    return () => { cancelled = true; };
  }, [selectedAgent, withConnection]);

  // 3) Run projection
  const run = async () => {
    if (!selectedAgent || selectedRoleId === null) return;
    setRunning(true);
    setRunError(null);
    setResult(null);
    try {
      const r = await fetch(withConnection('/api/argus/what-if/role-removal'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity_id: selectedAgent,
          role_assignment_id: selectedRoleId,
        }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => null);
        throw new Error((body && body.error) || `Projection failed (${r.status})`);
      }
      const d = (await r.json()) as WhatIfResult;
      setResult(d);
    } catch (e) {
      setRunError(e instanceof Error ? e.message : 'Projection failed');
    } finally {
      setRunning(false);
    }
  };

  const selectedRole = useMemo(
    () => roles.find(r => r.id === selectedRoleId) || null,
    [roles, selectedRoleId],
  );

  return (
    <div className="space-y-4">
      {/* Picker */}
      <div className="rounded-xl border p-4 space-y-3"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <p className="text-[11px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
          Pick an AI agent and one of its role assignments. Argus projects the
          agent's risk score WITHOUT that role using the same scoring catalog
          the live engine uses. The role is <span className="font-semibold">not</span> deleted.
        </p>

        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[280px]">
            <label className="text-[10px] uppercase tracking-wider font-semibold block mb-1"
                   style={{ color: 'var(--text-tertiary)' }}>
              AI Agent
            </label>
            <select
              value={selectedAgent}
              onChange={e => setSelectedAgent(e.target.value)}
              className="text-xs px-2 py-1.5 rounded border min-w-[280px]"
              style={{
                borderColor: 'var(--border-default)',
                backgroundColor: 'var(--bg-raised)',
                color: 'var(--text-primary)',
              }}
              disabled={agentsLoading || agents.length === 0}
            >
              <option value="">
                {agentsLoading ? 'Loading agents…' : agents.length === 0 ? 'No AI agents' : 'Pick an agent…'}
              </option>
              {agents.map(a => (
                <option key={a.identity_id} value={a.identity_id}>
                  {a.display_name} — {a.identity_id.slice(0, 8)}…
                </option>
              ))}
            </select>
          </div>

          <div className="min-w-[300px] flex-1">
            <label className="text-[10px] uppercase tracking-wider font-semibold block mb-1"
                   style={{ color: 'var(--text-tertiary)' }}>
              Role assignment to remove
            </label>
            <select
              value={selectedRoleId ?? ''}
              onChange={e => setSelectedRoleId(e.target.value ? Number(e.target.value) : null)}
              className="w-full text-xs px-2 py-1.5 rounded border"
              style={{
                borderColor: 'var(--border-default)',
                backgroundColor: 'var(--bg-raised)',
                color: 'var(--text-primary)',
              }}
              disabled={!selectedAgent || rolesLoading || roles.length === 0}
            >
              <option value="">
                {!selectedAgent
                  ? 'Pick an agent first…'
                  : rolesLoading
                    ? 'Loading roles…'
                    : roles.length === 0
                      ? 'No role assignments'
                      : 'Pick a role…'}
              </option>
              {roles.map(r => (
                <option key={r.id} value={r.id}>
                  {r.role_name} on {r.scope_type || 'scope'} ({r.scope ? r.scope.slice(0, 60) : '—'})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={run}
            disabled={!selectedAgent || selectedRoleId === null || running}
            className="px-3 py-1.5 rounded text-xs font-semibold border transition disabled:opacity-50"
            style={{
              borderColor: 'rgba(139,92,246,0.40)',
              backgroundColor: 'rgba(139,92,246,0.18)',
              color: '#c4b5fd',
            }}
          >
            {running ? 'Projecting…' : 'Project removal'}
          </button>
        </div>

        {rolesError && (
          <p className="text-[11px] text-red-400">{rolesError}</p>
        )}
        {selectedRole && (
          <p className="text-[10px] font-mono truncate"
             style={{ color: 'var(--text-tertiary)' }}
             title={selectedRole.scope}>
            Target: {selectedRole.role_name} · {selectedRole.scope}
          </p>
        )}
      </div>

      {/* Error */}
      {runError && (
        <div className="rounded-lg border p-3 text-xs text-red-400"
             style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
          {runError}
        </div>
      )}

      {/* Projection result */}
      {result && (
        <ResultBlock result={result} />
      )}

      {/* Empty state */}
      {!result && !running && !runError && (
        <div className="rounded-xl border border-dashed p-6 text-center text-xs"
             style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-tertiary)' }}>
          Pick an agent and a role above to project what the agent's CVSS-aligned
          score would look like without that role.
        </div>
      )}
    </div>
  );
}

function ResultBlock({ result }: { result: WhatIfResult }) {
  const cur = sevTone(result.current_severity);
  const proj = sevTone(result.projected_severity);
  const delta = (result.current_score - result.projected_score) || 0;

  return (
    <div className="space-y-3 animate-[fadeIn_280ms_ease-out]">
      {/* Warning */}
      {result.warning && (
        <div className="rounded-lg border px-3 py-2 text-[11px]"
             style={{
               borderColor: 'rgba(250,204,21,0.30)',
               backgroundColor: 'rgba(250,204,21,0.08)',
               color: '#facc15',
             }}>
          <span className="font-semibold uppercase tracking-wider mr-1.5">
            {result.confidence || 'projected'}
          </span>
          {result.warning}
        </div>
      )}

      {/* Score delta */}
      <div className="rounded-xl border p-4 grid grid-cols-3 gap-4"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <ScoreBox
          label="Current score"
          score={result.current_score}
          severity={result.current_severity || '—'}
          tone={cur}
        />
        <DeltaBox delta={delta} reductionPct={result.reduction_pct} />
        <ScoreBox
          label="Projected score"
          score={result.projected_score}
          severity={result.projected_severity || '—'}
          tone={proj}
        />
      </div>

      {/* Role banner */}
      <div className="rounded-xl border p-3"
           style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
        <p className="text-[10px] uppercase tracking-wider font-semibold"
           style={{ color: 'var(--text-tertiary)' }}>
          Removed (architecturally)
        </p>
        <p className="text-xs font-semibold mt-0.5" style={{ color: 'var(--text-primary)' }}>
          {result.role_assignment.role_name}
        </p>
        <p className="text-[10px] font-mono truncate" style={{ color: 'var(--text-tertiary)' }}
           title={result.role_assignment.scope}>
          {result.role_assignment.scope || '—'}
        </p>
      </div>

      {/* Signal diff */}
      <div className="grid md:grid-cols-2 gap-3">
        <SignalList
          title="Signals that would no longer fire"
          tone="emerald"
          signals={result.removed_signals || []}
          emptyText="No signals would be cleared by removing this role."
        />
        <SignalList
          title="Signals that would remain"
          tone="amber"
          signals={result.remaining_signals || []}
          emptyText="No remaining signals — agent would be clean."
        />
      </div>

      {/* Removed attack paths */}
      {(result.removed_paths || []).length > 0 && (
        <div className="rounded-xl border p-4"
             style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
          <p className="text-[10px] uppercase tracking-wider font-semibold mb-2"
             style={{ color: 'var(--text-tertiary)' }}>
            Attack paths invalidated by removal ({(result.removed_paths || []).length})
          </p>
          <ul className="space-y-1.5">
            {(result.removed_paths || []).map((p, i) => {
              const t = sevTone(p.severity);
              return (
                <li key={`${p.path_id}-${i}`}
                    className="text-[11px] flex items-start gap-2">
                  <span className="inline-flex items-center px-1.5 py-0.5 rounded border font-bold uppercase tabular-nums"
                        style={{ color: t.fg, backgroundColor: t.bg, borderColor: t.border }}>
                    {p.severity || '—'}
                  </span>
                  <span className="font-mono tabular-nums"
                        style={{ color: 'var(--text-tertiary)' }}>
                    {typeof p.risk_score === 'number' ? p.risk_score.toFixed(1) : '—'}
                  </span>
                  <span className="min-w-0 flex-1"
                        style={{ color: 'var(--text-secondary)' }}>
                    {p.description || p.path_type || `path ${p.path_id ?? ''}`}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}

function ScoreBox({
  label, score, severity, tone,
}: { label: string; score: number; severity: string; tone: { fg: string; bg: string; border: string } }) {
  return (
    <div className="text-center">
      <p className="text-[10px] uppercase tracking-wider font-semibold mb-1"
         style={{ color: 'var(--text-tertiary)' }}>
        {label}
      </p>
      <p className="text-3xl font-bold tabular-nums" style={{ color: tone.fg }}>
        {score.toFixed(1)}
      </p>
      <span className="inline-block text-[10px] font-bold uppercase mt-1 px-2 py-0.5 rounded border"
            style={{ color: tone.fg, backgroundColor: tone.bg, borderColor: tone.border }}>
        {severity}
      </span>
    </div>
  );
}

function DeltaBox({ delta, reductionPct }: { delta: number; reductionPct: number }) {
  // Honest sign: positive delta = score went DOWN (improvement).
  const reduced = delta > 0;
  const fg = reduced ? '#4ade80' : delta < 0 ? '#f87171' : '#94a3b8';
  return (
    <div className="text-center flex flex-col items-center justify-center border-l border-r"
         style={{ borderColor: 'var(--border-subtle)' }}>
      <p className="text-[10px] uppercase tracking-wider font-semibold mb-1"
         style={{ color: 'var(--text-tertiary)' }}>
        Delta
      </p>
      <p className="text-2xl font-bold tabular-nums" style={{ color: fg }}>
        {delta >= 0 ? '−' : '+'}{Math.abs(delta).toFixed(1)}
      </p>
      <p className="text-[11px] tabular-nums mt-1" style={{ color: fg }}>
        {reductionPct.toFixed(1)}% reduction
      </p>
    </div>
  );
}

function SignalList({
  title, tone, signals, emptyText,
}: {
  title: string;
  tone: 'emerald' | 'amber';
  signals: SignalRef[];
  emptyText: string;
}) {
  const dot = tone === 'emerald' ? 'bg-emerald-400' : 'bg-amber-400';
  return (
    <div className="rounded-xl border p-3"
         style={{ borderColor: 'var(--border-subtle)', backgroundColor: 'var(--bg-surface)' }}>
      <p className="text-[10px] uppercase tracking-wider font-semibold mb-2"
         style={{ color: 'var(--text-tertiary)' }}>
        {title}
      </p>
      {signals.length === 0 ? (
        <p className="text-[11px] italic" style={{ color: 'var(--text-tertiary)' }}>
          {emptyText}
        </p>
      ) : (
        <ul className="space-y-1">
          {signals.map((s, i) => (
            <li key={`${s.signal}-${i}`}
                className="text-[11px] flex items-center gap-2">
              <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
              <span className="font-mono"
                    style={{ color: 'var(--text-secondary)' }}>
                {s.signal}
              </span>
              {typeof s.weight === 'number' && (
                <span className="ml-auto text-[10px] font-mono tabular-nums"
                      style={{ color: 'var(--text-tertiary)' }}>
                  weight {s.weight}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
