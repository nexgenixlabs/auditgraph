import React, { useState, useEffect } from 'react';
import {
  type RemediationData,
  type RemediationActionsMap,
  type RemediationStatus,
  type RemediationAction,
  type RemediationItem,
  type IdentityDetailsResponse,
  type CvssFix,
  type CvssFixResponse,
  DataSource,
} from './types';

// ─── Props ──────────────────────────────────────────────────────────

interface RemediationTabProps {
  remediationData: RemediationData | null;
  remediationLoading: boolean;
  remediationActions: RemediationActionsMap;
  actionLoading: number | null;
  executeLoading: number | null;
  handleRemediationAction: (playbookId: number, status: RemediationStatus, notes?: string) => void;
  handleRemediationExecute: (playbookId: number, actionType: string) => void;
  data: IdentityDetailsResponse;
}

// ─── Constants ──────────────────────────────────────────────────────

// Sprint A.4 — heuristic risk-reduction estimator. The structured CVSS-fix
// percentages live on /api/identities/<id>/fixes (CvssFix.risk_reduction_pct)
// and can supersede this table later; meanwhile this gives the executive a
// defensible per-action "what does this buy me" without claiming false precision.
const RISK_REDUCTION_TABLE: Record<string, Record<string, number>> = {
  critical: { low: 25, medium: 22, high: 18 },
  high:     { low: 15, medium: 12, high: 10 },
  medium:   { low: 8,  medium: 6,  high: 4 },
  low:      { low: 3,  medium: 2,  high: 1 },
};

function estimateRiskReduction(impact?: string, effort?: string): number {
  const i = String(impact || 'medium').toLowerCase();
  const e = String(effort || 'medium').toLowerCase();
  const row = RISK_REDUCTION_TABLE[i] || RISK_REDUCTION_TABLE.medium;
  return row[e] ?? 5;
}

const STATUS_COLORS: Record<RemediationStatus, string> = {
  open: 'bg-gray-100 text-gray-600',
  acknowledged: 'bg-blue-100 text-blue-700',
  completed: 'bg-green-100 text-green-700',
  skipped: 'bg-yellow-100 text-yellow-700',
};

const STATUS_LABELS: Record<RemediationStatus, string> = {
  open: 'Open',
  acknowledged: 'Acknowledged',
  completed: 'Completed',
  skipped: 'Skipped',
};

// ─── CvssFixRecommendations (internal) ──────────────────────────────

function CvssFixRecommendations({ identityId }: { identityId: string }) {
  const [data, setData] = useState<CvssFixResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetch(`/api/identities/${encodeURIComponent(identityId)}/fixes`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (!cancelled) setData(d); })
      .catch(() => { if (!cancelled) setData(null); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [identityId]);

  if (loading) {
    return (
      <div className="animate-pulse space-y-3 mb-6">
        {[1, 2, 3].map(i => <div key={i} className="h-24 bg-gray-100 rounded-xl" />)}
      </div>
    );
  }

  if (!data || !data.fixes || data.fixes.length === 0) return null;

  const projected = data.projected_impact?.after_all_fixes;

  return (
    <div className="mb-8">
      <div className="text-xs text-gray-400 uppercase tracking-wider font-semibold mb-3">CVSS-Aligned Recommendations</div>
      <div className="space-y-3">
        {data.fixes.map((fix: CvssFix, idx: number) => (
          <div key={fix.fix_type} className="border rounded-xl p-4 bg-white hover:shadow-md transition">
            <div className="flex items-start justify-between gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                  <span className="text-xs font-bold text-gray-400">#{idx + 1}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase text-white" style={{ backgroundColor: '#24A2A1' }}>
                    {fix.verb}
                  </span>
                  <span className="text-sm font-semibold text-gray-900">{fix.title}</span>
                </div>
                <p className="text-xs text-gray-600 mb-2">{fix.description}</p>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-green-100 text-green-700">
                    -{fix.risk_reduction_pct}% risk
                  </span>
                  <span className="text-[10px] text-gray-500">
                    {fix.current_score.toFixed(1)} → {fix.simulated_score.toFixed(1)} ({fix.simulated_band})
                  </span>
                  <span className="text-[10px] text-gray-400">·</span>
                  <span className="text-[10px] text-gray-500">{fix.effort_minutes} min effort</span>
                  <span className="text-[10px] text-gray-400">·</span>
                  <span
                    className="px-1.5 py-0.5 rounded text-[10px] font-semibold text-white"
                    style={{ backgroundColor: fix.safety_color || '#6b7280' }}
                  >
                    {fix.execution_safety}
                  </span>
                  {fix.safety_reason && (
                    <span className="text-[10px] text-gray-400 italic">{fix.safety_reason}</span>
                  )}
                </div>
                {fix.framework_badges.length > 0 && (
                  <div className="flex gap-1.5 mt-2 flex-wrap">
                    {fix.framework_badges.map(badge => (
                      <span key={badge} className="px-2 py-0.5 rounded-full text-[10px] font-medium text-white" style={{ backgroundColor: '#15306A' }}>
                        {badge}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              <button
                disabled
                className="px-3 py-1.5 rounded-lg text-[10px] font-medium bg-gray-100 text-gray-400 cursor-not-allowed whitespace-nowrap"
                title="Coming soon"
              >
                + Add to Queue
              </button>
            </div>
          </div>
        ))}
      </div>

      {projected && (
        <div className="mt-4 bg-gray-50 rounded-xl p-4 border">
          <div className="text-xs font-semibold text-gray-700 mb-2">Projected Impact (all fixes applied)</div>
          <div className="grid grid-cols-4 gap-3">
            <div className="text-center">
              <div className="text-lg font-bold text-green-700">-{projected.risk_reduction_pct}%</div>
              <div className="text-[10px] text-gray-500">Total Reduction</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-gray-900">{projected.simulated_score.toFixed(1)}</div>
              <div className="text-[10px] text-gray-500">Projected Score</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-gray-900">{projected.simulated_band}</div>
              <div className="text-[10px] text-gray-500">Projected Band</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-blue-700">+{projected.posture_score_delta.toFixed(1)}</div>
              <div className="text-[10px] text-gray-500">Posture Improvement</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── RemediationCard (internal) ─────────────────────────────────────

function RemediationCard({
  remediation,
  index,
  action,
  onAction,
  onExecute,
  loading,
  executing,
}: {
  remediation: RemediationItem;
  index: number;
  action?: RemediationAction;
  onAction: (status: RemediationStatus, notes?: string) => void;
  onExecute: (actionType: string) => void;
  loading: boolean;
  executing: boolean;
}) {
  const [expanded, setExpanded] = useState(false);

  const currentStatus: RemediationStatus = action?.status || 'open';

  const impactColors: Record<string, string> = {
    critical: 'bg-red-100 text-red-700',
    high: 'bg-orange-100 text-orange-700',
    medium: 'bg-yellow-100 text-yellow-700',
    low: 'bg-green-100 text-green-700',
  };

  const effortColors: Record<string, string> = {
    low: 'bg-green-100 text-green-700',
    medium: 'bg-yellow-100 text-yellow-700',
    high: 'bg-red-100 text-red-700',
  };

  // Sprint A.4 — estimated risk reduction surfaced per row.
  //
  // RemediationItem doesn't carry a `risk_reduction` field (the structured value
  // lives on the parallel /fixes endpoint via CvssFix.risk_reduction_pct). For
  // the per-row hint, we derive a defensible estimate from impact x effort —
  // the relationship the scoring engine uses internally anyway: high-impact
  // / low-effort actions remove proportionally more CVSS than low-impact /
  // high-effort cleanup. Shown as "Est. -X%" so executives don't read it as
  // an exact promise; honest framing.
  const riskReductionPct = estimateRiskReduction(remediation.impact, remediation.effort);
  const reductionColor =
    riskReductionPct >= 18 ? '#ef4444' :
    riskReductionPct >= 10 ? '#f97316' :
    riskReductionPct >= 5  ? '#f59e0b' : '#10b981';

  const categoryLabels: Record<string, string> = {
    access_control: 'Access Control',
    credential_hygiene: 'Credential Hygiene',
    governance: 'Governance',
    monitoring: 'Monitoring',
  };

  // Contextual action buttons based on current status
  const availableActions: { status: RemediationStatus; label: string; color: string }[] = [];
  if (currentStatus === 'open') {
    availableActions.push(
      { status: 'acknowledged', label: 'Acknowledge', color: 'bg-blue-600 hover:bg-blue-700 text-white' },
      { status: 'completed', label: 'Mark Complete', color: 'bg-green-600 hover:bg-green-700 text-white' },
      { status: 'skipped', label: 'Skip', color: 'bg-gray-200 hover:bg-gray-300 text-gray-700' },
    );
  } else if (currentStatus === 'acknowledged') {
    availableActions.push(
      { status: 'completed', label: 'Mark Complete', color: 'bg-green-600 hover:bg-green-700 text-white' },
      { status: 'skipped', label: 'Skip', color: 'bg-gray-200 hover:bg-gray-300 text-gray-700' },
      { status: 'open', label: 'Reopen', color: 'bg-gray-200 hover:bg-gray-300 text-gray-700' },
    );
  } else if (currentStatus === 'completed') {
    availableActions.push(
      { status: 'open', label: 'Reopen', color: 'bg-gray-200 hover:bg-gray-300 text-gray-700' },
    );
  } else if (currentStatus === 'skipped') {
    availableActions.push(
      { status: 'open', label: 'Reopen', color: 'bg-gray-200 hover:bg-gray-300 text-gray-700' },
    );
  }

  return (
    <div className={`border rounded-xl overflow-hidden hover:shadow-md transition ${currentStatus === 'completed' ? 'opacity-60' : ''}`}>
      {/* Header — always visible */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left bg-white px-5 py-4 flex items-start justify-between gap-4"
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-bold text-gray-400">P{index + 1}</span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${impactColors[remediation.impact] || 'bg-gray-100 text-gray-600'}`}>
              {remediation.impact}
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${effortColors[remediation.effort] || 'bg-gray-100 text-gray-600'}`}>
              {remediation.effort} effort
            </span>
            {/* Sprint A.4 — per-row risk reduction. "Est." prefix flags it as
                derived, not a promise. Real CVSS deltas live on /fixes. */}
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold"
              style={{ background: `${reductionColor}15`, color: reductionColor, border: `1px solid ${reductionColor}55` }}
              title={`Estimated CVSS reduction based on impact × effort. Run the What-If simulator for an exact delta.`}>
              <span aria-hidden>▼</span>
              <span>Est. −{riskReductionPct}% risk</span>
            </span>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-50 text-blue-700">
              {categoryLabels[remediation.category] || remediation.category}
            </span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${STATUS_COLORS[currentStatus]}`}>
              {STATUS_LABELS[currentStatus]}
            </span>
          </div>
          <div className="font-semibold text-sm text-gray-900">{remediation.title}</div>
          <div className="text-xs text-gray-500 mt-1 line-clamp-1">{remediation.description}</div>
        </div>
        <svg className={`w-5 h-5 text-gray-400 flex-shrink-0 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Expandable content */}
      {expanded && (
        <div className="border-t bg-gray-50 px-5 py-4 space-y-4">
          <div className="text-xs text-gray-700">{remediation.description}</div>

          {/* Step-by-step instructions */}
          <div>
            <div className="text-xs font-semibold text-gray-700 mb-2">Step-by-Step Remediation</div>
            <ol className="space-y-2">
              {remediation.steps.map((step, sIdx) => (
                <li key={sIdx} className="flex gap-3 text-xs text-gray-700">
                  <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center font-bold text-[10px]">
                    {sIdx + 1}
                  </span>
                  <span className="pt-0.5">{step}</span>
                </li>
              ))}
            </ol>
          </div>

          {/* Compliance references */}
          {remediation.compliance_refs.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-gray-700 mb-1.5">Compliance References</div>
              <div className="flex flex-wrap gap-1.5">
                {remediation.compliance_refs.map((ref, rIdx) => (
                  <span key={rIdx} className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-purple-50 text-purple-700 border border-purple-200">
                    {ref}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Execution result */}
          {action?.execution_status && (
            <div className={`border rounded-lg p-3 ${
              action.execution_status === 'success' ? 'bg-green-50 border-green-200' :
              action.execution_status === 'simulated' ? 'bg-amber-50 border-amber-200' :
              'bg-red-50 border-red-200'
            }`}>
              <div className="flex items-center gap-2">
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                  action.execution_status === 'success' ? 'bg-green-200 text-green-800' :
                  action.execution_status === 'simulated' ? 'bg-amber-200 text-amber-800' :
                  'bg-red-200 text-red-800'
                }`}>
                  {action.execution_status}
                </span>
                {action.execution_log?.action_type && (
                  <span className="text-[10px] text-gray-500">{action.execution_log.action_type.replace(/_/g, ' ')}</span>
                )}
                {action.executed_at && (
                  <span className="text-[10px] text-gray-400 ml-auto">
                    {new Date(action.executed_at).toLocaleString()}
                  </span>
                )}
              </div>
              {action.execution_log?.detail && (
                <p className="text-xs text-gray-600 mt-1">{action.execution_log.detail}</p>
              )}
            </div>
          )}

          {/* Action buttons */}
          <div className="border-t pt-3">
            <div className="flex items-center gap-2 flex-wrap">
              {availableActions.map(btn => (
                <button
                  key={btn.status}
                  onClick={(e) => { e.stopPropagation(); onAction(btn.status); }}
                  disabled={loading}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${btn.color} disabled:opacity-50`}
                >
                  {loading ? 'Updating...' : btn.label}
                </button>
              ))}

              {/* Execute dropdown */}
              {currentStatus !== 'completed' && currentStatus !== 'skipped' && !action?.execution_status && (
                <>
                  <span className="text-gray-300 mx-1">|</span>
                  <button
                    onClick={(e) => { e.stopPropagation(); onExecute('flag_for_review'); }}
                    disabled={executing}
                    className="px-3 py-1.5 rounded-lg text-xs font-medium transition bg-purple-600 hover:bg-purple-700 text-white disabled:opacity-50"
                  >
                    {executing ? 'Executing...' : 'Flag for Review'}
                  </button>
                  {(remediation.category === 'governance') && (
                    <button
                      onClick={(e) => { e.stopPropagation(); if (window.confirm('This will simulate disabling the identity. Continue?')) onExecute('disable_identity'); }}
                      disabled={executing}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition bg-red-600 hover:bg-red-700 text-white disabled:opacity-50"
                    >
                      {executing ? 'Executing...' : 'Disable Identity'}
                    </button>
                  )}
                  {(remediation.category === 'credential_hygiene') && (
                    <button
                      onClick={(e) => { e.stopPropagation(); if (window.confirm('This will simulate credential rotation. Continue?')) onExecute('rotate_credential'); }}
                      disabled={executing}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition bg-orange-600 hover:bg-orange-700 text-white disabled:opacity-50"
                    >
                      {executing ? 'Executing...' : 'Rotate Credential'}
                    </button>
                  )}
                  {(remediation.category === 'access_control') && (
                    <button
                      onClick={(e) => { e.stopPropagation(); if (window.confirm('This will simulate role removal. Continue?')) onExecute('remove_role'); }}
                      disabled={executing}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition bg-red-600 hover:bg-red-700 text-white disabled:opacity-50"
                    >
                      {executing ? 'Executing...' : 'Remove Role'}
                    </button>
                  )}
                </>
              )}

              {action?.updated_at && (
                <span className="text-[10px] text-gray-400 ml-auto">
                  Updated {new Date(action.updated_at).toLocaleString()}
                </span>
              )}
            </div>
            {action?.notes && (
              <div className="mt-2 text-[10px] text-gray-500 bg-white rounded p-2 border">
                {action.notes}
              </div>
            )}
          </div>

          {/* Matched reason */}
          <div className="text-[10px] text-gray-400 italic">
            Matched: {remediation.matched_reason}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── RemediationTab ─────────────────────────────────────────────────

export function RemediationTab({
  remediationData,
  remediationLoading,
  remediationActions,
  actionLoading,
  executeLoading,
  handleRemediationAction,
  handleRemediationExecute,
  data,
}: RemediationTabProps) {
  const identityId = data?.identity?.identity_id;

  return (
    <div className="space-y-6">
      {identityId && <CvssFixRecommendations identityId={identityId} />}
      {remediationLoading ? (
        <div className="animate-pulse space-y-4">
          {[1, 2, 3].map(i => <div key={i} className="h-32 bg-gray-100 rounded-xl" />)}
        </div>
      ) : !remediationData || remediationData.remediations.length === 0 ? (
        (() => {
          const govActions = (
            (data as any)?.remediation_actions ??
            (data as any)?.governance_remediation_actions ??
            (data as any)?.identity?.remediation_actions
          ) as Array<{
            priority: string; impact: string; action: string; reason: string; framework: string | null; effort: string | null;
          }> | undefined;
          const hasGovActions = govActions && govActions.length > 0 && govActions[0].priority !== 'P2';
          if (!hasGovActions) {
            const gov = (data as any)?.identity?.governance_state;
            const priv = (data as any)?.identity?.privilege_level;
            if (gov && gov !== 'Governed') {
              console.warn('RemediationTab: no actions for identity', (data as any)?.identity?.identity_id, { governance: gov, privilege: priv });
            }
          }

          if (!hasGovActions) {
            return (
              <div className="text-center py-12">
                <svg className="w-12 h-12 text-green-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div className="text-sm font-medium text-gray-600">No remediations needed</div>
                <div className="text-xs text-gray-400 mt-1">This identity meets current governance requirements.</div>
              </div>
            );
          }

          const priorityColor: Record<string, string> = {
            P0: 'bg-red-100 text-red-700 border-red-200',
            P1: 'bg-orange-100 text-orange-700 border-orange-200',
            P2: 'bg-blue-100 text-blue-700 border-blue-200',
          };
          const impactColor: Record<string, string> = {
            Critical: 'text-red-700',
            High: 'text-orange-700',
            Medium: 'text-yellow-700',
            Low: 'text-gray-500',
          };

          return (
            <div className="space-y-4">
              <div className="text-xs text-gray-400 uppercase tracking-wider font-semibold">Governance-Derived Actions</div>
              {govActions!.map((a, idx) => (
                <div key={idx} className="border rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${priorityColor[a.priority] || 'bg-gray-100 text-gray-600'}`}>{a.priority}</span>
                    <span className={`text-sm font-semibold ${impactColor[a.impact] || 'text-gray-700'}`}>{a.action}</span>
                  </div>
                  <div className="text-xs text-gray-600 mb-2">{a.reason}</div>
                  <div className="flex items-center gap-3 text-[10px] text-gray-400">
                    {a.framework && <span>Framework: {a.framework}</span>}
                    {a.effort && <span>Effort: {a.effort}</span>}
                  </div>
                </div>
              ))}
            </div>
          );
        })()
      ) : (
        <>
          {/* Summary bar */}
          <div className="grid grid-cols-5 gap-4">
            <div className="bg-gray-50 rounded-xl p-4 text-center">
              <div className="text-2xl font-bold text-gray-900">{remediationData.summary.total}</div>
              <div className="text-xs text-gray-500 mt-1">Total Actions</div>
            </div>
            <div className="bg-red-50 rounded-xl p-4 text-center">
              <div className="text-2xl font-bold text-red-700">{remediationData.summary.critical_actions}</div>
              <div className="text-xs text-red-600 mt-1">Critical</div>
            </div>
            <div className="bg-green-50 rounded-xl p-4 text-center">
              <div className="text-2xl font-bold text-green-700">{remediationData.summary.quick_wins}</div>
              <div className="text-xs text-green-600 mt-1">Quick Wins</div>
            </div>
            <div className="bg-green-50 rounded-xl p-4 text-center">
              <div className="text-2xl font-bold text-green-700">
                {Object.values(remediationActions).filter(a => a.status === 'completed').length}
              </div>
              <div className="text-xs text-green-600 mt-1">Completed</div>
            </div>
            <div className="bg-blue-50 rounded-xl p-4 text-center">
              <div className="text-2xl font-bold text-blue-700">
                {Object.values(remediationActions).filter(a => a.status === 'acknowledged').length}
              </div>
              <div className="text-xs text-blue-600 mt-1">Acknowledged</div>
            </div>
          </div>

          {/* Remediation cards */}
          <div className="space-y-4">
            {remediationData.remediations.map((rem, idx) => (
              <RemediationCard
                key={rem.id}
                remediation={rem}
                index={idx}
                action={remediationActions[rem.id]}
                onAction={(status, notes) => handleRemediationAction(rem.id, status, notes)}
                onExecute={(actionType) => handleRemediationExecute(rem.id, actionType)}
                loading={actionLoading === rem.id}
                executing={executeLoading === rem.id}
              />
            ))}
          </div>
        </>
      )}
      <DataSource label="AuditGraph Remediation Engine" apiSource="Pattern-matched playbook library" collectedAt={data?.evidence?.collected_at} />
    </div>
  );
}
