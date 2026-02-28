import React from 'react';
import type { RiskRuleData } from './types';

export interface ScoringTabProps {
  riskRules: RiskRuleData[];
  openRuleModal: (rule?: RiskRuleData) => void;
  handleToggleRule: (rule: RiskRuleData) => void;
  ruleDeleteConfirm: number | null;
  setRuleDeleteConfirm: (id: number | null) => void;
  handleRuleDelete: (id: number) => void;
}

export function ScoringTab({
  riskRules,
  openRuleModal,
  handleToggleRule,
  ruleDeleteConfirm,
  setRuleDeleteConfirm,
  handleRuleDelete,
}: ScoringTabProps) {
  return (
    <>
      {/* Section 6: Custom Risk Rules */}
      <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-lg font-semibold text-gray-900">Custom Risk Rules</div>
            <p className="text-sm text-gray-500 mt-0.5">
              Adjust risk scoring with custom conditions — runs after default scoring
            </p>
          </div>
          <button
            onClick={() => openRuleModal()}
            disabled={riskRules.length >= 50}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
              riskRules.length >= 50
                ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                : 'bg-blue-600 text-white hover:bg-blue-700'
            }`}
          >
            + Add Rule
          </button>
        </div>

        {riskRules.length === 0 ? (
          <div className="text-sm text-gray-400 text-center py-6 border border-dashed rounded-lg">
            No custom risk rules configured. Add one to customize risk scoring.
          </div>
        ) : (
          <div className="space-y-2">
            {riskRules.map(rule => (
              <div key={rule.id} className="border rounded-lg px-4 py-3 flex items-center justify-between">
                <div className="flex items-center gap-3 min-w-0 flex-1">
                  <button
                    onClick={() => handleToggleRule(rule)}
                    className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-shrink-0 ${
                      rule.enabled ? 'bg-green-500' : 'bg-gray-300'
                    }`}
                  >
                    <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                      rule.enabled ? 'translate-x-4' : 'translate-x-0.5'
                    }`} />
                  </button>

                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium text-gray-900 truncate">{rule.name}</div>
                    <div className="text-xs text-gray-400">
                      {(rule.conditions?.all || []).length} condition{(rule.conditions?.all || []).length !== 1 ? 's' : ''} · Priority {rule.priority}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-shrink-0">
                  {/* Action badge */}
                  {rule.action_type === 'force_level' ? (
                    <span className={`px-2 py-0.5 text-[10px] font-semibold rounded ${
                      rule.force_level === 'critical' ? 'bg-red-100 text-red-700' :
                      rule.force_level === 'high' ? 'bg-orange-100 text-orange-700' :
                      rule.force_level === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                      'bg-green-100 text-green-700'
                    }`}>
                      FORCE {(rule.force_level || '').toUpperCase()}
                    </span>
                  ) : (
                    <span className={`px-2 py-0.5 text-[10px] font-semibold rounded ${
                      rule.points_adjustment > 0 ? 'bg-red-50 text-red-600' : 'bg-green-50 text-green-600'
                    }`}>
                      {rule.points_adjustment > 0 ? '+' : ''}{rule.points_adjustment} pts
                    </span>
                  )}

                  <button
                    onClick={() => openRuleModal(rule)}
                    className="px-2 py-1 text-xs font-medium text-blue-600 bg-blue-50 hover:bg-blue-100 rounded transition"
                  >
                    Edit
                  </button>
                  {ruleDeleteConfirm === rule.id ? (
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => handleRuleDelete(rule.id)}
                        className="px-2 py-1 text-xs font-medium text-white bg-red-600 hover:bg-red-700 rounded transition"
                      >
                        Confirm
                      </button>
                      <button
                        onClick={() => setRuleDeleteConfirm(null)}
                        className="px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded transition"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setRuleDeleteConfirm(rule.id)}
                      className="px-2 py-1 text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded transition"
                    >
                      Delete
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        <p className="text-xs text-gray-400">
          Maximum 50 rules. Rules run after default scoring on every snapshot, ordered by priority (lower runs first).
        </p>
      </div>
    </>
  );
}
