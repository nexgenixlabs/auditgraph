import React, { useCallback } from 'react';
import type { QueryFieldDefinition, QueryCondition, QueryGroup, AdvancedQuery, QueryOperator } from '../types';

// Field categories for grouped dropdown
const FIELD_CATEGORIES: Record<string, string[]> = {
  'Core': ['display_name', 'identity_type', 'identity_category', 'cloud', 'status', 'enabled', 'is_federated'],
  'Risk': ['risk_level', 'risk_score', 'privilege_tier'],
  'Roles': ['rbac_role_count', 'entra_role_count'],
  'Credentials': ['credential_count', 'credential_status', 'credential_risk', 'credential_expiration'],
  'Permissions': ['api_permission_count', 'app_role_count'],
  'Ownership': ['owner_display_name', 'owner_count'],
  'Activity': ['activity_status', 'created_datetime', 'last_sign_in', 'last_seen_auth'],
  'PIM': ['pim_eligible_count', 'has_permanent_assignment'],
  'Conditional Access': ['ca_coverage_status', 'ca_mfa_enforced'],
};

const OPERATOR_LABELS: Record<string, string> = {
  'equals': '=',
  'not_equals': '!=',
  'contains': 'contains',
  'not_contains': 'not contains',
  'greater_than': '>',
  'less_than': '<',
  'in': 'in',
  'not_in': 'not in',
  'is_empty': 'is empty',
  'is_not_empty': 'is not empty',
};

const STRING_OPS: QueryOperator[] = ['equals', 'not_equals', 'contains', 'not_contains', 'in', 'is_empty', 'is_not_empty'];
const NUMBER_OPS: QueryOperator[] = ['equals', 'not_equals', 'greater_than', 'less_than', 'in', 'is_empty', 'is_not_empty'];
const BOOLEAN_OPS: QueryOperator[] = ['equals'];
const DATE_OPS: QueryOperator[] = ['equals', 'greater_than', 'less_than', 'is_empty', 'is_not_empty'];

function getOpsForType(fieldType: string): QueryOperator[] {
  switch (fieldType) {
    case 'number': return NUMBER_OPS;
    case 'boolean': return BOOLEAN_OPS;
    case 'date': return DATE_OPS;
    default: return STRING_OPS;
  }
}

function makeId(): string {
  return Math.random().toString(36).slice(2, 10);
}

function newCondition(): QueryCondition {
  return { id: makeId(), field: '', operator: 'equals', value: '' };
}

function newGroup(): QueryGroup {
  return { id: makeId(), conditions: [newCondition()] };
}

// Value input component that adapts to field type
function ValueInput({
  condition,
  field,
  suggestions,
  onChange,
}: {
  condition: QueryCondition;
  field: QueryFieldDefinition | undefined;
  suggestions: Record<string, string[]>;
  onChange: (value: any) => void;
}) {
  const op = condition.operator;
  if (op === 'is_empty' || op === 'is_not_empty') return null;

  const fieldType = field?.type || 'string';
  const fieldName = condition.field;
  const valueSuggestions = suggestions[fieldName];

  if (fieldType === 'boolean') {
    return (
      <select
        value={String(condition.value)}
        onChange={e => onChange(e.target.value === 'true')}
        className="px-2 py-1.5 text-xs border border-gray-300 rounded-lg bg-white focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
      >
        <option value="true">True</option>
        <option value="false">False</option>
      </select>
    );
  }

  if (fieldType === 'date') {
    return (
      <input
        type="date"
        value={condition.value || ''}
        onChange={e => onChange(e.target.value)}
        className="px-2 py-1.5 text-xs border border-gray-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
      />
    );
  }

  if (valueSuggestions && op !== 'contains' && op !== 'not_contains') {
    if (op === 'in' || op === 'not_in') {
      const selected = Array.isArray(condition.value) ? condition.value : [];
      return (
        <div className="flex flex-wrap gap-1 items-center min-w-[120px]">
          {valueSuggestions.map(s => (
            <button
              key={s}
              type="button"
              onClick={() => {
                const next = selected.includes(s) ? selected.filter((v: string) => v !== s) : [...selected, s];
                onChange(next);
              }}
              className={`px-1.5 py-0.5 text-[10px] rounded-md border ${
                selected.includes(s)
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'bg-white text-gray-600 border-gray-300 hover:border-blue-400'
              }`}
            >
              {s.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
      );
    }
    return (
      <select
        value={condition.value || ''}
        onChange={e => onChange(e.target.value)}
        className="px-2 py-1.5 text-xs border border-gray-300 rounded-lg bg-white focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
      >
        <option value="">Select...</option>
        {valueSuggestions.map(s => (
          <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
        ))}
      </select>
    );
  }

  if (fieldType === 'number') {
    return (
      <input
        type="number"
        value={condition.value ?? ''}
        onChange={e => onChange(e.target.value === '' ? '' : Number(e.target.value))}
        placeholder="0"
        className="w-20 px-2 py-1.5 text-xs border border-gray-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
      />
    );
  }

  return (
    <input
      type="text"
      value={condition.value || ''}
      onChange={e => onChange(e.target.value)}
      placeholder="Value..."
      className="w-32 px-2 py-1.5 text-xs border border-gray-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
    />
  );
}

interface QueryBuilderProps {
  query: AdvancedQuery;
  onChange: (query: AdvancedQuery) => void;
  fields: QueryFieldDefinition[];
  valueSuggestions: Record<string, string[]>;
  resultCount?: number;
  loading?: boolean;
}

export default function QueryBuilder({
  query,
  onChange,
  fields,
  valueSuggestions,
  resultCount,
  loading,
}: QueryBuilderProps) {
  const fieldMap = new Map(fields.map(f => [f.name, f]));

  const updateGroups = useCallback((updater: (groups: QueryGroup[]) => QueryGroup[]) => {
    onChange({ groups: updater(query.groups) });
  }, [query.groups, onChange]);

  const addGroup = useCallback(() => {
    updateGroups(gs => [...gs, newGroup()]);
  }, [updateGroups]);

  const removeGroup = useCallback((gi: number) => {
    updateGroups(gs => gs.filter((_, i) => i !== gi));
  }, [updateGroups]);

  const addCondition = useCallback((gi: number) => {
    updateGroups(gs => gs.map((g, i) =>
      i === gi ? { ...g, conditions: [...g.conditions, newCondition()] } : g
    ));
  }, [updateGroups]);

  const removeCondition = useCallback((gi: number, ci: number) => {
    updateGroups(gs => gs.map((g, i) =>
      i === gi ? { ...g, conditions: g.conditions.filter((_, j) => j !== ci) } : g
    ).filter(g => g.conditions.length > 0));
  }, [updateGroups]);

  const updateCondition = useCallback((gi: number, ci: number, updates: Partial<QueryCondition>) => {
    updateGroups(gs => gs.map((g, i) =>
      i === gi
        ? {
            ...g,
            conditions: g.conditions.map((c, j) => {
              if (j !== ci) return c;
              const updated = { ...c, ...updates };
              // Reset value when field changes
              if (updates.field && updates.field !== c.field) {
                updated.operator = 'equals';
                updated.value = '';
              }
              // Reset value when switching to/from is_empty
              if (updates.operator && (updates.operator === 'is_empty' || updates.operator === 'is_not_empty')) {
                updated.value = '';
              }
              return updated;
            }),
          }
        : g
    ));
  }, [updateGroups]);

  if (query.groups.length === 0) {
    return (
      <div className="text-center py-6">
        <p className="text-sm text-gray-500 mb-3">Build complex queries with AND/OR conditions</p>
        <button
          onClick={addGroup}
          className="px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          Start Building Query
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-500">
          Conditions within a group are AND-joined. Groups are OR-joined.
        </span>
        <div className="flex items-center gap-2">
          {loading && (
            <span className="text-xs text-blue-600 animate-pulse">Querying...</span>
          )}
          {!loading && resultCount !== undefined && (
            <span className="text-xs font-medium text-gray-700">
              {resultCount.toLocaleString()} matching {resultCount === 1 ? 'identity' : 'identities'}
            </span>
          )}
        </div>
      </div>

      {query.groups.map((group, gi) => (
        <React.Fragment key={group.id}>
          {gi > 0 && (
            <div className="flex items-center gap-2 -my-1">
              <div className="flex-1 border-t border-gray-200" />
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-100 text-amber-700 uppercase tracking-wider">
                OR
              </span>
              <div className="flex-1 border-t border-gray-200" />
            </div>
          )}

          <div className="border border-gray-200 rounded-lg bg-gray-50 p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider">
                {query.groups.length > 1 ? `Group ${gi + 1}` : 'Conditions'} (AND)
              </span>
              {query.groups.length > 1 && (
                <button
                  onClick={() => removeGroup(gi)}
                  className="text-[10px] text-red-500 hover:text-red-700 font-medium"
                >
                  Remove group
                </button>
              )}
            </div>

            <div className="space-y-2">
              {group.conditions.map((cond, ci) => {
                const fieldDef = fieldMap.get(cond.field);
                const ops = fieldDef ? getOpsForType(fieldDef.type) : STRING_OPS;

                return (
                  <div key={cond.id} className="flex items-center gap-2 flex-wrap">
                    {ci > 0 && (
                      <span className="text-[10px] font-semibold text-blue-500 uppercase w-8">AND</span>
                    )}
                    {ci === 0 && <span className="w-8 text-[10px] text-gray-400">Where</span>}

                    {/* Field selector */}
                    <select
                      value={cond.field}
                      onChange={e => updateCondition(gi, ci, { field: e.target.value })}
                      className="px-2 py-1.5 text-xs border border-gray-300 rounded-lg bg-white focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="">Select field...</option>
                      {Object.entries(FIELD_CATEGORIES).map(([cat, fieldNames]) => (
                        <optgroup key={cat} label={cat}>
                          {fieldNames.filter(fn => fieldMap.has(fn)).map(fn => (
                            <option key={fn} value={fn}>{fieldMap.get(fn)?.label || fn}</option>
                          ))}
                        </optgroup>
                      ))}
                    </select>

                    {/* Operator selector */}
                    {cond.field && (
                      <select
                        value={cond.operator}
                        onChange={e => updateCondition(gi, ci, { operator: e.target.value as QueryOperator })}
                        className="px-2 py-1.5 text-xs border border-gray-300 rounded-lg bg-white focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                      >
                        {ops.map(op => (
                          <option key={op} value={op}>{OPERATOR_LABELS[op]}</option>
                        ))}
                      </select>
                    )}

                    {/* Value input */}
                    {cond.field && (
                      <ValueInput
                        condition={cond}
                        field={fieldDef}
                        suggestions={valueSuggestions}
                        onChange={val => updateCondition(gi, ci, { value: val })}
                      />
                    )}

                    {/* Remove condition */}
                    <button
                      onClick={() => removeCondition(gi, ci)}
                      className="ml-auto text-gray-400 hover:text-red-500 p-0.5"
                      title="Remove condition"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                );
              })}
            </div>

            <button
              onClick={() => addCondition(gi)}
              className="mt-2 text-xs text-blue-600 hover:text-blue-800 font-medium"
            >
              + Add condition
            </button>
          </div>
        </React.Fragment>
      ))}

      <div className="flex items-center gap-3">
        <button
          onClick={addGroup}
          className="text-xs text-amber-600 hover:text-amber-800 font-medium"
        >
          + Add OR group
        </button>
        <button
          onClick={() => onChange({ groups: [] })}
          className="text-xs text-gray-500 hover:text-gray-700"
        >
          Clear all
        </button>
      </div>
    </div>
  );
}
