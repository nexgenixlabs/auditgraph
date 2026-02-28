import React from 'react';
import type { ComplianceFramework } from './types';

export interface ComplianceSettingsTabProps {
  compFrameworks: ComplianceFramework[];
  togglingFramework: number | null;
  handleToggleFramework: (fw: ComplianceFramework) => void;
}

function ComplianceFrameworkRow({ fw, isCore, toggling, onToggle }: {
  fw: { id: number; name: string; short_name?: string; version: string | null; enabled: boolean; description: string | null; controls: { id: number; control_id: string; name: string }[]; identity_controls_count?: number; total_framework_controls?: number };
  isCore: boolean;
  toggling: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg border">
      <div className="flex items-center gap-3 min-w-0 flex-1">
        <button
          onClick={onToggle}
          disabled={toggling || isCore}
          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-shrink-0 ${
            fw.enabled ? 'bg-green-500' : 'bg-gray-300'
          } ${isCore ? 'opacity-60 cursor-not-allowed' : ''}`}
        >
          <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
            fw.enabled ? 'translate-x-4' : 'translate-x-0.5'
          }`} />
        </button>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium text-gray-900 flex items-center gap-2">
            {fw.short_name || fw.name}
            {fw.version && (
              <span className="px-1.5 py-0.5 bg-gray-100 text-gray-500 text-[10px] font-medium rounded">
                {fw.version}
              </span>
            )}
            {isCore && (
              <span className="px-1.5 py-0.5 bg-violet-50 text-violet-600 text-[9px] font-semibold rounded">
                Required
              </span>
            )}
          </div>
          <div className="text-xs text-gray-500">
            {fw.identity_controls_count || fw.controls?.length || 0} identity controls
            {!!fw.total_framework_controls && fw.total_framework_controls > 0 && (
              <span className="text-gray-400"> of {fw.total_framework_controls} total</span>
            )}
            {fw.description && <> &middot; {fw.description.slice(0, 60)}{(fw.description.length ?? 0) > 60 ? '...' : ''}</>}
          </div>
        </div>
      </div>
      <span className={`text-xs font-medium px-2 py-0.5 rounded ${
        fw.enabled ? 'bg-green-50 text-green-700' : 'bg-gray-100 text-gray-500'
      }`}>
        {fw.enabled ? 'Active' : 'Disabled'}
      </span>
    </div>
  );
}

export function ComplianceSettingsTab({
  compFrameworks,
  togglingFramework,
  handleToggleFramework,
}: ComplianceSettingsTabProps) {
  return (
    <>
      {/* Section 10: Compliance Frameworks */}
      <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="text-lg font-semibold text-gray-900">Compliance Frameworks</div>
            <span className="px-2 py-0.5 rounded-full text-[9px] font-medium bg-violet-50 text-violet-600">
              Identity Controls Only
            </span>
          </div>
          <p className="text-sm text-gray-500 mt-0.5">
            Enable or disable compliance frameworks evaluated against your identity posture.
            Scope: Identity, access, and privilege controls only.
          </p>
        </div>

        {compFrameworks.length === 0 ? (
          <div className="text-sm text-gray-400 text-center py-6 border border-dashed rounded-lg">
            No compliance frameworks found. They will be seeded on backend startup.
          </div>
        ) : (
          (() => {
            const TIER_ORDER = ['core', 'industry', 'privacy', 'benchmark'];
            const TIER_LABELS: Record<string, string> = {
              core: 'Core Governance',
              industry: 'Industry Specific',
              privacy: 'Privacy & Data Protection',
              benchmark: 'Technical Benchmarks',
            };
            const tierGroups: Record<string, ComplianceFramework[]> = {};
            for (const fw of compFrameworks) {
              const tier = fw.tier || 'core';
              if (!tierGroups[tier]) tierGroups[tier] = [];
              tierGroups[tier].push(fw);
            }
            const orderedTiers = TIER_ORDER.filter(t => tierGroups[t]?.length);
            // Fallback: if no tier data, show flat
            if (orderedTiers.length === 0) {
              return (
                <div className="space-y-2">
                  {compFrameworks.map(fw => (
                    <ComplianceFrameworkRow key={fw.id} fw={fw} isCore={false} toggling={togglingFramework === fw.id} onToggle={() => handleToggleFramework(fw)} />
                  ))}
                </div>
              );
            }
            return (
              <div className="space-y-5">
                {orderedTiers.map(tier => (
                  <div key={tier}>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-xs font-semibold uppercase tracking-wider text-gray-500">
                        {TIER_LABELS[tier] || tier}
                      </span>
                      {tier === 'core' && (
                        <span className="px-1.5 py-0.5 bg-violet-50 text-violet-600 text-[9px] font-semibold rounded">
                          Required
                        </span>
                      )}
                    </div>
                    <div className="space-y-2">
                      {tierGroups[tier].map(fw => (
                        <ComplianceFrameworkRow key={fw.id} fw={fw} isCore={tier === 'core'} toggling={togglingFramework === fw.id} onToggle={() => handleToggleFramework(fw)} />
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            );
          })()
        )}

        <p className="text-xs text-gray-400">
          Disabled frameworks are excluded from the compliance dashboard and gap analysis. Controls are evaluated on each API call using current identity posture data.
        </p>
      </div>
    </>
  );
}
