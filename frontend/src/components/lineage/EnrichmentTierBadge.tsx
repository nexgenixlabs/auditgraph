import React, { useState } from 'react';

const TIER_CONFIG: Record<string, { label: string; badgeClass: string; tooltip: string }> = {
  STATIC: {
    label: 'Static Analysis',
    badgeClass: 'bg-gray-100 text-gray-500 border-gray-200',
    tooltip: 'Workload associations from Resource Graph, ARM, and MS Graph only. No log data available.',
  },
  P1_SIGNIN: {
    label: 'Sign-in Enriched',
    badgeClass: 'bg-blue-100 text-blue-700 border-blue-200',
    tooltip: 'Static analysis plus sign-in activity type classification (NonInteractive / Delegated / Mixed). Enable Log Analytics to unlock full enrichment.',
  },
  P2_AUDIT: {
    label: 'Audit Log Enriched',
    badgeClass: 'bg-amber-100 text-amber-700 border-amber-200',
    tooltip: 'Static analysis plus cloud audit log signals (CloudTrail / GCP Audit Logs). Azure Log Analytics not yet connected.',
  },
  FULL: {
    label: 'Full Enrichment',
    badgeClass: 'bg-green-100 text-green-700 border-green-200',
    tooltip: 'All enrichment sources active: sign-in logs, ARM activity logs, Key Vault audit, and cloud audit logs.',
  },
};

export function EnrichmentTierBadge({ tier }: { tier: string | null | undefined }): React.ReactElement {
  const [showTooltip, setShowTooltip] = useState(false);
  const cfg = TIER_CONFIG[tier ?? ''] || TIER_CONFIG.STATIC;

  return (
    <div
      className="relative inline-block"
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-semibold ${cfg.badgeClass}`}>
        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
        </svg>
        {cfg.label}
      </span>

      {showTooltip && (
        <div className="absolute z-20 bottom-full mb-1.5 left-0 w-56 bg-gray-900 text-white text-[10px] rounded-lg px-3 py-2 shadow-lg">
          {cfg.tooltip}
          <div className="absolute top-full left-4 w-2 h-2 bg-gray-900 rotate-45 -mt-1" />
        </div>
      )}
    </div>
  );
}

export default EnrichmentTierBadge;
