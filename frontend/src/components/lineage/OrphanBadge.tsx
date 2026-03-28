import React, { useState } from 'react';

interface OrphanClassification {
  orphanStatus: string;
  orphanReasons: string[];
  recommendedAction: string | null;
  activeRoleCount: number;
}

const ORPHAN_CONFIG: Record<string, { label: string; badgeClass: string; iconColor: string }> = {
  SAFE_TO_RETIRE: {
    label: 'Safe to Retire',
    badgeClass: 'bg-green-100 text-green-700 border-green-200',
    iconColor: 'text-green-500',
  },
  CAUTION: {
    label: 'Caution \u2014 Active Roles',
    badgeClass: 'bg-amber-100 text-amber-700 border-amber-200',
    iconColor: 'text-amber-500',
  },
  BLOCKED: {
    label: 'Blocked \u2014 Cross-Cloud Reference',
    badgeClass: 'bg-red-100 text-red-700 border-red-200',
    iconColor: 'text-red-500',
  },
  NOT_ORPHANED: {
    label: 'Active Workload',
    badgeClass: 'bg-gray-100 text-gray-500 border-gray-200',
    iconColor: 'text-gray-400',
  },
  UNKNOWN: {
    label: 'Status Unknown',
    badgeClass: 'bg-gray-50 text-gray-400 border-gray-200',
    iconColor: 'text-gray-300',
  },
};

/** Friendly labels for AWS-specific orphan reasons from AwsOrphanDetectionEngine. */
const AWS_REASON_LABELS: Record<string, string> = {
  no_trust_policy_binding: 'No trust policy bindings found',
  no_lambda_binding: 'Not attached to any Lambda function',
  no_ecs_binding: 'Not used in any ECS task definition',
  no_eks_binding: 'No EKS workload associations',
  no_oidc_binding: 'No OIDC federation configured',
  no_resource_policy_ref: 'Not referenced in any resource policy (S3/KMS/SQS/SNS)',
  dormant_90d: 'IAM role not assumed in 90+ days',
  dormant_never: 'IAM role has never been assumed',
  no_cloudtrail_activity: 'No CloudTrail activity in last 90 days',
  has_write_policies: 'Role has write permissions (elevated risk)',
  cross_cloud_referenced: 'Referenced by identities in another cloud provider',
};

/** Full orphan badge with expandable reasons. */
export function OrphanBadge({ classification }: { classification: OrphanClassification }): React.ReactElement {
  const [expanded, setExpanded] = useState(false);
  const cfg = ORPHAN_CONFIG[classification.orphanStatus] || ORPHAN_CONFIG.UNKNOWN;

  return (
    <div className="relative inline-block">
      <button
        onClick={(e) => { e.stopPropagation(); setExpanded(!expanded); }}
        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-semibold transition-colors hover:opacity-80 ${cfg.badgeClass}`}
      >
        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        {cfg.label}
      </button>

      {expanded && classification.orphanReasons.length > 0 && (
        <div className="absolute z-20 mt-1 left-0 w-64 bg-white border border-gray-200 rounded-lg shadow-lg p-3 text-xs">
          <p className="font-semibold text-gray-700 mb-1.5">Orphan Analysis</p>
          <ul className="space-y-1">
            {classification.orphanReasons.map((reason, i) => (
              <li key={i} className="flex items-start gap-1.5 text-gray-600">
                <span className="mt-0.5 w-1 h-1 rounded-full bg-gray-400 shrink-0" />
                {AWS_REASON_LABELS[reason] || reason}
              </li>
            ))}
          </ul>
          {classification.recommendedAction && (
            <div className="mt-2 pt-2 border-t border-gray-100">
              <p className="text-[10px] font-semibold text-gray-500 uppercase mb-0.5">Recommended</p>
              <p className="text-gray-700">{classification.recommendedAction}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** Compact icon-only orphan badge for table rows. */
export function OrphanBadgeCompact({ status }: { status: string }): React.ReactElement {
  const cfg = ORPHAN_CONFIG[status] || ORPHAN_CONFIG.UNKNOWN;

  if (status === 'NOT_ORPHANED' || status === 'UNKNOWN') {
    return <span className="w-4" />;
  }

  return (
    <span
      className={`inline-flex items-center justify-center w-5 h-5 rounded-full ${cfg.badgeClass}`}
      title={cfg.label}
    >
      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5}
          d={status === 'SAFE_TO_RETIRE'
            ? 'M5 13l4 4L19 7'
            : status === 'CAUTION'
            ? 'M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'
            : 'M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728L5.636 5.636'} />
      </svg>
    </span>
  );
}

export default OrphanBadge;
