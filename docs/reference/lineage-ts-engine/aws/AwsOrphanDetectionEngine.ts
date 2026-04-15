/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * AwsOrphanDetectionEngine — AWS-specific orphan classification.
 *
 * Gathers signals from identity_lineage_bindings (populated by P2 modules),
 * CloudTrail events, and a single IAM API call (GetRole → RoleLastUsed).
 *
 * Signals (all DB except g):
 *   a) noTrustPolicyBinding     — no rows WHERE resource_type = 'AWSTrustPolicy'
 *   b) noLambdaBinding          — no rows WHERE resource_type = 'AWSLambda'
 *   c) noECSBinding             — no rows WHERE resource_type = 'AWSECSTask'
 *   d) noEKSBinding             — no rows WHERE resource_type = 'AWSEKSWorkload'
 *   e) noOIDCBinding            — no rows WHERE resource_type LIKE 'AWS%OIDC%'
 *   f) noResourcePolicyRef      — no rows WHERE resource_type IN (S3/KMS/SQS/SNS)
 *   g) lastAssumedDays          — iam:GetRole → RoleLastUsed.LastUsedDate
 *   h) recentCloudTrailActivity — aws_cloudtrail_events in last 90 days
 *
 * Classification (first match wins):
 *   NOT_ORPHANED  — any binding exists OR CloudTrail active OR lastAssumed < 30d
 *   CAUTION       — no bindings + dormant 90d+ + has write policies
 *   SAFE_TO_RETIRE— no bindings + dormant 90d+ + no CloudTrail + no write policies
 *   BLOCKED       — crossCloudReferenced (P5 sets this)
 *   UNKNOWN       — default / insufficient data
 */

import type { Pool } from "pg";
import type { IAMClient } from "@aws-sdk/client-iam";
import { GetRoleCommand } from "@aws-sdk/client-iam";
import type {
  OrphanStatus,
  OrphanClassification,
} from "../OrphanDetectionEngine";

// ── Signal types ──────────────────────────────────────────────────

interface AwsOrphanSignals {
  noTrustPolicyBinding: boolean;
  noLambdaBinding: boolean;
  noECSBinding: boolean;
  noEKSBinding: boolean;
  noOIDCBinding: boolean;
  noResourcePolicyRef: boolean;
  lastAssumedDays: number; // -1 = never used / unknown
  recentCloudTrailActivity: number; // count of events in last 90d
  hasWritePolicies: boolean;
  crossCloudReferenced: boolean;
}

// ── Helpers ─────────────────────────────────────────────────────────

function extractRoleName(arn: string): string {
  const match = arn.match(/:role\/(.+)$/);
  return match?.[1] ?? arn;
}

// ── Signal gathering ────────────────────────────────────────────────

/**
 * Check binding existence by resource_type pattern.
 */
async function hasBindingOfType(
  db: Pool,
  spnId: string,
  resourceTypeCondition: string,
  params: unknown[] = []
): Promise<boolean> {
  const { rows } = await db.query(
    `SELECT 1 FROM identity_lineage_bindings
     WHERE spn_id = $1 AND ${resourceTypeCondition}
     LIMIT 1`,
    [spnId, ...params]
  );
  return rows.length > 0;
}

/**
 * Get RoleLastUsed.LastUsedDate via iam:GetRole.
 * Returns days since last use, or -1 if never used / error.
 */
async function getLastAssumedDays(
  roleArn: string,
  iamClient: IAMClient
): Promise<number> {
  try {
    const roleName = extractRoleName(roleArn);
    const resp = await iamClient.send(
      new GetRoleCommand({ RoleName: roleName })
    );
    const lastUsed = resp.Role?.RoleLastUsed?.LastUsedDate;
    if (!lastUsed) return -1;
    const daysSince = Math.floor(
      (Date.now() - new Date(lastUsed).getTime()) / (1000 * 60 * 60 * 24)
    );
    return daysSince;
  } catch {
    return -1;
  }
}

/**
 * Check if the role has managed policies with write/admin permissions.
 * Looks at attached policy names for common write-level indicators.
 */
async function checkWritePolicies(
  db: Pool,
  spnId: string
): Promise<boolean> {
  // Check binding_evidence for attached policy info from TrustPolicyParser
  const { rows } = await db.query(
    `SELECT binding_evidence
     FROM identity_lineage_bindings
     WHERE spn_id = $1 AND resource_type = 'AWSTrustPolicy'
     LIMIT 5`,
    [spnId]
  );

  for (const row of rows) {
    const evidence = row.binding_evidence;
    if (!evidence) continue;
    const trustType = evidence.trustType ?? "";
    // ServicePrincipal bindings or cross-account with broad trust → write-capable
    if (
      trustType === "WildcardTrust" ||
      trustType === "CrossAccountAssumeRole"
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Gather all orphan-detection signals for an AWS identity.
 */
export async function gatherAwsOrphanSignals(
  identityId: string,
  roleArn: string,
  db: Pool,
  iamClient: IAMClient
): Promise<AwsOrphanSignals> {
  const spnId = identityId;

  // Run all DB queries + IAM call in parallel
  const [
    hasTrust,
    hasLambda,
    hasECS,
    hasEKS,
    hasOIDC,
    hasResPolicy,
    lastAssumedDays,
    cloudTrailResult,
    hasWritePols,
  ] = await Promise.all([
    hasBindingOfType(db, spnId, "resource_type = 'AWSTrustPolicy'"),
    hasBindingOfType(db, spnId, "resource_type = 'AWSLambda'"),
    hasBindingOfType(db, spnId, "resource_type = 'AWSECSTask'"),
    hasBindingOfType(db, spnId, "resource_type = 'AWSEKSWorkload'"),
    hasBindingOfType(db, spnId, "resource_type LIKE 'AWS%OIDC%'"),
    hasBindingOfType(
      db,
      spnId,
      "resource_type IN ('S3Bucket', 'KMSKey', 'SQSQueue', 'SNSTopic')"
    ),
    getLastAssumedDays(roleArn, iamClient),
    db.query(
      `SELECT COUNT(*)::int AS cnt
       FROM aws_cloudtrail_events
       WHERE identity_db_id = $1
         AND event_time > NOW() - INTERVAL '90 days'`,
      [spnId]
    ),
    checkWritePolicies(db, spnId),
  ]);

  return {
    noTrustPolicyBinding: !hasTrust,
    noLambdaBinding: !hasLambda,
    noECSBinding: !hasECS,
    noEKSBinding: !hasEKS,
    noOIDCBinding: !hasOIDC,
    noResourcePolicyRef: !hasResPolicy,
    lastAssumedDays,
    recentCloudTrailActivity: cloudTrailResult.rows[0]?.cnt ?? 0,
    hasWritePolicies: hasWritePols,
    crossCloudReferenced: false, // P5 populates this
  };
}

// ── Classification cascade ──────────────────────────────────────────

/**
 * Apply the classification cascade (first match wins).
 */
export function classifyFromSignals(
  signals: AwsOrphanSignals
): { status: OrphanStatus; reasons: string[]; recommendedAction: string | null } {
  const reasons: string[] = [];

  const allBindingsMissing =
    signals.noTrustPolicyBinding &&
    signals.noLambdaBinding &&
    signals.noECSBinding &&
    signals.noEKSBinding &&
    signals.noOIDCBinding &&
    signals.noResourcePolicyRef;

  const anyBindingExists = !allBindingsMissing;

  // Collect reasons
  if (signals.noTrustPolicyBinding) reasons.push("No trust policy binding");
  if (signals.noLambdaBinding) reasons.push("No Lambda execution role binding");
  if (signals.noECSBinding) reasons.push("No ECS task binding");
  if (signals.noEKSBinding) reasons.push("No EKS workload binding");
  if (signals.noOIDCBinding) reasons.push("No OIDC federation binding");
  if (signals.noResourcePolicyRef) reasons.push("No resource policy reference (S3/KMS/SQS/SNS)");
  if (signals.lastAssumedDays >= 0) {
    reasons.push(`Role last assumed ${signals.lastAssumedDays} days ago`);
  } else {
    reasons.push("Role never assumed or LastUsedDate unavailable");
  }
  if (signals.recentCloudTrailActivity > 0) {
    reasons.push(`${signals.recentCloudTrailActivity} CloudTrail events in last 90 days`);
  }
  if (signals.hasWritePolicies) reasons.push("Has write-level managed policies");
  if (signals.crossCloudReferenced) reasons.push("Referenced in cross-cloud configuration");

  // ── BLOCKED: cross-cloud reference ──────────────────────────────
  if (signals.crossCloudReferenced) {
    return {
      status: "BLOCKED",
      reasons,
      recommendedAction:
        "Do not modify — identity is referenced in cross-cloud configuration. Review in P5.",
    };
  }

  // ── NOT_ORPHANED: any binding exists OR CloudTrail active OR recent usage
  if (
    anyBindingExists ||
    signals.recentCloudTrailActivity > 0 ||
    (signals.lastAssumedDays >= 0 && signals.lastAssumedDays < 30)
  ) {
    return {
      status: "NOT_ORPHANED",
      reasons,
      recommendedAction: null,
    };
  }

  // ── CAUTION: all bindings missing + dormant 90d+ + write policies
  if (
    allBindingsMissing &&
    signals.lastAssumedDays > 90 &&
    signals.recentCloudTrailActivity === 0 &&
    signals.hasWritePolicies
  ) {
    return {
      status: "CAUTION",
      reasons,
      recommendedAction:
        "Review managed policies before retirement — role has write permissions but no active bindings.",
    };
  }

  // ── SAFE_TO_RETIRE: all bindings missing + dormant 90d+ + no activity
  if (
    allBindingsMissing &&
    signals.lastAssumedDays > 90 &&
    signals.recentCloudTrailActivity === 0
  ) {
    return {
      status: "SAFE_TO_RETIRE",
      reasons,
      recommendedAction:
        "Safe to disable or delete — no bindings, no CloudTrail activity, dormant 90+ days.",
    };
  }

  // ── UNKNOWN: default
  return {
    status: "UNKNOWN",
    reasons: reasons.length > 0 ? reasons : ["Insufficient data to classify"],
    recommendedAction:
      "Gather more lineage data before making a retirement decision.",
  };
}

// ── Main entry point ────────────────────────────────────────────────

/**
 * Classify orphan status for a single AWS identity.
 * Gathers signals from DB + a single IAM GetRole call, applies cascade.
 */
export async function classifyAwsOrphanStatus(
  identityId: string,
  roleArn: string,
  db: Pool,
  iamClient: IAMClient
): Promise<OrphanClassification> {
  const signals = await gatherAwsOrphanSignals(identityId, roleArn, db, iamClient);
  const result = classifyFromSignals(signals);

  return {
    spnId: identityId,
    orphanStatus: result.status,
    orphanReasons: result.reasons,
    activeRoleCount: 0, // AWS doesn't use the P1 role-count model
    recommendedAction: result.recommendedAction,
  };
}

// ── Persistence ─────────────────────────────────────────────────────

/**
 * Persist AWS orphan classification to identity_orphan_classifications.
 * ON CONFLICT (spn_id) DO UPDATE — same table as P1.
 */
export async function persistAwsOrphanClassification(
  db: Pool,
  connectionId: string,
  classification: OrphanClassification
): Promise<void> {
  await db.query(
    `INSERT INTO identity_orphan_classifications
       (spn_id, connection_id, orphan_status, orphan_reasons,
        active_role_count, recommended_action)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (spn_id) DO UPDATE SET
       orphan_status      = EXCLUDED.orphan_status,
       orphan_reasons     = EXCLUDED.orphan_reasons,
       active_role_count  = EXCLUDED.active_role_count,
       recommended_action = EXCLUDED.recommended_action,
       classified_at      = NOW()`,
    [
      classification.spnId,
      connectionId,
      classification.orphanStatus,
      JSON.stringify(classification.orphanReasons),
      classification.activeRoleCount,
      classification.recommendedAction,
    ]
  );
}
