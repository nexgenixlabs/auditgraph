/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * OrphanDetectionEngine — classifies whether an SPN is orphaned by gathering
 * signals entirely from the database (no new API calls).
 *
 * Signals:
 *   a) secretsExpired / certsExpired — from identities credential columns
 *   b) dormancyDays — from enrichment table or identities.created_at fallback
 *   c) hasResourceBindings — from identity_lineage_bindings (excluding RoleInferred)
 *   d) hasFederatedBindings — from identity_lineage_bindings (Federated%)
 *   e) activeRoleCount — from RoleInferred binding_evidence JSONB
 *   f) crossCloudReferenced — false (P1 default; P5 populates)
 *
 * Classification cascade (first match wins):
 *   BLOCKED → NOT_ORPHANED → CAUTION → SAFE_TO_RETIRE → UNKNOWN
 */

import type { Pool } from "pg";

// ── Public types ────────────────────────────────────────────────────

export type OrphanStatus =
  | "UNKNOWN"
  | "NOT_ORPHANED"
  | "SAFE_TO_RETIRE"
  | "CAUTION"
  | "BLOCKED";

export interface OrphanClassification {
  spnId: string;
  orphanStatus: OrphanStatus;
  orphanReasons: string[];
  activeRoleCount: number;
  recommendedAction: string | null;
}

// ── Signal gathering ────────────────────────────────────────────────

interface OrphanSignals {
  secretsExpired: boolean;
  certsExpired: boolean;
  dormancyDays: number;
  hasResourceBindings: boolean;
  hasFederatedBindings: boolean;
  activeRoleCount: number;
  crossCloudReferenced: boolean;
}

const READER_ROLES = new Set([
  "reader",
  "monitoring reader",
  "log analytics reader",
  "monitoring contributor",
  "log analytics contributor",
]);

/**
 * Gather all orphan-detection signals for an SPN from the database.
 * No API calls — pure SQL queries.
 */
export async function gatherSignals(
  db: Pool,
  spnId: string
): Promise<OrphanSignals> {
  // ── a+b) Credential expiry from identities table ────────────────
  const credResult = await db.query(
    `SELECT
       credential_expiration,
       credential_status,
       next_expiry,
       created_at
     FROM identities
     WHERE id = $1`,
    [spnId]
  );

  let secretsExpired = false;
  let certsExpired = false;
  let createdAt: Date | null = null;

  if (credResult.rows.length > 0) {
    const row = credResult.rows[0];
    createdAt = row.created_at ? new Date(row.created_at) : null;

    // credential_expiration or next_expiry in the past → expired
    const expiry = row.credential_expiration ?? row.next_expiry;
    if (expiry && new Date(expiry) < new Date()) {
      // credential_status hints at type; treat all as secrets for P1
      secretsExpired = true;
    }
    if (row.credential_status === "expired") {
      secretsExpired = true;
    }
  }

  // ── c) Dormancy — from enrichment table, fallback to created_at ─
  const enrichResult = await db.query(
    `SELECT
       COALESCE(
         (raw_signals->>'dormancyDays')::int,
         EXTRACT(DAY FROM NOW() - last_accessed_at)::int
       ) AS dormancy_days
     FROM identity_lineage_enrichment
     WHERE spn_id = $1 AND enrichment_source = 'SPSignInActivity'
     ORDER BY captured_at DESC
     LIMIT 1`,
    [spnId]
  );

  let dormancyDays: number;
  if (enrichResult.rows.length > 0 && enrichResult.rows[0].dormancy_days != null) {
    dormancyDays = enrichResult.rows[0].dormancy_days;
  } else if (createdAt) {
    dormancyDays = Math.floor(
      (Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24)
    );
  } else {
    dormancyDays = -1;
  }

  // ── d) Resource bindings (excluding RoleInferred) ───────────────
  const resourceResult = await db.query(
    `SELECT COUNT(*) AS cnt
     FROM identity_lineage_bindings
     WHERE spn_id = $1 AND resource_type != 'RoleInferred'`,
    [spnId]
  );
  const hasResourceBindings = parseInt(resourceResult.rows[0]?.cnt ?? "0", 10) > 0;

  // ── e) Federated bindings ───────────────────────────────────────
  const fedResult = await db.query(
    `SELECT COUNT(*) AS cnt
     FROM identity_lineage_bindings
     WHERE spn_id = $1 AND resource_type LIKE 'Federated%'`,
    [spnId]
  );
  const hasFederatedBindings = parseInt(fedResult.rows[0]?.cnt ?? "0", 10) > 0;

  // ── f) Active role count from RoleInferred evidence ─────────────
  const roleResult = await db.query(
    `SELECT binding_evidence
     FROM identity_lineage_bindings
     WHERE spn_id = $1 AND resource_type = 'RoleInferred'
     ORDER BY last_verified_at DESC NULLS LAST
     LIMIT 1`,
    [spnId]
  );

  let activeRoleCount = 0;
  if (roleResult.rows.length > 0) {
    const evidence = roleResult.rows[0].binding_evidence;
    const assignments: Array<{ roleDefinitionName: string }> =
      evidence?.roleAssignments ?? [];
    activeRoleCount = assignments.filter(
      (a) => !READER_ROLES.has(a.roleDefinitionName.toLowerCase())
    ).length;
  }

  // ── g) Cross-cloud referenced — P1 default: false ───────────────
  const crossCloudReferenced = false;

  return {
    secretsExpired,
    certsExpired,
    dormancyDays,
    hasResourceBindings,
    hasFederatedBindings,
    activeRoleCount,
    crossCloudReferenced,
  };
}

// ── Classification cascade ──────────────────────────────────────────

/**
 * Apply the 5-level classification cascade (first match wins).
 */
export function classify(signals: OrphanSignals): OrphanClassification {
  const reasons: string[] = [];
  const {
    secretsExpired,
    certsExpired,
    dormancyDays,
    hasResourceBindings,
    hasFederatedBindings,
    activeRoleCount,
    crossCloudReferenced,
  } = signals;

  const hasBindings = hasResourceBindings || hasFederatedBindings;
  const credsExpired = secretsExpired || certsExpired;

  if (secretsExpired) reasons.push("All client secrets expired");
  if (certsExpired) reasons.push("All certificates expired");
  if (dormancyDays >= 90) reasons.push(`Dormant for ${dormancyDays} days`);
  if (!hasResourceBindings && !hasFederatedBindings) reasons.push("No resource or federated bindings");
  if (hasFederatedBindings) reasons.push("Has federated credential bindings");
  if (hasResourceBindings) reasons.push("Has resource bindings");
  if (activeRoleCount > 0) reasons.push(`${activeRoleCount} active (non-Reader) role(s)`);
  if (crossCloudReferenced) reasons.push("Referenced in cross-cloud configuration");

  // ── BLOCKED: cross-cloud reference present ──────────────────────
  if (crossCloudReferenced) {
    return {
      spnId: "",
      orphanStatus: "BLOCKED",
      orphanReasons: reasons,
      activeRoleCount,
      recommendedAction: "Do not modify — identity is referenced in cross-cloud configuration. Review in P5.",
    };
  }

  // ── NOT_ORPHANED: has bindings AND dormancy < 90 ────────────────
  if (hasBindings && dormancyDays < 90) {
    return {
      spnId: "",
      orphanStatus: "NOT_ORPHANED",
      orphanReasons: reasons,
      activeRoleCount,
      recommendedAction: null,
    };
  }

  // ── CAUTION: creds expired + active roles + dormant ≥ 90 ───────
  if (credsExpired && activeRoleCount > 0 && dormancyDays >= 90) {
    return {
      spnId: "",
      orphanStatus: "CAUTION",
      orphanReasons: reasons,
      activeRoleCount,
      recommendedAction: "Review role assignments before retirement — credentials expired but active roles remain.",
    };
  }

  // ── SAFE_TO_RETIRE: expired or dormant, no bindings, no roles ──
  if (
    (credsExpired || dormancyDays >= 90) &&
    !hasResourceBindings &&
    !hasFederatedBindings &&
    activeRoleCount === 0
  ) {
    return {
      spnId: "",
      orphanStatus: "SAFE_TO_RETIRE",
      orphanReasons: reasons,
      activeRoleCount,
      recommendedAction: "Safe to disable or delete — no bindings, no active roles, credentials expired or dormant.",
    };
  }

  // ── UNKNOWN: default ────────────────────────────────────────────
  return {
    spnId: "",
    orphanStatus: "UNKNOWN",
    orphanReasons: reasons.length > 0 ? reasons : ["Insufficient data to classify"],
    activeRoleCount,
    recommendedAction: "Gather more lineage data before making a retirement decision.",
  };
}

// ── Main entry point ────────────────────────────────────────────────

/**
 * Classify orphan status for a single SPN.
 * Gathers all signals from DB, applies the cascade, returns the result.
 */
export async function classifyOrphanStatus(
  db: Pool,
  spnId: string
): Promise<OrphanClassification> {
  const signals = await gatherSignals(db, spnId);
  const result = classify(signals);
  result.spnId = spnId;
  return result;
}

// ── Persistence ─────────────────────────────────────────────────────

/**
 * Upsert orphan classification into identity_orphan_classifications.
 *
 * ON CONFLICT (spn_id) DO UPDATE — the table has a UNIQUE constraint on spn_id.
 */
export async function persistOrphanClassification(
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
