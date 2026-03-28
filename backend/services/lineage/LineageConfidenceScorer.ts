/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * LineageConfidenceScorer — computes a 0-100 composite score reflecting how
 * much we know about an SPN's lineage (bindings, creds, topology, enrichment).
 *
 * Scoring (additive, max 100):
 *   +35  resource binding with confidence >= 85
 *   +25  federated credential binding exists
 *   +15  roleTopology workloadType != "Unknown"
 *   +10  app registration has Azure URL in inferredHostUrls
 *   +10  enrichmentTier == "P2_AUDIT" (Full)
 *   +5   SPN has at least one owner
 *
 * All signals read from DB — no API calls.
 */

import type { Pool } from "pg";

// ── Signal queries ──────────────────────────────────────────────────

interface ScoringSignals {
  hasHighConfidenceBinding: boolean;   // +35
  hasFederatedBinding: boolean;        // +25
  hasKnownWorkloadType: boolean;       // +15
  hasAzureReplyUrl: boolean;           // +10
  hasFullEnrichment: boolean;          // +10
  hasOwner: boolean;                   // +5
}

async function gatherScoringSignals(
  db: Pool,
  spnId: string
): Promise<ScoringSignals> {
  // Single query: gather multiple counts from identity_lineage_bindings
  const bindingResult = await db.query(
    `SELECT
       COUNT(*) FILTER (
         WHERE resource_type NOT IN ('RoleInferred') AND confidence_score >= 85
       ) AS high_conf_count,
       COUNT(*) FILTER (
         WHERE resource_type LIKE 'Federated%'
       ) AS federated_count,
       MAX(CASE
         WHEN resource_type = 'RoleInferred'
           AND binding_evidence->>'workloadType' IS NOT NULL
           AND binding_evidence->>'workloadType' != 'Unknown'
         THEN 1 ELSE 0
       END) AS has_known_workload,
       MAX(CASE
         WHEN binding_method = 'ReplyUrl'
           AND (resource_type = 'AppService' OR resource_type = 'ContainerApp')
         THEN 1 ELSE 0
       END) AS has_azure_reply_url
     FROM identity_lineage_bindings
     WHERE spn_id = $1`,
    [spnId]
  );

  const row = bindingResult.rows[0] ?? {};
  const hasHighConfidenceBinding = parseInt(row.high_conf_count ?? "0", 10) > 0;
  const hasFederatedBinding = parseInt(row.federated_count ?? "0", 10) > 0;
  const hasKnownWorkloadType = parseInt(row.has_known_workload ?? "0", 10) > 0;
  const hasAzureReplyUrl = parseInt(row.has_azure_reply_url ?? "0", 10) > 0;

  // Enrichment tier — check if P2_AUDIT exists for this SPN
  const enrichResult = await db.query(
    `SELECT 1 FROM identity_lineage_enrichment
     WHERE spn_id = $1 AND enrichment_tier = 'P2_AUDIT'
     LIMIT 1`,
    [spnId]
  );
  const hasFullEnrichment = enrichResult.rows.length > 0;

  // Owner check — from identities table (owner_count column)
  const ownerResult = await db.query(
    `SELECT COALESCE(owner_count, 0) AS owner_count
     FROM identities WHERE id = $1`,
    [spnId]
  );
  const hasOwner = parseInt(ownerResult.rows[0]?.owner_count ?? "0", 10) > 0;

  return {
    hasHighConfidenceBinding,
    hasFederatedBinding,
    hasKnownWorkloadType,
    hasAzureReplyUrl,
    hasFullEnrichment,
    hasOwner,
  };
}

// ── Score computation ───────────────────────────────────────────────

/**
 * Compute the lineage confidence score from gathered signals.
 * Pure function — testable without DB.
 */
export function computeScore(signals: ScoringSignals): number {
  let score = 0;
  if (signals.hasHighConfidenceBinding) score += 35;
  if (signals.hasFederatedBinding) score += 25;
  if (signals.hasKnownWorkloadType) score += 15;
  if (signals.hasAzureReplyUrl) score += 10;
  if (signals.hasFullEnrichment) score += 10;
  if (signals.hasOwner) score += 5;
  return Math.min(score, 100);
}

// ── Main entry point ────────────────────────────────────────────────

/**
 * Compute the lineage confidence score for an SPN.
 * All signals gathered from DB, no API calls.
 */
export async function computeLineageScore(
  db: Pool,
  spnId: string
): Promise<number> {
  const signals = await gatherScoringSignals(db, spnId);
  return computeScore(signals);
}

// ── Persistence ─────────────────────────────────────────────────────

/**
 * Upsert lineage score into identity_lineage_scores.
 * PK is spn_id — always one row per SPN.
 */
export async function persistLineageScore(
  db: Pool,
  spnId: string,
  score: number
): Promise<void> {
  await db.query(
    `INSERT INTO identity_lineage_scores (spn_id, lineage_score)
     VALUES ($1, $2)
     ON CONFLICT (spn_id) DO UPDATE SET
       lineage_score = EXCLUDED.lineage_score,
       scored_at     = NOW()`,
    [spnId, Math.min(Math.max(score, 0), 100)]
  );
}
