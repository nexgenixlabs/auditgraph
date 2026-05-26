/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * AwsEnrichmentTierProbe — DB-only probe that detects the enrichment tier
 * for an AWS connection by checking for CloudTrail events.
 *
 * AWS enrichment tiers:
 *   STATIC    — no CloudTrail data ingested
 *   P2_AUDIT  — CloudTrail events present (audit log signals available)
 *
 * P1_SIGNIN and FULL are Azure-specific; AWS goes STATIC → P2_AUDIT directly.
 *
 * Result is cached in cloud_connections.metadata.enrichment_tier (same
 * pattern as the Azure EnrichmentTierProbe).
 */

import type { Pool } from "pg";
import type { EnrichmentTier } from "./types";

// ── Core probe ──────────────────────────────────────────────────────

/**
 * Detect the AWS enrichment tier for a connection.
 * Checks if any CloudTrail events exist for this connection.
 */
export async function detectAwsEnrichmentTier(
  db: Pool,
  connectionId: string
): Promise<EnrichmentTier> {
  // Check cache first
  const cached = await getCachedTier(db, connectionId);
  if (cached) return cached;

  let tier: EnrichmentTier = "STATIC";

  try {
    const { rows } = await db.query(
      `SELECT 1 FROM aws_cloudtrail_events
       WHERE cloud_connection_id = $1
       LIMIT 1`,
      [connectionId]
    );
    if (rows.length > 0) {
      tier = "P2_AUDIT";
    }
  } catch {
    // Table may not exist or query may fail — default to STATIC
  }

  // Cache the result
  await cacheTier(db, connectionId, tier);

  return tier;
}

// ── Cache helpers (same pattern as P1 Azure probe) ──────────────────

async function getCachedTier(
  db: Pool,
  connectionId: string
): Promise<EnrichmentTier | null> {
  try {
    const result = await db.query(
      `SELECT metadata->'enrichment_tier' AS tier
       FROM cloud_connections
       WHERE id = $1`,
      [connectionId]
    );
    const tier = result.rows[0]?.tier;
    if (tier === "STATIC" || tier === "P2_AUDIT") {
      return tier as EnrichmentTier;
    }
    return null;
  } catch {
    return null;
  }
}

async function cacheTier(
  db: Pool,
  connectionId: string,
  tier: EnrichmentTier
): Promise<void> {
  try {
    await db.query(
      `UPDATE cloud_connections
       SET metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('enrichment_tier', $2)
       WHERE id = $1`,
      [connectionId, tier]
    );
  } catch {
    // Non-fatal — cache miss just means we probe again next time
  }
}

/**
 * Invalidate the cached enrichment tier for an AWS connection.
 */
export async function invalidateAwsTierCache(
  db: Pool,
  connectionId: string
): Promise<void> {
  try {
    await db.query(
      `UPDATE cloud_connections
       SET metadata = metadata - 'enrichment_tier'
       WHERE id = $1`,
      [connectionId]
    );
  } catch {
    // Non-fatal
  }
}
