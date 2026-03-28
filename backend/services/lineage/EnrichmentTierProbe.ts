/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * EnrichmentTierProbe — detects the available enrichment tier for a connection
 * by probing the Azure Log Analytics workspace for sign-in log data.
 *
 * Tier hierarchy (CHECK constraint on identity_lineage_enrichment):
 *   STATIC    — no Log Analytics workspace (Resource Graph + ARM only)
 *   P1_SIGNIN — Log Analytics workspace exists but no SP sign-in log data
 *   P2_AUDIT  — cloud audit log signals (CloudTrail / GCP) without Azure LA
 *   FULL      — Log Analytics workspace with SP sign-in log data
 *
 * Return mapping for this Azure-specific probe:
 *   No Log Analytics workspace      → STATIC
 *   Workspace exists, no SP logs    → P1_SIGNIN
 *   Workspace exists with SP logs   → FULL
 *
 * P2_AUDIT is set by non-Azure enrichment paths (CloudTrail, GCP Audit).
 *
 * Result is cached in cloud_connections.metadata.enrichment_tier.
 */

import type { TokenCredential } from "@azure/identity";
import type { Pool } from "pg";

// ── Public types ────────────────────────────────────────────────────

export type EnrichmentTier = "STATIC" | "P1_SIGNIN" | "P2_AUDIT" | "FULL";

// ── ARM API helpers ─────────────────────────────────────────────────

interface WorkspaceListResponse {
  value: Array<{
    id: string;
    name: string;
    properties: { customerId: string };
  }>;
}

interface LogQueryResponse {
  tables?: Array<{
    rows?: unknown[][];
  }>;
}

async function fetchJson<T>(
  url: string,
  token: string,
  method = "GET",
  body?: object
): Promise<T | null> {
  try {
    const resp = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (!resp.ok) return null;
    return (await resp.json()) as T;
  } catch {
    return null;
  }
}

// ── Core probe logic ────────────────────────────────────────────────

/**
 * Detect the enrichment tier available for a connection.
 *
 * 1. Default: P1_SIGNIN (servicePrincipalSignInActivity always assumed available)
 * 2. List Log Analytics workspaces in the subscription
 * 3. If workspace found: POST test KQL query for AADServicePrincipalSignInLogs
 *    - Success + data → P2_AUDIT
 *    - Success + no data → P1_SIGNIN
 *    - Error → P1_SIGNIN
 * 4. Cache result in cloud_connections.metadata
 */
export async function detectEnrichmentTier(
  db: Pool,
  connectionId: string,
  subscriptionId: string,
  credential: TokenCredential
): Promise<EnrichmentTier> {
  // Check cache first
  const cached = await getCachedTier(db, connectionId);
  if (cached) return cached;

  // Default is STATIC — no Log Analytics workspace available
  let tier: EnrichmentTier = "STATIC";

  if (subscriptionId) {
    tier = await probeLogAnalytics(subscriptionId, credential);
  }

  // Cache the result
  await cacheTier(db, connectionId, tier);

  return tier;
}

async function probeLogAnalytics(
  subscriptionId: string,
  credential: TokenCredential
): Promise<EnrichmentTier> {
  const token = await credential.getToken("https://management.azure.com/.default");
  if (!token) return "STATIC";

  // Step 2: List Log Analytics workspaces
  const workspaces = await fetchJson<WorkspaceListResponse>(
    `https://management.azure.com/subscriptions/${subscriptionId}` +
      `/providers/Microsoft.OperationalInsights/workspaces?api-version=2023-09-01`,
    token.token
  );

  if (!workspaces?.value?.length) return "STATIC";

  // Step 3: Probe first workspace with test KQL
  const workspace = workspaces.value[0];
  const workspaceId = workspace.properties?.customerId ?? workspace.id;

  const logToken = await credential.getToken("https://api.loganalytics.io/.default");
  if (!logToken) return "P1_SIGNIN";

  const queryResult = await fetchJson<LogQueryResponse>(
    `https://api.loganalytics.io/v1/workspaces/${workspaceId}/query`,
    logToken.token,
    "POST",
    { query: "AADServicePrincipalSignInLogs | limit 1" }
  );

  if (!queryResult) return "P1_SIGNIN";

  const hasData = (queryResult.tables?.[0]?.rows?.length ?? 0) > 0;
  return hasData ? "FULL" : "P1_SIGNIN";
}

// ── Cache helpers ───────────────────────────────────────────────────

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
    if (tier === "STATIC" || tier === "P1_SIGNIN" || tier === "P2_AUDIT" || tier === "FULL") {
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
 * Invalidate the cached enrichment tier for a connection.
 * Called when a connection's configuration changes.
 */
export async function invalidateTierCache(
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
