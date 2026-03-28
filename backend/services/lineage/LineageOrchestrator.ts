/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * LineageOrchestrator — full pipeline coordinator for Identity Lineage Engine.
 *
 * Pipeline (per connection):
 *   1. Load SPNs (non-Microsoft, non-deleted) from identities table
 *   2. detectEnrichmentTier (connection-level, cached)
 *   3. Per SPN in batches of 50, parallel within each batch:
 *      a. scanResourcesForSPN        — Resource Graph static bindings
 *      b. getFederatedMappings        — Federated credential parsing
 *      c. inferRoleTopology           — RBAC classification
 *      d. getAppRegistrationMetadata  — Reply URL inference
 *      e. enrichSignInActivity        — Sign-in type + dormancy
 *      f. computeLineageScore         — Additive 0-100 scoring
 *      g. classifyOrphanStatus        — 5-level orphan classification
 *   4. Return LineageScanSummary
 *
 * Error isolation: a single SPN failure never aborts the full scan.
 */

import { DefaultAzureCredential, type TokenCredential } from "@azure/identity";
import { Client } from "@microsoft/microsoft-graph-client";
import type { Pool } from "pg";

import { scanResourcesForSPN, type ResourceBinding } from "./ResourceGraphScanner";
import {
  getFederatedMappings,
  persistFederatedBindings,
  type FederatedMapping,
} from "./FederatedCredentialMapper";
import {
  inferRoleTopology,
  persistRoleTopology,
  type RoleTopology,
} from "./RoleTopologyInferrer";
import {
  getAppRegistrationMetadata,
  persistAppRegistrationBindings,
  type AppRegistrationMetadata,
} from "./AppRegistrationMiner";
import {
  enrichSignInActivity,
  persistSignInEnrichment,
  type SignInEnrichment,
} from "./SignInActivityEnricher";
import {
  computeLineageScore,
  persistLineageScore,
} from "./LineageConfidenceScorer";
import {
  classifyOrphanStatus,
  persistOrphanClassification,
  type OrphanClassification,
} from "./OrphanDetectionEngine";
import {
  detectEnrichmentTier,
  type EnrichmentTier,
} from "./EnrichmentTierProbe";

// ── Constants ───────────────────────────────────────────────────────

const SPN_BATCH_SIZE = 50;

// ── Types ───────────────────────────────────────────────────────────

interface SPNRecord {
  id: string;          // identities.id (bigint as string from pg)
  clientId: string;    // identities.app_id or identity_id
  objectId: string;    // identities.identity_id (Azure object_id)
  displayName: string;
}

interface ConnectionRecord {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  subscriptionIds: string[];
}

interface ScanError {
  spnId: string;
  displayName: string;
  module: string;
  error: string;
}

export interface LineageScanSummary {
  connectionId: string;
  spnsScanned: number;
  bindingsFound: number;
  federatedFound: number;
  orphansFound: {
    safeToRetire: number;
    caution: number;
    blocked: number;
  };
  enrichmentTier: EnrichmentTier;
  scanErrors: ScanError[];
  durationMs: number;
  completedAt: string;
}

// ── Structured logging ─────────────────────────────────────────────

function logEvent(event: Record<string, unknown>): void {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), ...event }));
}

// ── Helpers ─────────────────────────────────────────────────────────

async function fetchConnection(
  db: Pool,
  connectionId: string
): Promise<ConnectionRecord> {
  const { rows } = await db.query(
    `SELECT azure_directory_id AS "tenantId",
            client_id          AS "clientId",
            metadata
     FROM cloud_connections
     WHERE id = $1 AND status = 'connected'`,
    [connectionId]
  );
  if (rows.length === 0) {
    throw new Error(`Connection ${connectionId} not found or not connected`);
  }
  const row = rows[0];
  const meta = row.metadata ?? {};
  return {
    tenantId: row.tenantId,
    clientId: row.clientId,
    clientSecret: meta.client_secret ?? "",
    subscriptionIds: meta.subscription_ids ?? [],
  };
}

async function fetchSPNs(
  db: Pool,
  connectionId: string
): Promise<SPNRecord[]> {
  const { rows } = await db.query(
    `SELECT i.id::text                          AS "id",
            COALESCE(i.app_id, i.identity_id)   AS "clientId",
            i.identity_id                        AS "objectId",
            i.display_name                       AS "displayName"
     FROM identities i
     JOIN discovery_runs dr ON dr.id = i.discovery_run_id
     WHERE dr.cloud_connection_id = $1
       AND i.identity_category IN ('service_principal', 'managed_identity_user', 'managed_identity_system')
       AND i.deleted_at IS NULL
       AND NOT COALESCE(i.is_microsoft_system, false)
     ORDER BY i.id`,
    [connectionId]
  );
  return rows as SPNRecord[];
}

/**
 * Upsert a batch of resource bindings into identity_lineage_bindings.
 */
async function upsertBindings(
  db: Pool,
  connectionId: string,
  spnId: string,
  bindings: ResourceBinding[]
): Promise<void> {
  if (bindings.length === 0) return;

  const values: unknown[] = [];
  const placeholders: string[] = [];
  let idx = 1;

  for (const b of bindings) {
    placeholders.push(
      `($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++})`
    );
    values.push(
      spnId,
      connectionId,
      b.resourceId,
      b.resourceType,
      b.resourceName,
      b.resourceGroup,
      b.region,
      b.bindingMethod,
      JSON.stringify(b.bindingEvidence),
      b.confidenceScore
    );
  }

  await db.query(
    `INSERT INTO identity_lineage_bindings
       (spn_id, connection_id, resource_id, resource_type, resource_name,
        resource_group, region, binding_method, binding_evidence, confidence_score)
     VALUES ${placeholders.join(", ")}
     ON CONFLICT (spn_id, resource_id, binding_method) DO UPDATE SET
       resource_type    = EXCLUDED.resource_type,
       resource_name    = EXCLUDED.resource_name,
       resource_group   = EXCLUDED.resource_group,
       region           = EXCLUDED.region,
       binding_evidence = EXCLUDED.binding_evidence,
       confidence_score = EXCLUDED.confidence_score,
       last_verified_at = NOW()`,
    values
  );
}

function batch<T>(items: T[], size: number): T[][] {
  const batches: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    batches.push(items.slice(i, i + size));
  }
  return batches;
}

/**
 * Create an MS Graph client from a TokenCredential.
 * Uses the Graph SDK's built-in auth provider pattern.
 */
function createGraphClient(credential: TokenCredential): Client {
  return Client.initWithMiddleware({
    authProvider: {
      getAccessToken: async () => {
        const tokenResponse = await credential.getToken(
          "https://graph.microsoft.com/.default"
        );
        return tokenResponse?.token ?? "";
      },
    },
  });
}

// ── Per-SPN pipeline ───────────────────────────────────────────────

interface SPNScanResult {
  bindingsFound: number;
  federatedFound: number;
  orphanStatus: string;
}

/**
 * Run the full lineage pipeline for a single SPN.
 *
 * Each sub-module failure is caught individually — a failed federated
 * lookup doesn't prevent resource scanning, role topology, etc.
 */
async function scanSingleSPN(
  db: Pool,
  connectionId: string,
  conn: ConnectionRecord,
  credential: TokenCredential,
  graphClient: Client,
  spn: SPNRecord,
  enrichmentTier: EnrichmentTier,
  scanErrors: ScanError[]
): Promise<SPNScanResult> {
  const result: SPNScanResult = {
    bindingsFound: 0,
    federatedFound: 0,
    orphanStatus: "UNKNOWN",
  };

  // a. Resource Graph scanning
  try {
    const bindings = await scanResourcesForSPN(
      spn.clientId,
      conn.subscriptionIds,
      credential
    );
    await upsertBindings(db, connectionId, spn.id, bindings);
    result.bindingsFound = bindings.length;
  } catch (err) {
    scanErrors.push({
      spnId: spn.id,
      displayName: spn.displayName,
      module: "ResourceGraphScanner",
      error: String(err),
    });
    logEvent({
      event: "lineage_scan_error",
      connectionId,
      spnId: spn.id,
      module: "ResourceGraphScanner",
      error: String(err),
    });
  }

  // b. Federated credential mappings
  try {
    const mappings: FederatedMapping[] = await getFederatedMappings(
      spn.objectId,
      graphClient
    );
    if (mappings.length > 0) {
      await persistFederatedBindings(db, spn.id, connectionId, mappings);
    }
    result.federatedFound = mappings.length;
  } catch (err) {
    scanErrors.push({
      spnId: spn.id,
      displayName: spn.displayName,
      module: "FederatedCredentialMapper",
      error: String(err),
    });
    logEvent({
      event: "lineage_scan_error",
      connectionId,
      spnId: spn.id,
      module: "FederatedCredentialMapper",
      error: String(err),
    });
  }

  // c. Role topology inference (use first subscription)
  const subscriptionId = conn.subscriptionIds[0] ?? "";
  if (subscriptionId) {
    try {
      const topology: RoleTopology = await inferRoleTopology(
        spn.objectId,
        subscriptionId,
        credential
      );
      await persistRoleTopology(
        db,
        spn.id,
        connectionId,
        subscriptionId,
        spn.objectId,
        topology
      );
    } catch (err) {
      scanErrors.push({
        spnId: spn.id,
        displayName: spn.displayName,
        module: "RoleTopologyInferrer",
        error: String(err),
      });
      logEvent({
        event: "lineage_scan_error",
        connectionId,
        spnId: spn.id,
        module: "RoleTopologyInferrer",
        error: String(err),
      });
    }
  }

  // d. App registration mining (uses clientId to look up app via Graph)
  try {
    // Resolve app objectId from clientId (appId) via Graph
    const metadata: AppRegistrationMetadata | null =
      await getAppRegistrationMetadata(spn.objectId, graphClient);
    if (metadata) {
      await persistAppRegistrationBindings(db, spn.id, connectionId, metadata);
    }
  } catch (err) {
    scanErrors.push({
      spnId: spn.id,
      displayName: spn.displayName,
      module: "AppRegistrationMiner",
      error: String(err),
    });
    logEvent({
      event: "lineage_scan_error",
      connectionId,
      spnId: spn.id,
      module: "AppRegistrationMiner",
      error: String(err),
    });
  }

  // e. Sign-in activity enrichment
  try {
    const enrichment: SignInEnrichment = await enrichSignInActivity(
      spn.objectId,
      graphClient
    );
    await persistSignInEnrichment(db, spn.id, connectionId, enrichment);
  } catch (err) {
    scanErrors.push({
      spnId: spn.id,
      displayName: spn.displayName,
      module: "SignInActivityEnricher",
      error: String(err),
    });
    logEvent({
      event: "lineage_scan_error",
      connectionId,
      spnId: spn.id,
      module: "SignInActivityEnricher",
      error: String(err),
    });
  }

  // f. Lineage confidence score (reads from DB — must run after a–e persist)
  try {
    const score = await computeLineageScore(db, spn.id);
    await persistLineageScore(db, spn.id, score);
  } catch (err) {
    scanErrors.push({
      spnId: spn.id,
      displayName: spn.displayName,
      module: "LineageConfidenceScorer",
      error: String(err),
    });
    logEvent({
      event: "lineage_scan_error",
      connectionId,
      spnId: spn.id,
      module: "LineageConfidenceScorer",
      error: String(err),
    });
  }

  // g. Orphan classification (reads from DB — must run after a–e persist)
  try {
    const classification: OrphanClassification = await classifyOrphanStatus(
      db,
      spn.id
    );
    await persistOrphanClassification(db, connectionId, classification);
    result.orphanStatus = classification.orphanStatus;
  } catch (err) {
    scanErrors.push({
      spnId: spn.id,
      displayName: spn.displayName,
      module: "OrphanDetectionEngine",
      error: String(err),
    });
    logEvent({
      event: "lineage_scan_error",
      connectionId,
      spnId: spn.id,
      module: "OrphanDetectionEngine",
      error: String(err),
    });
  }

  return result;
}

// ── Public entry point ──────────────────────────────────────────────

/**
 * Run the full identity lineage pipeline for every SPN in a connection.
 *
 * Steps:
 *   1. Fetch connection credentials + subscription list
 *   2. Detect enrichment tier (STATIC / P1_SIGNIN / P2_AUDIT)
 *   3. Load all non-Microsoft SPNs for the connection
 *   4. Batch into groups of 50, run full pipeline per SPN
 *   5. Return aggregated summary
 *
 * Error isolation: individual SPN failures are logged and collected
 * in scanErrors[] but never abort the scan.
 */
export async function runFullLineageScan(
  db: Pool,
  connectionId: string
): Promise<LineageScanSummary> {
  const startMs = Date.now();

  // 1. Load connection
  const conn = await fetchConnection(db, connectionId);
  if (conn.subscriptionIds.length === 0) {
    logEvent({
      event: "lineage_scan_start",
      connectionId,
      spnCount: 0,
      note: "no subscriptions — skipping",
    });
    return {
      connectionId,
      spnsScanned: 0,
      bindingsFound: 0,
      federatedFound: 0,
      orphansFound: { safeToRetire: 0, caution: 0, blocked: 0 },
      enrichmentTier: "STATIC",
      scanErrors: [],
      durationMs: Date.now() - startMs,
      completedAt: new Date().toISOString(),
    };
  }

  const credential = new DefaultAzureCredential({
    tenantId: conn.tenantId,
  });
  const graphClient = createGraphClient(credential);

  // 2. Detect enrichment tier (connection-level, cached)
  let enrichmentTier: EnrichmentTier = "STATIC";
  try {
    enrichmentTier = await detectEnrichmentTier(
      db,
      connectionId,
      conn.subscriptionIds[0],
      credential
    );
  } catch (err) {
    logEvent({
      event: "lineage_scan_error",
      connectionId,
      spnId: null,
      module: "EnrichmentTierProbe",
      error: String(err),
    });
    // Fall back to STATIC — scan still proceeds
  }

  // 3. Load SPNs
  const spns = await fetchSPNs(db, connectionId);

  logEvent({
    event: "lineage_scan_start",
    connectionId,
    spnCount: spns.length,
    enrichmentTier,
  });

  if (spns.length === 0) {
    return {
      connectionId,
      spnsScanned: 0,
      bindingsFound: 0,
      federatedFound: 0,
      orphansFound: { safeToRetire: 0, caution: 0, blocked: 0 },
      enrichmentTier,
      scanErrors: [],
      durationMs: Date.now() - startMs,
      completedAt: new Date().toISOString(),
    };
  }

  // 4. Batch and scan
  const spnBatches = batch(spns, SPN_BATCH_SIZE);
  const scanErrors: ScanError[] = [];
  let totalBindings = 0;
  let totalFederated = 0;
  let orphanCounts = { safeToRetire: 0, caution: 0, blocked: 0 };
  let scanned = 0;

  for (const spnBatch of spnBatches) {
    const results = await Promise.all(
      spnBatch.map((spn) =>
        scanSingleSPN(
          db,
          connectionId,
          conn,
          credential,
          graphClient,
          spn,
          enrichmentTier,
          scanErrors
        )
      )
    );

    for (const r of results) {
      totalBindings += r.bindingsFound;
      totalFederated += r.federatedFound;
      if (r.orphanStatus === "SAFE_TO_RETIRE") orphanCounts.safeToRetire++;
      else if (r.orphanStatus === "CAUTION") orphanCounts.caution++;
      else if (r.orphanStatus === "BLOCKED") orphanCounts.blocked++;
    }

    scanned += spnBatch.length;
    if (scanned % 50 === 0 || scanned === spns.length) {
      logEvent({
        event: "lineage_scan_progress",
        connectionId,
        scanned,
        total: spns.length,
      });
    }
  }

  // 5. Build summary
  const summary: LineageScanSummary = {
    connectionId,
    spnsScanned: scanned,
    bindingsFound: totalBindings,
    federatedFound: totalFederated,
    orphansFound: orphanCounts,
    enrichmentTier,
    scanErrors,
    durationMs: Date.now() - startMs,
    completedAt: new Date().toISOString(),
  };

  logEvent({
    event: "lineage_scan_complete",
    connectionId,
    ...summary,
    scanErrors: summary.scanErrors.length, // log count, not full array
  });

  return summary;
}

// ── Legacy alias (keep existing callers working) ────────────────────

/**
 * @deprecated Use `runFullLineageScan` instead. This legacy wrapper
 * maintains backward compatibility with Sprint-1 callers.
 */
export async function runLineageScan(
  db: Pool,
  connectionId: string
): Promise<void> {
  await runFullLineageScan(db, connectionId);
}
