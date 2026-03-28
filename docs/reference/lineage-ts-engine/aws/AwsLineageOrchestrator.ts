/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * AwsLineageOrchestrator — full pipeline coordinator for AWS Identity Lineage.
 *
 * Pipeline (per AWS connection):
 *   1. Load connection credentials from cloud_connections
 *   2. Fetch account IDs from cloud_subscriptions
 *   3. Create SDK clients: IAMClient, ECSClient, EKSClient, SQSClient, SNSClient
 *   4. Detect enrichment tier (STATIC vs P2_AUDIT)
 *   5. Fetch AWS identities via tenant_or_org_id = ANY(accountIds)
 *   6. Clear EKS cluster cache
 *   7. Batch 50, parallel within each batch — per identity:
 *      a. TrustPolicyParser (SDK, roles only)
 *      b. LambdaRoleScanner (DB-only, fast)
 *      c. ECSTaskDefScanner (SDK)
 *      d. EKSWorkloadScanner (live K8s API)
 *      e. OIDCProviderMapper (SDK, roles only)
 *      f. ResourcePolicyScanner (DB: S3+KMS, SDK: SQS+SNS)
 *      g. computeLineageScore — P1 module, cloud-agnostic
 *      h. classifyAwsOrphanStatus — AWS-specific orphan engine
 *   8. Return AwsLineageScanSummary
 *
 * Error isolation: each module try/catch, errors collected in errors[].
 */

import { IAMClient } from "@aws-sdk/client-iam";
import { ECSClient } from "@aws-sdk/client-ecs";
import { EKSClient } from "@aws-sdk/client-eks";
import { SQSClient } from "@aws-sdk/client-sqs";
import { SNSClient } from "@aws-sdk/client-sns";
import type { Pool } from "pg";

import type {
  AwsConnectionRecord,
  AwsIdentityRecord,
  AwsScanError,
  AwsIdentityScanResult,
  AwsLineageScanSummary,
  EnrichmentTier,
} from "./types";

import { parseTrustPolicy, persistTrustBindings } from "./TrustPolicyParser";
import { scanLambdaForRole } from "./LambdaRoleScanner";
import { scanECSTaskDefs } from "./ECSTaskDefScanner";
import {
  scanEKSWorkloads,
  eksWorkloadToResourceBinding,
  clearClusterCache,
} from "./EKSWorkloadScanner";
import { mapOIDCProviders, persistOIDCMappings } from "./OIDCProviderMapper";
import {
  scanResourcePolicies,
  persistResourcePolicyBindings,
} from "./ResourcePolicyScanner";
import { detectAwsEnrichmentTier } from "./AwsEnrichmentTierProbe";
import {
  classifyAwsOrphanStatus,
  persistAwsOrphanClassification,
} from "./AwsOrphanDetectionEngine";
import { upsertBindings } from "./upsertBindings";

// P1 modules (cloud-agnostic)
import { computeLineageScore, persistLineageScore } from "../LineageConfidenceScorer";

// ── Constants ───────────────────────────────────────────────────────

const BATCH_SIZE = 50;

// ── Structured logging ──────────────────────────────────────────────

function logEvent(event: Record<string, unknown>): void {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), ...event }));
}

// ── Helpers ─────────────────────────────────────────────────────────

function batch<T>(items: T[], size: number): T[][] {
  const batches: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    batches.push(items.slice(i, i + size));
  }
  return batches;
}

/**
 * Load AWS connection credentials from cloud_connections.
 */
async function fetchAwsConnection(
  db: Pool,
  connectionId: number
): Promise<AwsConnectionRecord> {
  const { rows } = await db.query(
    `SELECT id, metadata
     FROM cloud_connections
     WHERE id = $1 AND cloud = 'aws' AND status = 'connected'`,
    [connectionId]
  );
  if (rows.length === 0) {
    throw new Error(`AWS connection ${connectionId} not found or not connected`);
  }
  const meta = rows[0].metadata ?? {};

  // Fetch account IDs from cloud_subscriptions
  const { rows: subRows } = await db.query(
    `SELECT subscription_id
     FROM cloud_subscriptions
     WHERE cloud_connection_id = $1 AND cloud = 'aws'`,
    [connectionId]
  );
  const accountIds = subRows.map(
    (r: { subscription_id: string }) => r.subscription_id
  );

  return {
    connectionId: String(rows[0].id),
    awsAccessKeyId: meta.aws_access_key_id ?? "",
    awsSecretAccessKey: meta.aws_secret_access_key ?? "",
    region: meta.region ?? "us-east-1",
    accountIds,
  };
}

/**
 * Fetch AWS identities using tenant_or_org_id = ANY(accountIds).
 */
async function fetchAwsIdentities(
  db: Pool,
  accountIds: string[]
): Promise<AwsIdentityRecord[]> {
  if (accountIds.length === 0) return [];

  const { rows } = await db.query(
    `SELECT i.id::text              AS "id",
            i.identity_id           AS "identityId",
            i.principal_id          AS "principalId",
            i.display_name          AS "displayName",
            i.identity_category     AS "identityCategory",
            COALESCE(i.is_federated, false) AS "isFederated",
            COALESCE(i.tags, '{}')  AS "tags"
     FROM identities i
     WHERE i.cloud = 'aws'
       AND i.tenant_or_org_id = ANY($1)
       AND i.deleted_at IS NULL
     ORDER BY i.id`,
    [accountIds]
  );
  return rows as AwsIdentityRecord[];
}

/**
 * Create AWS SDK clients with the connection credentials.
 * ECS, EKS, SQS, SNS clients may be null if credentials are insufficient.
 */
function createAwsClients(conn: AwsConnectionRecord): {
  iamClient: IAMClient;
  ecsClient: ECSClient | null;
  eksClient: EKSClient | null;
  sqsClient: SQSClient | null;
  snsClient: SNSClient | null;
} {
  const credentials = {
    accessKeyId: conn.awsAccessKeyId,
    secretAccessKey: conn.awsSecretAccessKey,
  };
  const region = conn.region;

  const iamClient = new IAMClient({ region, credentials });

  let ecsClient: ECSClient | null = null;
  let eksClient: EKSClient | null = null;
  let sqsClient: SQSClient | null = null;
  let snsClient: SNSClient | null = null;

  try {
    ecsClient = new ECSClient({ region, credentials });
  } catch {
    // ECS client creation failure — non-fatal
  }

  try {
    eksClient = new EKSClient({ region, credentials });
  } catch {
    // EKS client creation failure — non-fatal
  }

  try {
    sqsClient = new SQSClient({ region, credentials });
  } catch {
    // SQS client creation failure — non-fatal
  }

  try {
    snsClient = new SNSClient({ region, credentials });
  } catch {
    // SNS client creation failure — non-fatal
  }

  return { iamClient, ecsClient, eksClient, sqsClient, snsClient };
}

// ── Per-identity pipeline ───────────────────────────────────────────

async function scanSingleIdentity(
  db: Pool,
  connectionId: string,
  conn: AwsConnectionRecord,
  iamClient: IAMClient,
  ecsClient: ECSClient | null,
  eksClient: EKSClient | null,
  sqsClient: SQSClient | null,
  snsClient: SNSClient | null,
  identity: AwsIdentityRecord,
  accountId: string,
  errors: AwsScanError[]
): Promise<AwsIdentityScanResult> {
  const result: AwsIdentityScanResult = {
    bindingsFound: 0,
    orphanStatus: "UNKNOWN",
  };

  const roleArn = identity.principalId;

  // a. Trust policy parsing (SDK, roles only)
  try {
    const trustBindings = await parseTrustPolicy(iamClient, identity, accountId);
    if (trustBindings.length > 0) {
      await persistTrustBindings(db, identity.id, connectionId, trustBindings);
      result.bindingsFound += trustBindings.length;
    }
  } catch (err) {
    errors.push({
      spnId: identity.id,
      displayName: identity.displayName,
      module: "TrustPolicyParser",
      error: String(err),
    });
  }

  // b. Lambda role scanning (DB-only, fast path)
  try {
    const lambdaBindings = await scanLambdaForRole(db, roleArn, connectionId);
    if (lambdaBindings.length > 0) {
      await upsertBindings(db, connectionId, identity.id, lambdaBindings);
      result.bindingsFound += lambdaBindings.length;
    }
  } catch (err) {
    errors.push({
      spnId: identity.id,
      displayName: identity.displayName,
      module: "LambdaRoleScanner",
      error: String(err),
    });
  }

  // c. ECS task definition scanning (SDK, if client available)
  if (ecsClient) {
    try {
      const ecsBindings = await scanECSTaskDefs(
        ecsClient,
        roleArn,
        accountId,
        conn.region
      );
      if (ecsBindings.length > 0) {
        await upsertBindings(db, connectionId, identity.id, ecsBindings);
        result.bindingsFound += ecsBindings.length;
      }
    } catch (err) {
      errors.push({
        spnId: identity.id,
        displayName: identity.displayName,
        module: "ECSTaskDefScanner",
        error: String(err),
      });
    }
  }

  // d. EKS workload scanning (live K8s API, if EKS client available)
  if (eksClient) {
    try {
      const eksBindings = await scanEKSWorkloads(
        roleArn,
        eksClient,
        conn.region
      );
      if (eksBindings.length > 0) {
        const resourceBindings = eksBindings.map(eksWorkloadToResourceBinding);
        await upsertBindings(db, connectionId, identity.id, resourceBindings);
        result.bindingsFound += eksBindings.length;
      }
    } catch (err) {
      errors.push({
        spnId: identity.id,
        displayName: identity.displayName,
        module: "EKSWorkloadScanner",
        error: String(err),
      });
    }
  }

  // e. OIDC provider mapping (SDK, roles only)
  if (identity.identityCategory !== "iam_user") {
    try {
      const oidcMappings = await mapOIDCProviders(roleArn, iamClient);
      if (oidcMappings.length > 0) {
        await persistOIDCMappings(
          db,
          identity.id,
          connectionId,
          oidcMappings,
          accountId
        );
        result.bindingsFound += oidcMappings.length;
      }
    } catch (err) {
      errors.push({
        spnId: identity.id,
        displayName: identity.displayName,
        module: "OIDCProviderMapper",
        error: String(err),
      });
    }
  }

  // f. Resource policy scanning (DB: S3+KMS, SDK: SQS+SNS)
  if (sqsClient && snsClient) {
    try {
      const rpRefs = await scanResourcePolicies(
        roleArn,
        accountId,
        db,
        sqsClient,
        snsClient,
        conn.region
      );
      if (rpRefs.length > 0) {
        await persistResourcePolicyBindings(
          db,
          identity.id,
          connectionId,
          rpRefs
        );
        result.bindingsFound += rpRefs.length;
      }
    } catch (err) {
      errors.push({
        spnId: identity.id,
        displayName: identity.displayName,
        module: "ResourcePolicyScanner",
        error: String(err),
      });
    }
  }

  // g. Lineage confidence score (reads from DB — must run after a–f persist)
  try {
    const score = await computeLineageScore(db, identity.id);
    await persistLineageScore(db, identity.id, score);
  } catch (err) {
    errors.push({
      spnId: identity.id,
      displayName: identity.displayName,
      module: "LineageConfidenceScorer",
      error: String(err),
    });
  }

  // h. AWS orphan classification (DB + IAM RoleLastUsed — must run after a–f persist)
  try {
    const classification = await classifyAwsOrphanStatus(
      identity.id,
      roleArn,
      db,
      iamClient
    );
    await persistAwsOrphanClassification(db, connectionId, classification);
    result.orphanStatus = classification.orphanStatus;
  } catch (err) {
    errors.push({
      spnId: identity.id,
      displayName: identity.displayName,
      module: "AwsOrphanDetectionEngine",
      error: String(err),
    });
  }

  return result;
}

// ── Public entry point ──────────────────────────────────────────────

/**
 * Run the full AWS identity lineage pipeline for every identity in a connection.
 *
 * Steps:
 *   1. Fetch connection credentials + account IDs
 *   2. Create SDK clients (IAM, ECS, EKS, SQS, SNS)
 *   3. Detect enrichment tier (STATIC or P2_AUDIT)
 *   4. Load all AWS identities via tenant_or_org_id = ANY(accountIds)
 *   5. Clear EKS cluster cache (fresh scan)
 *   6. Batch into groups of 50, run full pipeline per identity
 *   7. Return AwsLineageScanSummary
 */
export async function runAwsLineageScan(
  connectionId: number,
  db: Pool
): Promise<AwsLineageScanSummary> {
  const startMs = Date.now();
  const connIdStr = String(connectionId);

  // 1. Load connection
  const conn = await fetchAwsConnection(db, connectionId);
  if (conn.accountIds.length === 0) {
    logEvent({
      event: "aws_lineage_scan_skip",
      connectionId,
      reason: "no account IDs",
    });
    return {
      connectionId,
      accountsScanned: 0,
      identitiesScanned: 0,
      bindingsFound: 0,
      orphansFound: { safeToRetire: 0, caution: 0, blocked: 0 },
      enrichmentTier: "STATIC",
      durationMs: Date.now() - startMs,
      completedAt: new Date().toISOString(),
      errors: [],
    };
  }

  // 2. Create SDK clients
  const { iamClient, ecsClient, eksClient, sqsClient, snsClient } =
    createAwsClients(conn);
  const primaryAccountId = conn.accountIds[0];

  // 3. Detect enrichment tier
  let enrichmentTier: EnrichmentTier = "STATIC";
  try {
    enrichmentTier = await detectAwsEnrichmentTier(db, connIdStr);
  } catch (err) {
    logEvent({
      event: "aws_lineage_tier_error",
      connectionId,
      error: String(err),
    });
  }

  // 4. Fetch identities via tenant_or_org_id = ANY(accountIds)
  const identities = await fetchAwsIdentities(db, conn.accountIds);

  logEvent({
    event: "aws_lineage_scan_start",
    connectionId,
    identityCount: identities.length,
    accountCount: conn.accountIds.length,
    enrichmentTier,
  });

  if (identities.length === 0) {
    return {
      connectionId,
      accountsScanned: conn.accountIds.length,
      identitiesScanned: 0,
      bindingsFound: 0,
      orphansFound: { safeToRetire: 0, caution: 0, blocked: 0 },
      enrichmentTier,
      durationMs: Date.now() - startMs,
      completedAt: new Date().toISOString(),
      errors: [],
    };
  }

  // 5. Clear EKS cluster cache for a fresh scan
  clearClusterCache();

  // 6. Batch and scan
  const identityBatches = batch(identities, BATCH_SIZE);
  const errors: AwsScanError[] = [];
  let totalBindings = 0;
  const orphanCounts = { safeToRetire: 0, caution: 0, blocked: 0 };
  let scanned = 0;

  for (const identityBatch of identityBatches) {
    const results = await Promise.all(
      identityBatch.map((identity) =>
        scanSingleIdentity(
          db,
          connIdStr,
          conn,
          iamClient,
          ecsClient,
          eksClient,
          sqsClient,
          snsClient,
          identity,
          primaryAccountId,
          errors
        )
      )
    );

    for (const r of results) {
      totalBindings += r.bindingsFound;
      if (r.orphanStatus === "SAFE_TO_RETIRE") orphanCounts.safeToRetire++;
      else if (r.orphanStatus === "CAUTION") orphanCounts.caution++;
      else if (r.orphanStatus === "BLOCKED") orphanCounts.blocked++;
    }

    scanned += identityBatch.length;
    logEvent({
      event: "aws_lineage_scan_progress",
      connectionId,
      scanned,
      total: identities.length,
    });
  }

  // 7. Build summary
  const summary: AwsLineageScanSummary = {
    connectionId,
    accountsScanned: conn.accountIds.length,
    identitiesScanned: scanned,
    bindingsFound: totalBindings,
    orphansFound: orphanCounts,
    enrichmentTier,
    durationMs: Date.now() - startMs,
    completedAt: new Date().toISOString(),
    errors,
  };

  logEvent({
    event: "aws_lineage_scan_complete",
    connectionId,
    identitiesScanned: summary.identitiesScanned,
    bindingsFound: summary.bindingsFound,
    orphansFound: summary.orphansFound,
    errorCount: summary.errors.length,
    durationMs: summary.durationMs,
  });

  return summary;
}
