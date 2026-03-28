/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * RoleTopologyInferrer — classifies an SPN's workload type by analyzing its
 * RBAC role assignment pattern across ARM scopes.
 *
 * Calls the ARM Role Assignments API filtered by principalId, then applies
 * a first-match rule set to produce a workload classification with confidence.
 *
 * Produces one "RoleInferred" row in identity_lineage_bindings per SPN.
 */

import type { TokenCredential } from "@azure/identity";
import type { Pool } from "pg";

// ── Public types ────────────────────────────────────────────────────

export interface RoleAssignment {
  roleDefinitionName: string;
  scope: string;
}

export interface RoleTopology {
  workloadType: string;
  confidenceScore: number;
  matchedRule: string;
  roleAssignments: RoleAssignment[];
  topResources: string[];
}

// ── ARM API response types ──────────────────────────────────────────

interface ARMRoleAssignment {
  id: string;
  properties: {
    roleDefinitionId: string;
    principalId: string;
    scope: string;
    expandedProperties?: {
      roleDefinition?: {
        displayName?: string;
      };
    };
  };
}

interface ARMRoleAssignmentListResponse {
  value: ARMRoleAssignment[];
  nextLink?: string;
}

// ── Constants ───────────────────────────────────────────────────────

const MAX_RETRIES = 3;
const BASE_BACKOFF_MS = 1_000;
const ARM_API_VERSION = "2022-04-01";

// ── Role name sets (lowercased for comparison) ──────────────────────

const ACR_PULL_ROLES = new Set(["acrpull", "acr pull", "acrreader", "acr reader"]);

const KV_STORAGE_ROLES = new Set([
  "key vault secrets user",
  "storage blob data reader",
  "storage blob data contributor",
]);

const QUEUE_SERVERLESS_ROLES = new Set([
  "storage queue data message processor",
  "storage blob data owner",
  "service bus data receiver",
]);

const BROAD_INFRA_ROLES = new Set(["contributor", "owner"]);

const DB_ROLES = new Set([
  "sql db contributor",
  "cosmos db account reader role",
  "cosmos db account reader",
  "documentdb account contributor",
]);

const STORAGE_BLOB_CONTRIBUTOR = "storage blob data contributor";

const DATA_PIPELINE_PLUS_ROLES = new Set([
  "azure event hubs data sender",
  "azure event hubs data receiver",
  "eventhubs data sender",
  "eventhubs data receiver",
  "data factory contributor",
  "azure data factory contributor",
]);

const READER_ONLY_ROLES = new Set([
  "reader",
  "monitoring reader",
  "log analytics reader",
  "log analytics contributor",
  "monitoring contributor",
]);

// ── ARM API helpers ─────────────────────────────────────────────────

function is429(err: unknown): boolean {
  if (typeof err === "object" && err !== null) {
    const e = err as Record<string, unknown>;
    return e.statusCode === 429 || e.status === 429;
  }
  return false;
}

function extractRetryAfter(err: unknown): number | null {
  if (typeof err === "object" && err !== null) {
    const headers = (err as { response?: { headers?: Record<string, string> } })
      .response?.headers;
    const raw = headers?.["retry-after"] ?? headers?.["Retry-After"];
    if (raw) {
      const seconds = parseInt(raw, 10);
      if (!Number.isNaN(seconds)) return seconds * 1_000;
    }
  }
  return null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetch all role assignments for a principalId in a subscription.
 * Handles pagination (nextLink) and 429 retry with exponential backoff.
 */
export async function fetchRoleAssignments(
  objectId: string,
  subscriptionId: string,
  credential: TokenCredential
): Promise<RoleAssignment[]> {
  const token = await credential.getToken("https://management.azure.com/.default");
  if (!token) throw new Error("Failed to acquire ARM token");

  const assignments: RoleAssignment[] = [];
  let url: string | null =
    `https://management.azure.com/subscriptions/${subscriptionId}` +
    `/providers/Microsoft.Authorization/roleAssignments` +
    `?$filter=principalId eq '${objectId}'` +
    `&$expand=roleDefinition` +
    `&api-version=${ARM_API_VERSION}`;

  while (url) {
    const body = await fetchWithRetry(url, token.token);
    for (const ra of body.value) {
      const name =
        ra.properties.expandedProperties?.roleDefinition?.displayName ??
        ra.properties.roleDefinitionId.split("/").pop() ??
        "Unknown";
      assignments.push({
        roleDefinitionName: name,
        scope: ra.properties.scope,
      });
    }
    url = body.nextLink ?? null;
  }

  return assignments;
}

async function fetchWithRetry(
  url: string,
  bearerToken: string
): Promise<ARMRoleAssignmentListResponse> {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    const resp = await fetch(url, {
      headers: { Authorization: `Bearer ${bearerToken}` },
    });

    if (resp.status === 429 && attempt < MAX_RETRIES) {
      const retryAfter =
        parseInt(resp.headers.get("retry-after") ?? "", 10) * 1_000;
      const backoff = Number.isNaN(retryAfter)
        ? BASE_BACKOFF_MS * 2 ** (attempt - 1)
        : retryAfter;
      console.warn(
        `[RoleTopologyInferrer] 429, retry ${attempt}/${MAX_RETRIES} after ${backoff}ms`
      );
      await sleep(backoff);
      continue;
    }

    if (!resp.ok) {
      throw Object.assign(new Error(`ARM API ${resp.status}: ${resp.statusText}`), {
        statusCode: resp.status,
      });
    }

    return (await resp.json()) as ARMRoleAssignmentListResponse;
  }

  /* istanbul ignore next */
  throw new Error("Exhausted retries");
}

// ── Classification engine ───────────────────────────────────────────

/**
 * Extract the last segment of an ARM scope as a human-readable resource name.
 *   /subscriptions/.../resourceGroups/rg/providers/Microsoft.Sql/servers/mydb
 *   → "mydb"
 */
function scopeToResourceName(scope: string): string {
  const parts = scope.split("/");
  return parts[parts.length - 1] ?? scope;
}

/**
 * Returns true if the scope is at subscription or resource-group level
 * (not drilled down to a specific resource).
 */
function isBroadScope(scope: string): boolean {
  const lower = scope.toLowerCase();
  // /subscriptions/{id}  or  /subscriptions/{id}/resourceGroups/{rg}
  const segments = lower.split("/").filter(Boolean);
  // subscriptions/{id} = 2 segments, +resourcegroups/{rg} = 4 segments
  return segments.length <= 4;
}

interface ClassificationResult {
  workloadType: string;
  confidenceScore: number;
  matchedRule: string;
}

/**
 * Apply the 6-rule classification cascade (first match wins).
 */
export function classifyRoles(assignments: RoleAssignment[]): ClassificationResult {
  const roleNames = new Set(
    assignments.map((a) => a.roleDefinitionName.toLowerCase())
  );

  const hasAcrPull = hasAny(roleNames, ACR_PULL_ROLES);
  const hasKvStorage = hasAny(roleNames, KV_STORAGE_ROLES);
  const hasQueueServerless = hasAny(roleNames, QUEUE_SERVERLESS_ROLES);
  const hasBroadInfra = hasAny(roleNames, BROAD_INFRA_ROLES);
  const hasDb = hasAny(roleNames, DB_ROLES);
  const hasBlobContributor = roleNames.has(STORAGE_BLOB_CONTRIBUTOR);
  const hasDataPipelinePlus = hasAny(roleNames, DATA_PIPELINE_PLUS_ROLES);
  const broadScoped = assignments.some(
    (a) =>
      BROAD_INFRA_ROLES.has(a.roleDefinitionName.toLowerCase()) &&
      isBroadScope(a.scope)
  );
  const allReaderOnly =
    assignments.length > 0 &&
    [...roleNames].every((r) => READER_ONLY_ROLES.has(r));

  // Rule 1: ContainerisedApp — AcrPull + KV/Storage companion
  if (hasAcrPull && hasKvStorage) {
    return { workloadType: "ContainerisedApp", confidenceScore: 85, matchedRule: "Rule1_ContainerisedApp" };
  }

  // Rule 2: ServerlessWorker — queue/blob-owner/service-bus processor roles
  if (hasQueueServerless) {
    return { workloadType: "ServerlessWorker", confidenceScore: 80, matchedRule: "Rule2_ServerlessWorker" };
  }

  // Rule 3: InfrastructureOrIaC — broad Contributor/Owner at sub/RG, NO AcrPull
  if (broadScoped && hasBroadInfra && !hasAcrPull) {
    return { workloadType: "InfrastructureOrIaC", confidenceScore: 75, matchedRule: "Rule3_InfrastructureOrIaC" };
  }

  // Rule 4: BackendDatabaseService — SQL/Cosmos contributor/reader
  if (hasDb) {
    return { workloadType: "BackendDatabaseService", confidenceScore: 82, matchedRule: "Rule4_BackendDatabaseService" };
  }

  // Rule 5: DataPipeline — Blob Contributor + EventHubs/DataFactory
  if (hasBlobContributor && hasDataPipelinePlus) {
    return { workloadType: "DataPipeline", confidenceScore: 78, matchedRule: "Rule5_DataPipeline" };
  }

  // Rule 6: MonitoringAgent — all roles are Reader-level only
  if (allReaderOnly) {
    return { workloadType: "MonitoringAgent", confidenceScore: 72, matchedRule: "Rule6_MonitoringAgent" };
  }

  // Default
  return { workloadType: "Unknown", confidenceScore: 30, matchedRule: "Default_Unknown" };
}

function hasAny(roleSet: Set<string>, targets: Set<string>): boolean {
  for (const t of targets) {
    if (roleSet.has(t)) return true;
  }
  return false;
}

// ── Main entry point ────────────────────────────────────────────────

/**
 * Infer the workload type of an SPN from its RBAC role assignment topology.
 *
 * 1. Fetches role assignments from ARM API (paginated, with 429 retry)
 * 2. Applies the 6-rule classification cascade
 * 3. Returns the topology with matched rule, assignments, and top resources
 */
export async function inferRoleTopology(
  objectId: string,
  subscriptionId: string,
  credential: TokenCredential
): Promise<RoleTopology> {
  if (!objectId || !subscriptionId) {
    return {
      workloadType: "Unknown",
      confidenceScore: 0,
      matchedRule: "NoInput",
      roleAssignments: [],
      topResources: [],
    };
  }

  const assignments = await fetchRoleAssignments(objectId, subscriptionId, credential);

  const classification = classifyRoles(assignments);

  // Extract top 3 unique resource names from scopes (most specific first)
  const resourceNames = assignments
    .map((a) => scopeToResourceName(a.scope))
    .filter((name, i, arr) => arr.indexOf(name) === i);
  const topResources = resourceNames.slice(0, 3);

  return {
    ...classification,
    roleAssignments: assignments,
    topResources,
  };
}

// ── Persistence ─────────────────────────────────────────────────────

/**
 * Persist a RoleTopology inference as a single "RoleInferred" row in
 * identity_lineage_bindings.
 *
 * resource_id is a synthetic URI: `role-inferred://{subscriptionId}/{objectId}`
 * so the (spn_id, resource_id, binding_method) upsert key is stable across scans.
 */
export async function persistRoleTopology(
  db: Pool,
  spnId: string,
  connectionId: string,
  subscriptionId: string,
  objectId: string,
  topology: RoleTopology
): Promise<void> {
  const resourceId = `role-inferred://${subscriptionId}/${objectId}`;

  await db.query(
    `INSERT INTO identity_lineage_bindings
       (spn_id, connection_id, resource_id, resource_type, resource_name,
        resource_group, region, binding_method, binding_evidence, confidence_score)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
     ON CONFLICT (spn_id, resource_id, binding_method) DO UPDATE SET
       resource_type    = EXCLUDED.resource_type,
       resource_name    = EXCLUDED.resource_name,
       binding_evidence = EXCLUDED.binding_evidence,
       confidence_score = EXCLUDED.confidence_score,
       last_verified_at = NOW()`,
    [
      spnId,
      connectionId,
      resourceId,
      "RoleInferred",
      topology.workloadType,
      null,  // resource_group — not applicable
      null,  // region — not applicable
      "RolePatternInferred",
      JSON.stringify({
        workloadType: topology.workloadType,
        matchedRule: topology.matchedRule,
        roleAssignments: topology.roleAssignments,
        topResources: topology.topResources,
      }),
      topology.confidenceScore,
    ]
  );
}
