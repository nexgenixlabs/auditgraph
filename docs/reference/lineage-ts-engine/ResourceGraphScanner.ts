/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * ResourceGraphScanner — discovers Azure resources that consume a given SPN.
 *
 * Runs 7 resource-type KQL queries against Azure Resource Graph, then
 * follow-up ARM calls for AKS node labels, Automation Account connections,
 * and Data Factory linked services.
 *
 * Rate limiting: p-limit concurrency 15, exponential backoff on HTTP 429.
 */

import { ResourceGraphClient } from "@azure/arm-resourcegraph";
import { TokenCredential } from "@azure/identity";
import pLimit from "p-limit";

// ── Public interface ────────────────────────────────────────────────

export interface ResourceBinding {
  resourceId: string;
  resourceType: string;
  resourceName: string;
  resourceGroup: string;
  region: string;
  bindingMethod: string;
  bindingEvidence: Record<string, unknown>;
  confidenceScore: number;
}

// ── Retry constants ─────────────────────────────────────────────────

const MAX_RETRIES = 3;
const BASE_BACKOFF_MS = 1_000;
const CONCURRENCY_LIMIT = 15;

// ── Helpers ─────────────────────────────────────────────────────────

interface ResourceGraphRow {
  id: string;
  name: string;
  resourceGroup: string;
  location: string;
  [key: string]: unknown;
}

/**
 * Execute a KQL query against Azure Resource Graph with 429 retry.
 */
async function queryResourceGraph(
  client: ResourceGraphClient,
  subscriptionIds: string[],
  kql: string,
  resourceLabel: string
): Promise<ResourceGraphRow[]> {
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const response = await client.resources(
        {
          subscriptions: subscriptionIds,
          query: kql,
        },
        { resultFormat: "objectArray" }
      );
      return (response.data as ResourceGraphRow[]) ?? [];
    } catch (err: unknown) {
      if (is429(err) && attempt < MAX_RETRIES) {
        const retryAfter = extractRetryAfter(err);
        const backoff = retryAfter ?? BASE_BACKOFF_MS * 2 ** (attempt - 1);
        console.warn(
          `[ResourceGraphScanner] 429 on ${resourceLabel}, retry ${attempt}/${MAX_RETRIES} after ${backoff}ms`
        );
        await sleep(backoff);
        continue;
      }
      throw err;
    }
  }
  /* istanbul ignore next — unreachable after for-loop */
  return [];
}

function is429(err: unknown): boolean {
  if (typeof err === "object" && err !== null) {
    const e = err as Record<string, unknown>;
    return e.statusCode === 429 || (e as { code?: string }).code === "TooManyRequests";
  }
  return false;
}

function extractRetryAfter(err: unknown): number | null {
  if (typeof err === "object" && err !== null) {
    const headers = (err as { response?: { headers?: Record<string, string> } }).response
      ?.headers;
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

function parseResourceGroup(resourceId: string): string {
  const match = resourceId.match(/\/resourceGroups\/([^/]+)/i);
  return match?.[1] ?? "";
}

/**
 * Fetch from ARM REST API with 429 exponential backoff.
 * Used by AKS agent-pool follow-up calls.
 */
async function armFetchWithRetry(
  url: string,
  credential: TokenCredential
): Promise<Response> {
  const token = await credential.getToken("https://management.azure.com/.default");
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    const resp = await fetch(url, {
      headers: { Authorization: `Bearer ${token!.token}` },
    });
    if (resp.status === 429 && attempt < MAX_RETRIES) {
      const retryHeader = resp.headers.get("retry-after");
      const backoff = retryHeader
        ? parseInt(retryHeader, 10) * 1_000
        : BASE_BACKOFF_MS * 2 ** (attempt - 1);
      console.warn(
        `[ResourceGraphScanner] ARM 429, retry ${attempt}/${MAX_RETRIES} after ${backoff}ms`
      );
      await sleep(backoff);
      continue;
    }
    return resp;
  }
  /* istanbul ignore next — unreachable after for-loop */
  throw new Error("ARM fetch exhausted retries");
}

// ── Per-type scanners ───────────────────────────────────────────────

async function scanAppServices(
  client: ResourceGraphClient,
  subscriptionIds: string[],
  clientId: string
): Promise<ResourceBinding[]> {
  const kql = `
    Resources
    | where type =~ "microsoft.web/sites"
    | where kind !contains "functionapp"
    | mv-expand setting = properties.siteConfig.appSettings
    | where setting.value =~ "${clientId}"
    | project id, name, resourceGroup, location, settingKey = setting.name
  `;
  const rows = await queryResourceGraph(client, subscriptionIds, kql, "AppService");
  return rows.map((r) => ({
    resourceId: r.id,
    resourceType: "AppService",
    resourceName: r.name,
    resourceGroup: r.resourceGroup ?? parseResourceGroup(r.id),
    region: r.location,
    bindingMethod: "HardcodedClientId",
    bindingEvidence: { settingKey: r.settingKey, matchedValue: clientId },
    confidenceScore: 90,
  }));
}

async function scanFunctionApps(
  client: ResourceGraphClient,
  subscriptionIds: string[],
  clientId: string
): Promise<ResourceBinding[]> {
  const kql = `
    Resources
    | where type =~ "microsoft.web/sites"
    | where kind contains "functionapp"
    | mv-expand setting = properties.siteConfig.appSettings
    | where setting.value =~ "${clientId}"
    | project id, name, resourceGroup, location, settingKey = setting.name
  `;
  const rows = await queryResourceGraph(client, subscriptionIds, kql, "FunctionApp");
  return rows.map((r) => ({
    resourceId: r.id,
    resourceType: "FunctionApp",
    resourceName: r.name,
    resourceGroup: r.resourceGroup ?? parseResourceGroup(r.id),
    region: r.location,
    bindingMethod: "HardcodedClientId",
    bindingEvidence: { settingKey: r.settingKey, matchedValue: clientId },
    confidenceScore: 90,
  }));
}

async function scanAKSClusters(
  client: ResourceGraphClient,
  subscriptionIds: string[],
  clientId: string,
  credential: TokenCredential,
  limit: <T>(fn: () => PromiseLike<T>) => Promise<T>
): Promise<ResourceBinding[]> {
  const kql = `
    Resources
    | where type =~ "microsoft.containerservice/managedclusters"
    | where properties.securityProfile.workloadIdentity.enabled == true
    | project id, name, resourceGroup, location, subscriptionId
  `;
  const rows = await queryResourceGraph(client, subscriptionIds, kql, "AKS");
  const bindings: ResourceBinding[] = [];

  for (const r of rows) {
    try {
      const subId =
        (r.subscriptionId as string) ??
        r.id.match(/\/subscriptions\/([^/]+)/i)?.[1];
      if (!subId) continue;
      const rg = r.resourceGroup ?? parseResourceGroup(r.id);
      const url =
        `https://management.azure.com/subscriptions/${subId}` +
        `/resourceGroups/${rg}/providers/Microsoft.ContainerService` +
        `/managedClusters/${r.name}/agentPools?api-version=2023-10-01`;

      const resp = await limit(() => armFetchWithRetry(url, credential));

      // 404 → cluster not found, skip entirely
      if (resp.status === 404) continue;

      // 403 → cannot inspect agent pools, fall back to inferred binding
      if (resp.status === 403) {
        bindings.push({
          resourceId: r.id,
          resourceType: "AKS",
          resourceName: r.name,
          resourceGroup: rg,
          region: r.location,
          bindingMethod: "WorkloadIdentityInferred",
          bindingEvidence: {
            clusterName: r.name,
            resourceGroup: rg,
            reason: "workloadIdentity.enabled but agent pool inspection denied (403)",
          },
          confidenceScore: 60,
        });
        continue;
      }

      if (!resp.ok) continue;

      const body = (await resp.json()) as {
        value?: Array<{ name?: string; properties?: { nodeLabels?: Record<string, string> } }>;
      };
      const pools = body.value ?? [];
      if (pools.length === 0) continue; // empty pools → skip, no binding

      // Case-insensitive match on the workload identity client-id node label
      const matchedPool = pools.find((pool) => {
        const labelValue =
          pool.properties?.nodeLabels?.["azure.workload.identity/client-id"];
        return labelValue != null && labelValue.toLowerCase() === clientId.toLowerCase();
      });

      if (matchedPool) {
        bindings.push({
          resourceId: r.id,
          resourceType: "AKS",
          resourceName: r.name,
          resourceGroup: rg,
          region: r.location,
          bindingMethod: "WorkloadIdentityAnnotation",
          bindingEvidence: {
            clusterName: r.name,
            resourceGroup: rg,
            agentPoolName: matchedPool.name ?? "unknown",
            nodeLabelKey: "azure.workload.identity/client-id",
            nodeLabelValue:
              matchedPool.properties?.nodeLabels?.[
                "azure.workload.identity/client-id"
              ] ?? clientId,
          },
          confidenceScore: 95,
        });
      }
    } catch {
      // Skip clusters we cannot inspect — non-fatal
    }
  }
  return bindings;
}

async function scanContainerApps(
  client: ResourceGraphClient,
  subscriptionIds: string[],
  clientId: string
): Promise<ResourceBinding[]> {
  const kql = `
    Resources
    | where type =~ "microsoft.app/containerapps"
    | mv-expand env = properties.template.containers[0].env
    | where env.value =~ "${clientId}"
    | project id, name, resourceGroup, location, envKey = env.name
  `;
  const rows = await queryResourceGraph(client, subscriptionIds, kql, "ContainerApp");
  return rows.map((r) => ({
    resourceId: r.id,
    resourceType: "ContainerApp",
    resourceName: r.name,
    resourceGroup: r.resourceGroup ?? parseResourceGroup(r.id),
    region: r.location,
    bindingMethod: "HardcodedClientId",
    bindingEvidence: { envKey: r.envKey, matchedValue: clientId },
    confidenceScore: 85,
  }));
}

async function scanLogicApps(
  client: ResourceGraphClient,
  subscriptionIds: string[],
  clientId: string
): Promise<ResourceBinding[]> {
  const kql = `
    Resources
    | where type =~ "microsoft.logic/workflows"
    | where tostring(properties.parameters) contains "${clientId}"
    | project id, name, resourceGroup, location
  `;
  const rows = await queryResourceGraph(client, subscriptionIds, kql, "LogicApp");
  return rows.map((r) => ({
    resourceId: r.id,
    resourceType: "LogicApp",
    resourceName: r.name,
    resourceGroup: r.resourceGroup ?? parseResourceGroup(r.id),
    region: r.location,
    bindingMethod: "HardcodedClientId",
    bindingEvidence: { parameterSearch: true, matchedValue: clientId },
    confidenceScore: 70,
  }));
}

async function scanAutomationAccounts(
  client: ResourceGraphClient,
  subscriptionIds: string[],
  clientId: string,
  credential: TokenCredential
): Promise<ResourceBinding[]> {
  const kql = `
    Resources
    | where type =~ "microsoft.automation/automationaccounts"
    | project id, name, resourceGroup, location, subscriptionId
  `;
  const rows = await queryResourceGraph(client, subscriptionIds, kql, "AutomationAccount");
  const bindings: ResourceBinding[] = [];

  for (const r of rows) {
    try {
      const subId =
        (r.subscriptionId as string) ??
        r.id.match(/\/subscriptions\/([^/]+)/i)?.[1];
      if (!subId) continue;
      const rg = r.resourceGroup ?? parseResourceGroup(r.id);
      const url =
        `https://management.azure.com/subscriptions/${subId}` +
        `/resourceGroups/${rg}/providers/Microsoft.Automation` +
        `/automationAccounts/${r.name}/connections?api-version=2023-11-01`;

      const token = await credential.getToken("https://management.azure.com/.default");
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${token!.token}` },
      });
      if (!resp.ok) continue;
      const body = (await resp.json()) as {
        value?: Array<{
          name?: string;
          properties?: { fieldDefinitionValues?: Record<string, string> };
        }>;
      };
      const match = (body.value ?? []).find((conn) => {
        const props = conn.properties?.fieldDefinitionValues ?? {};
        return Object.values(props).some((v) => v === clientId);
      });
      if (match) {
        bindings.push({
          resourceId: r.id,
          resourceType: "AutomationAccount",
          resourceName: r.name,
          resourceGroup: rg,
          region: r.location,
          bindingMethod: "HardcodedClientId",
          bindingEvidence: {
            connectionName: match.name,
            matchedField: "typeProperties.clientId",
            matchedValue: clientId,
          },
          confidenceScore: 80,
        });
      }
    } catch {
      // Non-fatal — skip accounts we cannot inspect
    }
  }
  return bindings;
}

async function scanDataFactories(
  client: ResourceGraphClient,
  subscriptionIds: string[],
  clientId: string,
  credential: TokenCredential
): Promise<ResourceBinding[]> {
  const kql = `
    Resources
    | where type =~ "microsoft.datafactory/factories"
    | project id, name, resourceGroup, location, subscriptionId
  `;
  const rows = await queryResourceGraph(client, subscriptionIds, kql, "DataFactory");
  const bindings: ResourceBinding[] = [];

  for (const r of rows) {
    try {
      const subId =
        (r.subscriptionId as string) ??
        r.id.match(/\/subscriptions\/([^/]+)/i)?.[1];
      if (!subId) continue;
      const rg = r.resourceGroup ?? parseResourceGroup(r.id);
      const url =
        `https://management.azure.com/subscriptions/${subId}` +
        `/resourceGroups/${rg}/providers/Microsoft.DataFactory` +
        `/factories/${r.name}/linkedservices?api-version=2018-06-01`;

      const token = await credential.getToken("https://management.azure.com/.default");
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${token!.token}` },
      });
      if (!resp.ok) continue;
      const body = (await resp.json()) as {
        value?: Array<{
          name?: string;
          properties?: { typeProperties?: Record<string, unknown> };
        }>;
      };
      const match = (body.value ?? []).find(
        (ls) => ls.properties?.typeProperties?.servicePrincipalId === clientId
      );
      if (match) {
        bindings.push({
          resourceId: r.id,
          resourceType: "DataFactory",
          resourceName: r.name,
          resourceGroup: rg,
          region: r.location,
          bindingMethod: "HardcodedClientId",
          bindingEvidence: {
            linkedServiceName: match.name,
            matchedField: "typeProperties.servicePrincipalId",
            matchedValue: clientId,
          },
          confidenceScore: 92,
        });
      }
    } catch {
      // Non-fatal
    }
  }
  return bindings;
}

// ── Main entry point ────────────────────────────────────────────────

/**
 * Scan all 7 resource types for references to the given SPN clientId.
 *
 * Runs KQL queries against Azure Resource Graph (with p-limit concurrency
 * of 15 and exponential backoff on 429), then follow-up ARM REST calls
 * for AKS, Automation Accounts, and Data Factory.
 */
export async function scanResourcesForSPN(
  clientId: string,
  subscriptionIds: string[],
  credential: TokenCredential
): Promise<ResourceBinding[]> {
  if (!clientId || subscriptionIds.length === 0) {
    return [];
  }

  const client = new ResourceGraphClient(credential);
  const limit = pLimit(CONCURRENCY_LIMIT);

  const scanners: Array<() => Promise<ResourceBinding[]>> = [
    () => scanAppServices(client, subscriptionIds, clientId),
    () => scanFunctionApps(client, subscriptionIds, clientId),
    () => scanAKSClusters(client, subscriptionIds, clientId, credential, limit),
    () => scanContainerApps(client, subscriptionIds, clientId),
    () => scanLogicApps(client, subscriptionIds, clientId),
    () => scanAutomationAccounts(client, subscriptionIds, clientId, credential),
    () => scanDataFactories(client, subscriptionIds, clientId, credential),
  ];

  const results = await Promise.all(scanners.map((fn) => limit(fn)));
  return results.flat();
}
