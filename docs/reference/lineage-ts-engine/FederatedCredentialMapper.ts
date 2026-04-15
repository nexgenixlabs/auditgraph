/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * FederatedCredentialMapper — resolves federated identity credentials on an SPN
 * via MS Graph and classifies them as GitHub Actions, AKS Workload Identity,
 * or External IdP bindings.
 *
 * Each credential becomes a row in identity_lineage_bindings with
 * binding_method = "FederatedCredential".
 */

import type { Client } from "@microsoft/microsoft-graph-client";
import type { Pool } from "pg";

// ── Public types ────────────────────────────────────────────────────

export type WorkloadType = "GitHubActions" | "AKSWorkload" | "ExternalIdP";

export interface FederatedMapping {
  credentialId: string;
  workloadType: WorkloadType;
  org?: string;
  repo?: string;
  branch?: string;
  environment?: string;
  namespace?: string;
  serviceAccount?: string;
  clusterId?: string;
  issuer: string;
  subject: string;
  confidenceScore: number;
}

// ── Graph API response shape ────────────────────────────────────────

interface FederatedIdentityCredential {
  id: string;
  name: string;
  issuer: string;
  subject: string;
  audiences: string[];
}

interface FederatedCredentialListResponse {
  value: FederatedIdentityCredential[];
}

// ── Subject parsing ─────────────────────────────────────────────────

const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";

/**
 * Parse a federated identity credential into a structured mapping.
 *
 * Rules (evaluated in order):
 *   1. GitHub Actions — issuer matches GITHUB_ISSUER
 *      Subject patterns:
 *        repo:{org}/{repo}:ref:refs/heads/{branch}  → GitHubBranch
 *        repo:{org}/{repo}:environment:{env}         → GitHubEnvironment
 *        repo:{org}/{repo}:pull_request               → GitHubPR
 *   2. AKS Workload Identity — issuer contains "oidc.prod.aks.azure.com"
 *      Subject: system:serviceaccount:{namespace}:{serviceAccountName}
 *   3. External IdP — everything else
 */
export function parseSubject(cred: FederatedIdentityCredential): FederatedMapping {
  const base = {
    credentialId: cred.id,
    issuer: cred.issuer,
    subject: cred.subject,
  };

  // ── 1. GitHub Actions ───────────────────────────────────────────
  if (cred.issuer === GITHUB_ISSUER) {
    return parseGitHubSubject(base, cred.subject);
  }

  // ── 2. AKS Workload Identity ────────────────────────────────────
  if (cred.issuer.includes("oidc.prod.aks.azure.com")) {
    return parseAKSSubject(base, cred.issuer, cred.subject);
  }

  // ── 3. External IdP (catch-all) ─────────────────────────────────
  return {
    ...base,
    workloadType: "ExternalIdP",
    confidenceScore: 70,
  };
}

function parseGitHubSubject(
  base: Pick<FederatedMapping, "credentialId" | "issuer" | "subject">,
  subject: string
): FederatedMapping {
  // Pattern: repo:{org}/{repo}:ref:refs/heads/{branch}
  const branchMatch = subject.match(
    /^repo:([^/]+)\/([^:]+):ref:refs\/heads\/(.+)$/
  );
  if (branchMatch) {
    return {
      ...base,
      workloadType: "GitHubActions",
      org: branchMatch[1],
      repo: branchMatch[2],
      branch: branchMatch[3],
      confidenceScore: 98,
    };
  }

  // Pattern: repo:{org}/{repo}:environment:{env}
  const envMatch = subject.match(
    /^repo:([^/]+)\/([^:]+):environment:(.+)$/
  );
  if (envMatch) {
    return {
      ...base,
      workloadType: "GitHubActions",
      org: envMatch[1],
      repo: envMatch[2],
      environment: envMatch[3],
      confidenceScore: 98,
    };
  }

  // Pattern: repo:{org}/{repo}:pull_request
  const prMatch = subject.match(
    /^repo:([^/]+)\/([^:]+):pull_request$/
  );
  if (prMatch) {
    return {
      ...base,
      workloadType: "GitHubActions",
      org: prMatch[1],
      repo: prMatch[2],
      confidenceScore: 98,
    };
  }

  // Unrecognised GitHub subject — still GitHub but lower confidence
  const fallbackMatch = subject.match(/^repo:([^/]+)\/([^:]+)/);
  return {
    ...base,
    workloadType: "GitHubActions",
    org: fallbackMatch?.[1],
    repo: fallbackMatch?.[2],
    confidenceScore: 85,
  };
}

function parseAKSSubject(
  base: Pick<FederatedMapping, "credentialId" | "issuer" | "subject">,
  issuer: string,
  subject: string
): FederatedMapping {
  // Issuer example:
  //   https://{region}.oic.prod-aks.azure.com/{tenantId}/{clusterId}/
  // or:
  //   https://oidc.prod.aks.azure.com/{tenantId}/{clusterId}/
  const clusterMatch = issuer.match(
    /oidc\.prod[^/]*\.a[kz][su]re\.com\/[^/]+\/([^/]+)/i
  );
  const clusterId = clusterMatch?.[1] ?? null;

  // Subject: system:serviceaccount:{namespace}:{serviceAccountName}
  const saMatch = subject.match(
    /^system:serviceaccount:([^:]+):(.+)$/
  );

  return {
    ...base,
    workloadType: "AKSWorkload",
    clusterId: clusterId ?? undefined,
    namespace: saMatch?.[1],
    serviceAccount: saMatch?.[2],
    confidenceScore: 98,
  };
}

// ── Graph API call ──────────────────────────────────────────────────

/**
 * Fetch federated identity credentials for an SPN and parse each one
 * into a structured FederatedMapping.
 *
 * Returns [] if the SPN has no federated credentials or the Graph call fails.
 */
export async function getFederatedMappings(
  objectId: string,
  graphClient: Client
): Promise<FederatedMapping[]> {
  if (!objectId) return [];

  try {
    const response: FederatedCredentialListResponse = await graphClient
      .api(`/servicePrincipals/${objectId}/federatedIdentityCredentials`)
      .get();

    const creds = response?.value ?? [];
    return creds.map(parseSubject);
  } catch (err: unknown) {
    const status = (err as { statusCode?: number }).statusCode;
    // 404 = SPN has no federated creds configured; not an error
    if (status === 404) return [];
    console.error(
      `[FederatedCredentialMapper] Graph call failed for objectId=${objectId}:`,
      err
    );
    return [];
  }
}

// ── Persistence ─────────────────────────────────────────────────────

function workloadTypeToResourceType(wt: WorkloadType): string {
  switch (wt) {
    case "GitHubActions":
      return "FederatedGitHub";
    case "AKSWorkload":
      return "FederatedAKS";
    case "ExternalIdP":
      return "FederatedExternal";
  }
}

function buildResourceId(mapping: FederatedMapping): string {
  switch (mapping.workloadType) {
    case "GitHubActions":
      return mapping.org && mapping.repo
        ? `github://${mapping.org}/${mapping.repo}`
        : `github://unknown/${mapping.credentialId}`;
    case "AKSWorkload":
      return mapping.clusterId
        ? `aks://${mapping.clusterId}/${mapping.namespace ?? "default"}/${mapping.serviceAccount ?? "unknown"}`
        : `aks://unknown/${mapping.credentialId}`;
    case "ExternalIdP":
      return `federated://${mapping.issuer}/${mapping.credentialId}`;
  }
}

function buildEvidence(mapping: FederatedMapping): Record<string, unknown> {
  const evidence: Record<string, unknown> = {
    credentialId: mapping.credentialId,
    issuer: mapping.issuer,
    subject: mapping.subject,
  };
  if (mapping.org) evidence.org = mapping.org;
  if (mapping.repo) evidence.repo = mapping.repo;
  if (mapping.branch) evidence.branch = mapping.branch;
  if (mapping.environment) evidence.environment = mapping.environment;
  if (mapping.namespace) evidence.namespace = mapping.namespace;
  if (mapping.serviceAccount) evidence.serviceAccount = mapping.serviceAccount;
  if (mapping.clusterId) evidence.clusterId = mapping.clusterId;
  return evidence;
}

/**
 * Persist federated mappings as identity_lineage_bindings rows.
 *
 * Uses the same upsert pattern as LineageOrchestrator (ON CONFLICT
 * on the (spn_id, resource_id, binding_method) unique constraint).
 */
export async function persistFederatedBindings(
  db: Pool,
  spnId: string,
  connectionId: string,
  mappings: FederatedMapping[]
): Promise<void> {
  if (mappings.length === 0) return;

  const values: unknown[] = [];
  const placeholders: string[] = [];
  let idx = 1;

  for (const m of mappings) {
    const resourceId = buildResourceId(m);
    const resourceType = workloadTypeToResourceType(m.workloadType);
    const evidence = buildEvidence(m);
    const resourceName =
      m.workloadType === "GitHubActions"
        ? `${m.org}/${m.repo}` + (m.branch ? `@${m.branch}` : m.environment ? `[${m.environment}]` : "")
        : m.workloadType === "AKSWorkload"
          ? `${m.namespace}/${m.serviceAccount}`
          : m.issuer;

    placeholders.push(
      `($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++})`
    );
    values.push(
      spnId,
      connectionId,
      resourceId,
      resourceType,
      resourceName,
      null,           // resource_group — not applicable for federated
      null,           // region — not applicable for federated
      "FederatedCredential",
      JSON.stringify(evidence),
      m.confidenceScore
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
       binding_evidence = EXCLUDED.binding_evidence,
       confidence_score = EXCLUDED.confidence_score,
       last_verified_at = NOW()`,
    values
  );
}
