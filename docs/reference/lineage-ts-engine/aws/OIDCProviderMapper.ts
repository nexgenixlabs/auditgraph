/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * OIDCProviderMapper — discovers IAM OIDC providers and maps them to
 * identity lineage bindings by cross-referencing with role trust policies.
 *
 * AWS APIs:
 *   iam:ListOpenIDConnectProviders → provider ARNs
 *   iam:GetOpenIDConnectProvider  → URL, ClientIDList, ThumbprintList
 *   iam:GetRole                   → trust policy (for condition parsing)
 *
 * Provider classification:
 *   token.actions.githubusercontent.com → GitHubActions  confidence: 98
 *   oidc.eks.*.amazonaws.com            → EKSCluster     confidence: 95
 *   else                                → ExternalIdP    confidence: 70
 *
 * For GitHub OIDC: trust policy conditions are parsed to extract
 *   org, repo, branch, environment from the :sub condition.
 */

import type { IAMClient } from "@aws-sdk/client-iam";
import {
  ListOpenIDConnectProvidersCommand,
  GetOpenIDConnectProviderCommand,
  GetRoleCommand,
} from "@aws-sdk/client-iam";
import type { Pool } from "pg";

import type {
  OIDCFederationMapping,
  TrustPolicyStatement,
  TrustPolicyDocument,
  ResourceBinding,
} from "./types";
import { upsertBindings } from "./upsertBindings";

// ── Internal types ──────────────────────────────────────────────────

interface OIDCProviderDetail {
  arn: string;
  url: string;
  clientIds: string[];
  thumbprints: string[];
}

// ── Helpers ─────────────────────────────────────────────────────────

function extractRoleName(arn: string): string {
  const match = arn.match(/:role\/(.+)$/);
  return match?.[1] ?? arn;
}

function extractAccountId(arn: string): string {
  const match = arn.match(/arn:aws:iam::(\d+):/);
  return match?.[1] ?? "";
}

/**
 * Classify an OIDC provider by its issuer URL.
 */
export function classifyProviderUrl(
  url: string
): "GitHubActions" | "EKSCluster" | "ExternalIdP" {
  if (url.includes("token.actions.githubusercontent.com")) return "GitHubActions";
  if (/oidc\.eks\.[^.]+\.amazonaws\.com/.test(url)) return "EKSCluster";
  return "ExternalIdP";
}

/**
 * Parse trust policy conditions to extract GitHub Actions details:
 * org, repo, branch, environment from StringLike/StringEquals on :sub.
 *
 * Patterns:
 *   repo:{org}/{repo}:ref:refs/heads/{branch}
 *   repo:{org}/{repo}:environment:{env}
 */
function parseGitHubConditions(
  conditions: TrustPolicyStatement["Condition"],
  providerUrl: string
): { org?: string; repo?: string; branch?: string; environment?: string } {
  if (!conditions) return {};

  const subKey = `${providerUrl}:sub`;
  const subCondition =
    conditions.StringLike?.[subKey] ??
    conditions.StringEquals?.[subKey];

  if (!subCondition) return {};

  const subStr = Array.isArray(subCondition) ? subCondition[0] : subCondition;
  if (!subStr) return {};

  const result: {
    org?: string;
    repo?: string;
    branch?: string;
    environment?: string;
  } = {};

  const repoMatch = subStr.match(/^repo:([^/]+)\/([^:]+)/);
  if (repoMatch) {
    result.org = repoMatch[1];
    result.repo = repoMatch[2];
  }

  const branchMatch = subStr.match(/:ref:refs\/heads\/(.+)$/);
  if (branchMatch) {
    result.branch = branchMatch[1];
  }

  const envMatch = subStr.match(/:environment:(.+)$/);
  if (envMatch) {
    result.environment = envMatch[1];
  }

  return result;
}

/**
 * Extract an EKS cluster ARN from an OIDC provider URL.
 * Pattern: oidc.eks.{region}.amazonaws.com/id/{clusterId}
 */
function extractEKSClusterArn(
  url: string,
  accountId: string
): string | undefined {
  const match = url.match(
    /oidc\.eks\.([^.]+)\.amazonaws\.com\/id\/([A-Za-z0-9]+)/
  );
  if (match) {
    return `arn:aws:eks:${match[1]}:${accountId}:cluster/${match[2]}`;
  }
  return undefined;
}

/**
 * Check if a trust statement references a specific OIDC provider
 * by ARN or by issuer URL in the Federated principal.
 */
function statementReferencesProvider(
  stmt: TrustPolicyStatement,
  provider: OIDCProviderDetail
): boolean {
  if (stmt.Effect?.toLowerCase() === "deny") return false;

  const principal = stmt.Principal;
  if (!principal || typeof principal === "string") return false;

  const federated = principal.Federated;
  if (!federated) return false;

  const federatedArr = Array.isArray(federated) ? federated : [federated];
  return federatedArr.some(
    (f) => f === provider.arn || f.includes(provider.url)
  );
}

// ── Resource binding conversion ─────────────────────────────────────

function toResourceBinding(
  mapping: OIDCFederationMapping,
  accountId: string
): ResourceBinding {
  let resourceId: string;
  let resourceType: string;
  let resourceName: string;

  switch (mapping.providerType) {
    case "GitHubActions":
      resourceType = "AWSGitHubOIDC";
      resourceId =
        mapping.org && mapping.repo
          ? `github-oidc://${accountId}/${mapping.org}/${mapping.repo}`
          : `github-oidc://${accountId}/unknown`;
      resourceName =
        mapping.org && mapping.repo
          ? `GitHub: ${mapping.org}/${mapping.repo}`
          : "GitHub OIDC (unknown repo)";
      break;
    case "EKSCluster":
      resourceType = "AWSEKSClusterOIDC";
      resourceId = mapping.clusterArn
        ? `eks-oidc://${mapping.clusterArn}`
        : `eks-oidc://${mapping.providerArn}`;
      resourceName = mapping.clusterArn
        ? `EKS OIDC: ${mapping.clusterArn}`
        : `EKS OIDC: ${mapping.providerArn}`;
      break;
    default:
      resourceType = "AWSExternalOIDC";
      resourceId = `oidc://${mapping.providerArn}`;
      resourceName = `External OIDC: ${mapping.issuerUrl}`;
      break;
  }

  return {
    resourceId,
    resourceType,
    resourceName,
    resourceGroup: "",
    region: "",
    bindingMethod: "OIDCFederation",
    bindingEvidence: { ...mapping, cloud: "aws" },
    confidenceScore: mapping.confidenceScore,
  };
}

// ── Main function ───────────────────────────────────────────────────

/**
 * Discover OIDC providers in the AWS account and map them to the given
 * role by cross-referencing with its trust policy.
 *
 * Steps:
 *   1. List all IAM OIDC providers
 *   2. Get details (URL, clients, thumbprints) for each
 *   3. Get the role's trust policy
 *   4. Match providers to trust policy Federated principals
 *   5. Classify each matched provider and extract details
 */
export async function mapOIDCProviders(
  roleArn: string,
  iamClient: IAMClient
): Promise<OIDCFederationMapping[]> {
  if (!roleArn) return [];

  const mappings: OIDCFederationMapping[] = [];

  // 1. List all OIDC providers
  const listResp = await iamClient.send(
    new ListOpenIDConnectProvidersCommand({})
  );
  const providerArns = (listResp.OpenIDConnectProviderList ?? [])
    .map((p) => p.Arn)
    .filter(Boolean) as string[];

  if (providerArns.length === 0) return [];

  // 2. Get details for each provider
  const providers: OIDCProviderDetail[] = [];
  for (const arn of providerArns) {
    try {
      const resp = await iamClient.send(
        new GetOpenIDConnectProviderCommand({
          OpenIDConnectProviderArn: arn,
        })
      );
      providers.push({
        arn,
        url: resp.Url ?? "",
        clientIds: resp.ClientIDList ?? [],
        thumbprints: resp.ThumbprintList ?? [],
      });
    } catch {
      // Skip providers we can't read (permissions, deleted, etc.)
    }
  }

  if (providers.length === 0) return [];

  // 3. Get the role's trust policy
  const roleName = extractRoleName(roleArn);
  let trustDoc: TrustPolicyDocument | null = null;

  try {
    const roleResp = await iamClient.send(
      new GetRoleCommand({ RoleName: roleName })
    );
    const rawDoc = roleResp.Role?.AssumeRolePolicyDocument;
    if (rawDoc) {
      trustDoc = JSON.parse(decodeURIComponent(rawDoc));
    }
  } catch {
    return []; // Can't get trust policy — can't determine provider usage
  }

  if (!trustDoc?.Statement) return [];

  const accountId = extractAccountId(roleArn);

  // 4. Match providers to trust policy statements
  for (const provider of providers) {
    const matchingStmt = trustDoc.Statement.find((stmt) =>
      statementReferencesProvider(stmt, provider)
    );

    if (!matchingStmt) continue;

    const providerType = classifyProviderUrl(provider.url);

    const mapping: OIDCFederationMapping = {
      providerArn: provider.arn,
      providerType,
      issuerUrl: provider.url,
      confidenceScore: 70, // default for ExternalIdP
    };

    switch (providerType) {
      case "GitHubActions": {
        mapping.confidenceScore = 98;
        const ghDetails = parseGitHubConditions(
          matchingStmt.Condition,
          provider.url
        );
        mapping.org = ghDetails.org;
        mapping.repo = ghDetails.repo;
        mapping.branch = ghDetails.branch;
        mapping.environment = ghDetails.environment;
        break;
      }
      case "EKSCluster": {
        mapping.confidenceScore = 95;
        mapping.clusterArn = extractEKSClusterArn(provider.url, accountId);
        break;
      }
      // ExternalIdP stays at default confidence 70
    }

    mappings.push(mapping);
  }

  return mappings;
}

// ── Persistence ─────────────────────────────────────────────────────

/**
 * Persist OIDC federation mappings as identity_lineage_bindings rows.
 */
export async function persistOIDCMappings(
  db: Pool,
  spnId: string,
  connectionId: string,
  mappings: OIDCFederationMapping[],
  accountId: string
): Promise<void> {
  const bindings = mappings.map((m) => toResourceBinding(m, accountId));
  await upsertBindings(db, connectionId, spnId, bindings);
}
