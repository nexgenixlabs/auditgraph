/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * TrustPolicyParser — fetches IAM role trust policies via `iam:GetRole`,
 * URL-decodes the AssumeRolePolicyDocument, and classifies each Statement
 * into one of 6 trust types.
 *
 * IAM users are skipped (no trust policy).
 *
 * Trust type classification:
 *   GitHubOIDC            — token.actions.githubusercontent.com in Federated
 *   EKSOIDC               — oidc.eks.*.amazonaws.com in Federated
 *   CrossAccountAssumeRole — AWS principal from a different account
 *   ServicePrincipal      — *.amazonaws.com in Service
 *   ExternalIdPSAML       — arn:aws:iam::*:saml-provider/ in Federated
 *   WildcardTrust         — Principal: "*"
 */

import type { IAMClient } from "@aws-sdk/client-iam";
import { GetRoleCommand } from "@aws-sdk/client-iam";
import type { Pool } from "pg";

import type {
  AwsIdentityRecord,
  TrustPolicyDocument,
  TrustPolicyStatement,
  TrustBinding,
  TrustType,
  ResourceBinding,
} from "./types";
import { upsertBindings } from "./upsertBindings";

// ── Helpers ─────────────────────────────────────────────────────────

/**
 * Extract the role name from an IAM role ARN.
 * e.g. `arn:aws:iam::123456789012:role/MyRole` → `MyRole`
 * Handles path-prefixed roles: `arn:aws:iam::123:role/path/MyRole` → `path/MyRole`
 */
function extractRoleName(arn: string): string {
  const match = arn.match(/:role\/(.+)$/);
  return match?.[1] ?? arn;
}

/**
 * Normalize a Principal value to an array of strings.
 * Trust policy Principals can be "*", a string, or { AWS: [...], Service: [...], Federated: [...] }.
 */
function normalizePrincipal(
  principal: TrustPolicyStatement["Principal"],
  key: string
): string[] {
  if (!principal) return [];
  if (typeof principal === "string") {
    return key === "*" && principal === "*" ? ["*"] : [];
  }
  const val = principal[key];
  if (!val) return [];
  return Array.isArray(val) ? val : [val];
}

function getAllPrincipals(
  principal: TrustPolicyStatement["Principal"]
): string[] {
  if (!principal) return [];
  if (typeof principal === "string") return [principal];
  const result: string[] = [];
  for (const key of Object.keys(principal)) {
    const val = principal[key];
    if (Array.isArray(val)) result.push(...val);
    else if (typeof val === "string") result.push(val);
  }
  return result;
}

// ── Statement classifier ────────────────────────────────────────────

/**
 * Classify a single trust policy statement into zero or more TrustBindings.
 * Pure function — no API calls.
 */
export function classifyStatement(
  stmt: TrustPolicyStatement,
  accountId: string
): TrustBinding[] {
  // Skip Deny statements
  if (stmt.Effect?.toLowerCase() === "deny") return [];

  const bindings: TrustBinding[] = [];
  const federated = normalizePrincipal(stmt.Principal, "Federated");
  const services = normalizePrincipal(stmt.Principal, "Service");
  const awsPrincipals = normalizePrincipal(stmt.Principal, "AWS");
  const allPrincipals = getAllPrincipals(stmt.Principal);

  // 1. GitHub OIDC
  for (const f of federated) {
    if (f.includes("token.actions.githubusercontent.com")) {
      const condition = stmt.Condition;
      let org = "";
      let repo = "";

      // Extract org/repo from Condition
      const subCondition =
        condition?.StringLike?.["token.actions.githubusercontent.com:sub"] ??
        condition?.StringEquals?.["token.actions.githubusercontent.com:sub"];
      if (subCondition) {
        const subStr = Array.isArray(subCondition)
          ? subCondition[0]
          : subCondition;
        const repoMatch = subStr?.match(/^repo:([^/]+)\/([^:]+)/);
        if (repoMatch) {
          org = repoMatch[1];
          repo = repoMatch[2];
        }
      }

      const confidence = org && repo ? 95 : 75;
      const resourceId =
        org && repo
          ? `github-oidc://${accountId}/${org}/${repo}`
          : `github-oidc://${accountId}/unknown`;

      bindings.push({
        trustType: "GitHubOIDC",
        resourceId,
        resourceType: "GitHubOIDCTrust",
        resourceName: org && repo ? `${org}/${repo}` : "GitHub OIDC (unknown repo)",
        resourceGroup: "",
        region: "",
        bindingMethod: "TrustPolicy",
        bindingEvidence: {
          cloud: "aws",
          trustType: "GitHubOIDC",
          federatedPrincipal: f,
          org,
          repo,
          condition: condition ?? null,
        },
        confidenceScore: confidence,
      });
    }
  }

  // 2. EKS OIDC
  for (const f of federated) {
    if (f.match(/oidc\.eks\.[^.]+\.amazonaws\.com/)) {
      const condition = stmt.Condition;
      let namespace = "";
      let serviceAccount = "";
      let clusterId = "";

      // Extract cluster from federated ARN
      const clusterMatch = f.match(
        /oidc\.eks\.([^.]+)\.amazonaws\.com\/id\/([A-Z0-9]+)/i
      );
      const eksRegion = clusterMatch?.[1] ?? "";
      clusterId = clusterMatch?.[2] ?? "";

      // Extract namespace/SA from condition
      const subKey = Object.keys(condition?.StringEquals ?? {}).find((k) =>
        k.includes(":sub")
      );
      if (subKey) {
        const subVal = condition!.StringEquals![subKey];
        const subStr = Array.isArray(subVal) ? subVal[0] : subVal;
        const saMatch = subStr?.match(
          /^system:serviceaccount:([^:]+):([^:]+)$/
        );
        if (saMatch) {
          namespace = saMatch[1];
          serviceAccount = saMatch[2];
        }
      }

      const confidence = namespace && serviceAccount ? 95 : 70;
      const resourceId =
        namespace && serviceAccount
          ? `eks://${accountId}/${eksRegion}/${clusterId}/${namespace}/${serviceAccount}`
          : `eks://${accountId}/${eksRegion}/${clusterId}`;

      bindings.push({
        trustType: "EKSOIDC",
        resourceId,
        resourceType: "EKSOIDCTrust",
        resourceName: namespace
          ? `EKS ${clusterId} / ${namespace}:${serviceAccount}`
          : `EKS ${clusterId}`,
        resourceGroup: "",
        region: eksRegion,
        bindingMethod: "TrustPolicy",
        bindingEvidence: {
          cloud: "aws",
          trustType: "EKSOIDC",
          federatedPrincipal: f,
          clusterId,
          namespace,
          serviceAccount,
          condition: condition ?? null,
        },
        confidenceScore: confidence,
      });
    }
  }

  // 3. SAML Provider (ExternalIdPSAML)
  for (const f of federated) {
    if (f.match(/arn:aws:iam::\d+:saml-provider\//)) {
      const nameMatch = f.match(/saml-provider\/(.+)$/);
      const providerName = nameMatch?.[1] ?? "unknown";

      bindings.push({
        trustType: "ExternalIdPSAML",
        resourceId: `trust-policy://${accountId}/saml/${providerName}`,
        resourceType: "SAMLTrust",
        resourceName: `SAML: ${providerName}`,
        resourceGroup: "",
        region: "",
        bindingMethod: "TrustPolicy",
        bindingEvidence: {
          cloud: "aws",
          trustType: "ExternalIdPSAML",
          federatedPrincipal: f,
          providerName,
        },
        confidenceScore: 90,
      });
    }
  }

  // 4. Cross-account trust
  for (const p of awsPrincipals) {
    const arnMatch = p.match(/arn:aws:iam::(\d+):/);
    if (arnMatch) {
      const otherAccount = arnMatch[1];
      if (otherAccount !== accountId) {
        const hasExternalId = !!(
          stmt.Condition?.StringEquals?.["sts:ExternalId"]
        );
        bindings.push({
          trustType: "CrossAccountAssumeRole",
          resourceId: `trust-policy://${accountId}/cross-account/${otherAccount}`,
          resourceType: "CrossAccountTrust",
          resourceName: `Cross-account: ${otherAccount}`,
          resourceGroup: "",
          region: "",
          bindingMethod: "TrustPolicy",
          bindingEvidence: {
            cloud: "aws",
            trustType: "CrossAccountAssumeRole",
            awsPrincipal: p,
            otherAccount,
            hasExternalId,
          },
          confidenceScore: hasExternalId ? 90 : 80,
        });
      }
    }
  }

  // 5. Service principal (*.amazonaws.com)
  for (const svc of services) {
    if (svc.endsWith(".amazonaws.com")) {
      const svcName = svc.replace(".amazonaws.com", "");
      bindings.push({
        trustType: "ServicePrincipal",
        resourceId: `trust-policy://${accountId}/service/${svcName}`,
        resourceType: "ServiceTrust",
        resourceName: `Service: ${svcName}`,
        resourceGroup: "",
        region: "",
        bindingMethod: "TrustPolicy",
        bindingEvidence: {
          cloud: "aws",
          trustType: "ServicePrincipal",
          servicePrincipal: svc,
        },
        confidenceScore: 90,
      });
    }
  }

  // 6. Wildcard trust (Principal: "*")
  if (allPrincipals.includes("*")) {
    const hasConditions =
      stmt.Condition && Object.keys(stmt.Condition).length > 0;
    bindings.push({
      trustType: "WildcardTrust",
      resourceId: `trust-policy://${accountId}/wildcard`,
      resourceType: "WildcardTrust",
      resourceName: "Wildcard Principal (*)",
      resourceGroup: "",
      region: "",
      bindingMethod: "TrustPolicy",
      bindingEvidence: {
        cloud: "aws",
        trustType: "WildcardTrust",
        hasConditions: !!hasConditions,
        conditions: stmt.Condition ?? null,
      },
      confidenceScore: hasConditions ? 60 : 40,
    });
  }

  return bindings;
}

// ── Main parser ─────────────────────────────────────────────────────

/**
 * Fetch the trust policy for an IAM role, decode it, and classify all statements.
 * Returns [] for IAM users (no trust policy).
 */
export async function parseTrustPolicy(
  iamClient: IAMClient,
  identity: AwsIdentityRecord,
  accountId: string
): Promise<TrustBinding[]> {
  // Only roles have trust policies
  if (identity.identityCategory === "iam_user") return [];

  const roleName = extractRoleName(identity.principalId);

  try {
    const response = await iamClient.send(
      new GetRoleCommand({ RoleName: roleName })
    );

    const rawDoc = response.Role?.AssumeRolePolicyDocument;
    if (!rawDoc) return [];

    // Trust policy document is URL-encoded
    const decoded = decodeURIComponent(rawDoc);
    const doc: TrustPolicyDocument = JSON.parse(decoded);

    if (!doc.Statement || !Array.isArray(doc.Statement)) return [];

    return doc.Statement.flatMap((stmt) =>
      classifyStatement(stmt, accountId)
    );
  } catch (err: unknown) {
    // NoSuchEntity — role may have been deleted since discovery
    const code = (err as { name?: string })?.name;
    if (code === "NoSuchEntityException") return [];
    throw err;
  }
}

// ── Persistence ─────────────────────────────────────────────────────

/**
 * Persist trust bindings using the shared upsert pattern.
 */
export async function persistTrustBindings(
  db: Pool,
  spnId: string,
  connectionId: string,
  bindings: TrustBinding[]
): Promise<void> {
  await upsertBindings(db, connectionId, spnId, bindings);
}
