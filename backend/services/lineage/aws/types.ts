/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * Shared types for the AWS Identity Lineage Engine.
 *
 * AWS identities stored in the `identities` table use ARNs as principal_id,
 * AWS resources (S3/KMS/Lambda) are in their own tables, and CloudTrail
 * events are in `aws_cloudtrail_events`.
 */

import type { ResourceBinding } from "../ResourceGraphScanner";
import type { EnrichmentTier } from "../EnrichmentTierProbe";

// ── Connection & identity records ───────────────────────────────────

export interface AwsConnectionRecord {
  connectionId: string;
  awsAccessKeyId: string;
  awsSecretAccessKey: string;
  region: string;
  accountIds: string[];
}

export interface AwsIdentityRecord {
  id: string; // identities.id (BIGINT as string from pg)
  identityId: string; // identities.identity_id (ARN)
  principalId: string; // identities.principal_id (ARN)
  displayName: string;
  identityCategory: string; // iam_user | iam_role | iam_service_linked_role
  isFederated: boolean;
  tags: Record<string, unknown>; // JSONB
}

// ── Trust policy types ──────────────────────────────────────────────

export interface TrustPolicyStatement {
  Effect: string;
  Principal?: Record<string, string | string[]> | string;
  Action?: string | string[];
  Condition?: Record<string, Record<string, string | string[]>>;
}

export interface TrustPolicyDocument {
  Version: string;
  Statement: TrustPolicyStatement[];
}

export type TrustType =
  | "GitHubOIDC"
  | "EKSOIDC"
  | "CrossAccountAssumeRole"
  | "ServicePrincipal"
  | "ExternalIdPSAML"
  | "WildcardTrust";

export interface TrustBinding extends ResourceBinding {
  trustType: TrustType;
}

// ── EKS types ───────────────────────────────────────────────────────

export interface EKSClusterInfo {
  clusterArn: string;
  clusterName: string;
  oidcIssuer: string | null;
  region: string;
}

export interface EKSWorkloadBinding {
  clusterName: string;
  clusterArn: string;
  namespace: string;
  serviceAccount: string;
  oidcIssuer: string;
  roleArn: string;
  confidenceScore: 95;
}

// ── K8s API types (used by EKSWorkloadScanner) ──────────────────────

export interface K8sServiceAccountItem {
  metadata: {
    name: string;
    namespace: string;
    annotations?: Record<string, string>;
  };
}

export interface K8sServiceAccountList {
  items: K8sServiceAccountItem[];
}

export type K8sServiceAccountFetcher = (
  endpoint: string,
  token: string,
  caCertBase64: string
) => Promise<K8sServiceAccountItem[]>;

// ── OIDC Federation types ───────────────────────────────────────────

export interface OIDCFederationMapping {
  providerArn: string;
  providerType: "GitHubActions" | "EKSCluster" | "ExternalIdP";
  issuerUrl: string;
  org?: string;
  repo?: string;
  branch?: string;
  environment?: string;
  clusterArn?: string;
  confidenceScore: number;
}

// ── Resource policy types ───────────────────────────────────────────

export interface ResourcePolicyRef {
  resourceArn: string;
  resourceType: "S3Bucket" | "KMSKey" | "SQSQueue" | "SNSTopic";
  resourceName: string;
  statementSid: string;
  source: "db" | "live";
  confidenceScore: number;
}

// ── Scan result types ───────────────────────────────────────────────

export interface AwsScanError {
  spnId: string;
  displayName: string;
  module: string;
  error: string;
}

export interface AwsIdentityScanResult {
  bindingsFound: number;
  orphanStatus: string;
}

export interface AwsLineageScanSummary {
  connectionId: number;
  accountsScanned: number;
  identitiesScanned: number;
  bindingsFound: number;
  orphansFound: {
    safeToRetire: number;
    caution: number;
    blocked: number;
  };
  enrichmentTier: EnrichmentTier;
  durationMs: number;
  completedAt: string;
  errors: AwsScanError[];
}

// Re-export types that AWS modules need from P1
export type { ResourceBinding, EnrichmentTier };
