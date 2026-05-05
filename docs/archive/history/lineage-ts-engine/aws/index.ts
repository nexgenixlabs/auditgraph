/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * AWS Identity Lineage Engine — barrel exports.
 */

// Types
export type {
  AwsConnectionRecord,
  AwsIdentityRecord,
  TrustPolicyStatement,
  TrustPolicyDocument,
  TrustType,
  TrustBinding,
  EKSClusterInfo,
  EKSWorkloadBinding,
  K8sServiceAccountItem,
  K8sServiceAccountFetcher,
  OIDCFederationMapping,
  ResourcePolicyRef,
  AwsScanError,
  AwsIdentityScanResult,
  AwsLineageScanSummary,
} from "./types";

// Modules
export { classifyStatement, parseTrustPolicy, persistTrustBindings } from "./TrustPolicyParser";
export {
  scanS3BucketPolicies,
  scanKmsKeyPolicies,
  scanSqsQueuePolicies,
  scanSnsTopicPolicies,
  scanResourcePolicies,
  persistResourcePolicyBindings,
} from "./ResourcePolicyScanner";
export { scanLambdaForRole, persistLambdaBindings } from "./LambdaRoleScanner";
export { scanECSTaskDefs } from "./ECSTaskDefScanner";
export {
  scanEKSWorkloads,
  eksWorkloadToResourceBinding,
  clearClusterCache,
} from "./EKSWorkloadScanner";
export {
  mapOIDCProviders,
  persistOIDCMappings,
  classifyProviderUrl,
} from "./OIDCProviderMapper";
export { detectAwsEnrichmentTier, invalidateAwsTierCache } from "./AwsEnrichmentTierProbe";
export {
  classifyAwsOrphanStatus,
  persistAwsOrphanClassification,
  gatherAwsOrphanSignals,
  classifyFromSignals,
} from "./AwsOrphanDetectionEngine";
export { runAwsLineageScan } from "./AwsLineageOrchestrator";
export { upsertBindings } from "./upsertBindings";
