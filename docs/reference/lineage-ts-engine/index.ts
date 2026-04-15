/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
export { scanResourcesForSPN, type ResourceBinding } from "./ResourceGraphScanner";
export { getFederatedMappings, parseSubject, persistFederatedBindings, type FederatedMapping } from "./FederatedCredentialMapper";
export { inferRoleTopology, classifyRoles, persistRoleTopology, type RoleTopology, type RoleAssignment } from "./RoleTopologyInferrer";
export { getAppRegistrationMetadata, classifyUrl, persistAppRegistrationBindings, type AppRegistrationMetadata, type InferredHost } from "./AppRegistrationMiner";
export { enrichSignInActivity, classifySignInActivity, persistSignInEnrichment, type SignInEnrichment, type SignInType } from "./SignInActivityEnricher";
export { classifyOrphanStatus, classify, gatherSignals, persistOrphanClassification, type OrphanClassification } from "./OrphanDetectionEngine";
export { detectEnrichmentTier, invalidateTierCache, type EnrichmentTier } from "./EnrichmentTierProbe";
export { computeLineageScore, computeScore, persistLineageScore } from "./LineageConfidenceScorer";
export { runFullLineageScan, runLineageScan, type LineageScanSummary } from "./LineageOrchestrator";

// AWS Identity Lineage Engine (Phase 2)
export { runAwsLineageScan } from "./aws";
