/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * AppRegistrationMiner — fetches app registration metadata from MS Graph,
 * infers host URLs from replyUrls/identifierUris, and persists them as
 * "ReplyUrl" bindings in identity_lineage_bindings.
 *
 * Does NOT modify the service_principals table — all data is stored in
 * the lineage tables.
 */

import type { Client } from "@microsoft/microsoft-graph-client";
import type { Pool } from "pg";

// ── Public types ────────────────────────────────────────────────────

export interface AppOwner {
  id: string;
  displayName: string;
  upn: string;
}

export interface InferredHost {
  url: string;
  hostType: "AppService" | "ContainerApp" | "CustomDomain";
  confidenceBoost: number;
}

export interface AppRegistrationMetadata {
  appId: string;
  displayName: string;
  replyUrls: string[];
  identifierUris: string[];
  notes: string | null;
  description: string | null;
  createdAt: Date;
  owners: AppOwner[];
  inferredHostUrls: InferredHost[];
  metadataConfidence: number;
}

// ── Graph API response types ────────────────────────────────────────

interface GraphApplication {
  id: string;
  appId: string;
  displayName: string;
  web?: { redirectUris?: string[] };
  publicClient?: { redirectUris?: string[] };
  identifierUris?: string[];
  notes?: string;
  description?: string;
  createdDateTime?: string;
}

interface GraphOwner {
  id: string;
  displayName?: string;
  userPrincipalName?: string;
}

// ── URL inference rules ─────────────────────────────────────────────

/**
 * Classify a URL from replyUrls / identifierUris:
 *   *.azurewebsites.net      → AppService       +20 confidence
 *   *.azurecontainerapps.io  → ContainerApp     +20 confidence
 *   anything else             → CustomDomain     +5  confidence
 */
export function classifyUrl(url: string): InferredHost {
  const lower = url.toLowerCase();
  if (lower.includes(".azurewebsites.net")) {
    return { url, hostType: "AppService", confidenceBoost: 20 };
  }
  if (lower.includes(".azurecontainerapps.io")) {
    return { url, hostType: "ContainerApp", confidenceBoost: 20 };
  }
  return { url, hostType: "CustomDomain", confidenceBoost: 5 };
}

/**
 * Deduplicate and classify all URLs from an app registration.
 */
function inferHostUrls(replyUrls: string[], identifierUris: string[]): InferredHost[] {
  const seen = new Set<string>();
  const results: InferredHost[] = [];

  for (const url of [...replyUrls, ...identifierUris]) {
    if (!url || seen.has(url)) continue;
    // Skip localhost and common non-production URLs
    const lower = url.toLowerCase();
    if (lower.includes("localhost") || lower.includes("127.0.0.1")) continue;
    if (lower === "urn:ietf:wg:oauth:2.0:oob") continue;
    seen.add(url);
    results.push(classifyUrl(url));
  }

  return results;
}

/**
 * Compute overall metadata confidence:
 *   Base: 40 (we have the app registration)
 *   +10 if owners are present
 *   +10 if notes or description is present
 *   + sum of inferredHostUrl confidence boosts (capped at +40)
 */
function computeConfidence(
  owners: AppOwner[],
  notes: string | null,
  description: string | null,
  inferredHosts: InferredHost[]
): number {
  let score = 40;
  if (owners.length > 0) score += 10;
  if (notes || description) score += 10;
  const hostBoost = inferredHosts.reduce((sum, h) => sum + h.confidenceBoost, 0);
  score += Math.min(hostBoost, 40);
  return Math.min(score, 100);
}

// ── Graph API calls ─────────────────────────────────────────────────

/**
 * Fetch app registration metadata and owners from MS Graph.
 *
 * Uses the **application** objectId (not the SPN objectId) — the caller
 * must resolve this from the SPN's `appId` field.
 *
 * Returns null if the app registration is not found (404).
 */
export async function getAppRegistrationMetadata(
  appObjectId: string,
  graphClient: Client
): Promise<AppRegistrationMetadata | null> {
  if (!appObjectId) return null;

  let app: GraphApplication;
  try {
    app = await graphClient
      .api(`/applications/${appObjectId}`)
      .select("id,appId,displayName,web,publicClient,identifierUris,notes,description,createdDateTime")
      .get();
  } catch (err: unknown) {
    if ((err as { statusCode?: number }).statusCode === 404) return null;
    console.error(
      `[AppRegistrationMiner] Failed to fetch app ${appObjectId}:`,
      err
    );
    return null;
  }

  // Collect reply URLs from both web and publicClient redirectUris
  const replyUrls = [
    ...(app.web?.redirectUris ?? []),
    ...(app.publicClient?.redirectUris ?? []),
  ];
  const identifierUris = app.identifierUris ?? [];

  // Fetch owners
  let owners: AppOwner[] = [];
  try {
    const ownerResp = await graphClient
      .api(`/applications/${appObjectId}/owners`)
      .select("id,displayName,userPrincipalName")
      .get();
    owners = ((ownerResp?.value ?? []) as GraphOwner[]).map((o) => ({
      id: o.id,
      displayName: o.displayName ?? "",
      upn: o.userPrincipalName ?? "",
    }));
  } catch {
    // Non-fatal — owners may be restricted
  }

  const inferredHostUrls = inferHostUrls(replyUrls, identifierUris);
  const metadataConfidence = computeConfidence(
    owners,
    app.notes ?? null,
    app.description ?? null,
    inferredHostUrls
  );

  return {
    appId: app.appId,
    displayName: app.displayName,
    replyUrls,
    identifierUris,
    notes: app.notes ?? null,
    description: app.description ?? null,
    createdAt: app.createdDateTime ? new Date(app.createdDateTime) : new Date(),
    owners,
    inferredHostUrls,
    metadataConfidence,
  };
}

// ── Persistence ─────────────────────────────────────────────────────

/**
 * Persist inferred host URL bindings as identity_lineage_bindings rows.
 *
 * Each inferredHostUrl becomes a separate row with:
 *   resource_type: the inferred host type (AppService / ContainerApp / CustomDomain)
 *   binding_method: "ReplyUrl"
 *   binding_evidence: { inferredHostUrls, owners }
 *
 * Upserts on (spn_id, resource_id, binding_method).
 */
export async function persistAppRegistrationBindings(
  db: Pool,
  spnId: string,
  connectionId: string,
  metadata: AppRegistrationMetadata
): Promise<void> {
  if (metadata.inferredHostUrls.length === 0) return;

  const values: unknown[] = [];
  const placeholders: string[] = [];
  let idx = 1;

  const evidence = {
    appId: metadata.appId,
    displayName: metadata.displayName,
    owners: metadata.owners.map((o) => ({ id: o.id, displayName: o.displayName, upn: o.upn })),
    allReplyUrls: metadata.replyUrls,
    identifierUris: metadata.identifierUris,
    notes: metadata.notes,
  };

  for (const host of metadata.inferredHostUrls) {
    placeholders.push(
      `($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++})`
    );
    values.push(
      spnId,
      connectionId,
      host.url,                               // resource_id = the URL itself
      host.hostType,                           // resource_type
      extractHostName(host.url),               // resource_name
      null,                                    // resource_group
      null,                                    // region
      "ReplyUrl",                              // binding_method
      JSON.stringify(evidence),
      metadata.metadataConfidence,
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

function extractHostName(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}
