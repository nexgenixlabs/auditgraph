/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * SignInActivityEnricher — enriches SPN lineage data with sign-in activity
 * signals from MS Graph's servicePrincipalSignInActivities endpoint.
 *
 * IMPORTANT: This does NOT replace the existing dormancy detection call.
 * It reuses the same Graph API result and writes enrichment data to the
 * identity_lineage_enrichment table for lineage-specific analysis.
 */

import type { Client } from "@microsoft/microsoft-graph-client";
import type { Pool } from "pg";

// ── Public types ────────────────────────────────────────────────────

export type SignInType = "NonInteractive" | "Delegated" | "Mixed" | "Never";

export interface SignInEnrichment {
  confirmedNHI: boolean;
  couldBeHuman: boolean;
  signInType: SignInType;
  dormancyDays: number;
  lastSignInAt: Date | null;
}

// ── Graph API response type ─────────────────────────────────────────

interface ServicePrincipalSignInActivity {
  id: string;
  lastSignInActivity?: {
    lastSignInDateTime?: string;
    lastNonInteractiveSignInDateTime?: string;
  };
  lastDelegatedSignInDateTime?: string;
  lastServicePrincipalSignInDateTime?: string;
}

// ── Core logic ──────────────────────────────────────────────────────

/**
 * Classify sign-in activity into an enrichment record.
 *
 * Rules (applied in order):
 *   1. nonInteractive set + delegated null → confirmedNHI, NonInteractive
 *   2. delegated set (regardless of nonInteractive) → couldBeHuman, Delegated
 *   3. both set → Mixed
 *   4. none set → Never
 *   5. dormancyDays = days since the most recent of all timestamps
 *
 * Note: rules 2 and 3 overlap intentionally — rule 3 catches the case where
 * both are present, overriding rule 2's Delegated with Mixed.
 */
export function classifySignInActivity(
  lastSignIn: string | null,
  lastNonInteractive: string | null,
  lastDelegated: string | null,
  lastServicePrincipal: string | null,
  now: Date = new Date()
): SignInEnrichment {
  const hasNonInteractive = lastNonInteractive !== null;
  const hasDelegated = lastDelegated !== null;
  const hasServicePrincipal = lastServicePrincipal !== null;
  const hasLastSignIn = lastSignIn !== null;

  // Determine signInType
  let signInType: SignInType;
  let confirmedNHI = false;
  let couldBeHuman = false;

  if (hasNonInteractive && hasDelegated) {
    // Rule 3: both set → Mixed
    signInType = "Mixed";
    couldBeHuman = true;
  } else if (hasDelegated) {
    // Rule 2: delegated set → Delegated
    signInType = "Delegated";
    couldBeHuman = true;
  } else if (hasNonInteractive || hasServicePrincipal) {
    // Rule 1: nonInteractive or SP set, no delegated → NonInteractive
    signInType = "NonInteractive";
    confirmedNHI = true;
  } else {
    // Rule 4: none set → Never
    signInType = "Never";
  }

  // Compute dormancyDays from most recent timestamp
  const timestamps = [lastSignIn, lastNonInteractive, lastDelegated, lastServicePrincipal]
    .filter((t): t is string => t !== null)
    .map((t) => new Date(t).getTime())
    .filter((t) => !Number.isNaN(t));

  let dormancyDays: number;
  let lastSignInAt: Date | null;

  if (timestamps.length > 0) {
    const mostRecent = Math.max(...timestamps);
    lastSignInAt = new Date(mostRecent);
    dormancyDays = Math.floor((now.getTime() - mostRecent) / (1000 * 60 * 60 * 24));
    if (dormancyDays < 0) dormancyDays = 0;
  } else {
    lastSignInAt = null;
    dormancyDays = -1; // Never signed in — distinct from "signed in 0 days ago"
  }

  return {
    confirmedNHI,
    couldBeHuman,
    signInType,
    dormancyDays,
    lastSignInAt,
  };
}

// ── Graph API call ──────────────────────────────────────────────────

/**
 * Fetch sign-in activity for an SPN from MS Graph and classify it.
 *
 * Uses: GET /v1.0/reports/servicePrincipalSignInActivities/{objectId}
 *
 * Returns a Never enrichment if the API returns 404 or fails.
 */
export async function enrichSignInActivity(
  objectId: string,
  graphClient: Client
): Promise<SignInEnrichment> {
  const NEVER: SignInEnrichment = {
    confirmedNHI: false,
    couldBeHuman: false,
    signInType: "Never",
    dormancyDays: -1,
    lastSignInAt: null,
  };

  if (!objectId) return NEVER;

  try {
    const activity: ServicePrincipalSignInActivity = await graphClient
      .api(`/reports/servicePrincipalSignInActivities/${objectId}`)
      .get();

    const lastSignIn =
      activity.lastSignInActivity?.lastSignInDateTime ?? null;
    const lastNonInteractive =
      activity.lastSignInActivity?.lastNonInteractiveSignInDateTime ?? null;
    const lastDelegated =
      activity.lastDelegatedSignInDateTime ?? null;
    const lastServicePrincipal =
      activity.lastServicePrincipalSignInDateTime ?? null;

    return classifySignInActivity(
      lastSignIn,
      lastNonInteractive,
      lastDelegated,
      lastServicePrincipal
    );
  } catch (err: unknown) {
    const status = (err as { statusCode?: number }).statusCode;
    if (status === 404) return NEVER;
    console.error(
      `[SignInActivityEnricher] Graph call failed for objectId=${objectId}:`,
      err
    );
    return NEVER;
  }
}

// ── Persistence ─────────────────────────────────────────────────────

/**
 * Persist sign-in enrichment to identity_lineage_enrichment.
 *
 * Uses a delete-then-insert pattern scoped to (spn_id, enrichment_source)
 * to maintain one enrichment row per SPN per source.
 *
 * enrichment_tier = "P1_SIGNIN" (matches the CHECK constraint on the table
 * and indicates this data comes from the P1-licensed sign-in activity API).
 */
export async function persistSignInEnrichment(
  db: Pool,
  spnId: string,
  connectionId: string,
  enrichment: SignInEnrichment
): Promise<void> {
  const source = "SPSignInActivity";

  // Remove stale row for this SPN + source
  await db.query(
    `DELETE FROM identity_lineage_enrichment
     WHERE spn_id = $1 AND enrichment_source = $2`,
    [spnId, source]
  );

  await db.query(
    `INSERT INTO identity_lineage_enrichment
       (spn_id, connection_id, enrichment_source, last_accessed_at,
        workload_type_inferred, sign_in_type, raw_signals, enrichment_tier)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      spnId,
      connectionId,
      source,
      enrichment.lastSignInAt,
      enrichment.confirmedNHI ? "ConfirmedNHI" : enrichment.couldBeHuman ? "PossibleHuman" : null,
      enrichment.signInType,
      JSON.stringify({
        confirmedNHI: enrichment.confirmedNHI,
        couldBeHuman: enrichment.couldBeHuman,
        dormancyDays: enrichment.dormancyDays,
        lastSignInAt: enrichment.lastSignInAt?.toISOString() ?? null,
      }),
      "P1_SIGNIN",
    ]
  );
}
