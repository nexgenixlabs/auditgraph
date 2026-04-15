/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * Shared upsert utility for identity_lineage_bindings.
 *
 * Extracted to avoid duplicating the 10-column INSERT across multiple
 * AWS lineage modules. Same pattern as P1 Azure LineageOrchestrator.
 */

import type { Pool } from "pg";
import type { ResourceBinding } from "./types";

/**
 * Upsert a batch of resource bindings into identity_lineage_bindings.
 * Uses ON CONFLICT (spn_id, resource_id, binding_method) to update
 * existing rows and set last_verified_at = NOW().
 */
export async function upsertBindings(
  db: Pool,
  connectionId: string,
  spnId: string,
  bindings: ResourceBinding[]
): Promise<void> {
  if (bindings.length === 0) return;

  const values: unknown[] = [];
  const placeholders: string[] = [];
  let idx = 1;

  for (const b of bindings) {
    placeholders.push(
      `($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++})`
    );
    values.push(
      spnId,
      connectionId,
      b.resourceId,
      b.resourceType,
      b.resourceName,
      b.resourceGroup,
      b.region,
      b.bindingMethod,
      JSON.stringify(b.bindingEvidence),
      b.confidenceScore
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
       resource_group   = EXCLUDED.resource_group,
       region           = EXCLUDED.region,
       binding_evidence = EXCLUDED.binding_evidence,
       confidence_score = EXCLUDED.confidence_score,
       last_verified_at = NOW()`,
    values
  );
}
