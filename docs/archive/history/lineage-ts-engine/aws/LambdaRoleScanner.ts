/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * LambdaRoleScanner — DB-only scanner that finds Lambda functions
 * whose execution_role_arn matches a given IAM role ARN.
 *
 * No SDK calls — reads directly from `aws_lambda_functions.execution_role_arn`.
 */

import type { Pool } from "pg";
import type { ResourceBinding } from "./types";
import { upsertBindings } from "./upsertBindings";

/**
 * Find Lambda functions that use the given role as their execution role.
 */
export async function scanLambdaForRole(
  db: Pool,
  roleArn: string,
  connectionId: string
): Promise<ResourceBinding[]> {
  if (!roleArn) return [];

  const { rows } = await db.query(
    `SELECT l.resource_id, l.name, l.region, l.aws_account_id,
            l.runtime, l.memory_size
     FROM aws_lambda_functions l
     JOIN discovery_runs dr ON dr.id = l.discovery_run_id
     WHERE dr.cloud_connection_id = $1
       AND l.execution_role_arn = $2`,
    [connectionId, roleArn]
  );

  return rows.map(
    (row: {
      resource_id: string;
      name: string;
      region: string;
      aws_account_id: string;
      runtime: string;
      memory_size: number;
    }) => ({
      resourceId: `lambda://${row.aws_account_id}/${row.region}/${row.name}`,
      resourceType: "LambdaFunction",
      resourceName: row.name,
      resourceGroup: "",
      region: row.region ?? "",
      bindingMethod: "ExecutionRole",
      bindingEvidence: {
        cloud: "aws",
        scanType: "LambdaExecutionRole",
        functionArn: row.resource_id,
        matchedRoleArn: roleArn,
        runtime: row.runtime,
        memorySize: row.memory_size,
        accountId: row.aws_account_id,
      },
      confidenceScore: 95,
    })
  );
}

/**
 * Scan and persist Lambda execution role bindings.
 */
export async function persistLambdaBindings(
  db: Pool,
  spnId: string,
  connectionId: string,
  roleArn: string
): Promise<ResourceBinding[]> {
  const bindings = await scanLambdaForRole(db, roleArn, connectionId);
  await upsertBindings(db, connectionId, spnId, bindings);
  return bindings;
}
