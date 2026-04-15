/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * ECSTaskDefScanner — SDK scanner that finds ECS task definitions
 * whose taskRoleArn or executionRoleArn matches a given IAM role ARN.
 *
 * Uses `ecs:ListTaskDefinitionFamilies` + `ecs:DescribeTaskDefinition`.
 * Non-fatal per-family errors (DescribeTaskDefinition failure) don't abort.
 */

import type { ECSClient } from "@aws-sdk/client-ecs";
import {
  ListTaskDefinitionFamiliesCommand,
  DescribeTaskDefinitionCommand,
} from "@aws-sdk/client-ecs";
import pLimit from "p-limit";

import type { ResourceBinding } from "./types";

// ── Constants ───────────────────────────────────────────────────────

const ECS_CONCURRENCY = 10;

// ── Scanner ─────────────────────────────────────────────────────────

/**
 * Scan all ACTIVE ECS task definition families and check if any reference
 * the given role ARN as taskRoleArn or executionRoleArn.
 */
export async function scanECSTaskDefs(
  ecsClient: ECSClient,
  roleArn: string,
  accountId: string,
  region: string
): Promise<ResourceBinding[]> {
  if (!roleArn) return [];

  const bindings: ResourceBinding[] = [];
  const limit = pLimit(ECS_CONCURRENCY);

  // List all ACTIVE task definition families
  let nextToken: string | undefined;
  const families: string[] = [];

  do {
    const listResp = await ecsClient.send(
      new ListTaskDefinitionFamiliesCommand({
        status: "ACTIVE",
        nextToken,
      })
    );
    if (listResp.families) {
      families.push(...listResp.families);
    }
    nextToken = listResp.nextToken;
  } while (nextToken);

  if (families.length === 0) return [];

  // Describe each family (latest revision), check role ARNs
  const tasks = families.map((family) =>
    limit(async () => {
      try {
        const descResp = await ecsClient.send(
          new DescribeTaskDefinitionCommand({
            taskDefinition: family,
          })
        );

        const taskDef = descResp.taskDefinition;
        if (!taskDef) return;

        const taskRoleMatch = taskDef.taskRoleArn === roleArn;
        const execRoleMatch = taskDef.executionRoleArn === roleArn;

        if (taskRoleMatch) {
          bindings.push({
            resourceId: `ecs://${accountId}/${region}/${family}`,
            resourceType: "ECSTaskDefinition",
            resourceName: family,
            resourceGroup: "",
            region,
            bindingMethod: "TaskRole",
            bindingEvidence: {
              cloud: "aws",
              scanType: "ECSTaskRole",
              taskDefinitionArn: taskDef.taskDefinitionArn ?? "",
              matchedField: "taskRoleArn",
              matchedRoleArn: roleArn,
              revision: taskDef.revision,
              accountId,
            },
            confidenceScore: 95,
          });
        }

        if (execRoleMatch) {
          bindings.push({
            resourceId: `ecs://${accountId}/${region}/${family}`,
            resourceType: "ECSTaskDefinition",
            resourceName: family,
            resourceGroup: "",
            region,
            bindingMethod: "ExecutionRole",
            bindingEvidence: {
              cloud: "aws",
              scanType: "ECSExecutionRole",
              taskDefinitionArn: taskDef.taskDefinitionArn ?? "",
              matchedField: "executionRoleArn",
              matchedRoleArn: roleArn,
              revision: taskDef.revision,
              accountId,
            },
            confidenceScore: 95,
          });
        }
      } catch {
        // Non-fatal: individual family describe failure doesn't abort scan
      }
    })
  );

  await Promise.all(tasks);
  return bindings;
}
