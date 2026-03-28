/**
 * @deprecated 2026-03-27 — Lineage engine unified under Python.
 * Python discovery engine is the single source of truth.
 * Retained as reference for Phase 2 Python reimplementation.
 */
/**
 * ResourcePolicyScanner — discovers resource policies referencing a given
 * IAM role ARN across S3, KMS, SQS, and SNS.
 *
 * S3 + KMS: DB-first (bucket_policy / key_policy JSONB already stored by
 *   discovery engine). ILIKE pre-filter + JSONB principal parsing.
 * SQS + SNS: Live SDK calls (no cached tables in the DB).
 *
 * Confidence scores:
 *   S3  → 88   KMS → 92   SQS → 85   SNS → 85
 */

import type { Pool } from "pg";
import type { SQSClient } from "@aws-sdk/client-sqs";
import {
  ListQueuesCommand,
  GetQueueAttributesCommand,
} from "@aws-sdk/client-sqs";
import type { SNSClient } from "@aws-sdk/client-sns";
import {
  ListTopicsCommand,
  GetTopicAttributesCommand,
} from "@aws-sdk/client-sns";

import type { ResourceBinding, ResourcePolicyRef } from "./types";
import { upsertBindings } from "./upsertBindings";

// ── Helpers ─────────────────────────────────────────────────────────

interface PolicyStatement {
  Sid?: string;
  Effect?: string;
  Principal?: Record<string, string | string[]> | string;
  Action?: string | string[];
  Resource?: string | string[];
  Condition?: Record<string, Record<string, string | string[]>>;
}

/**
 * Check if a policy statement's Principal.AWS contains the roleArn.
 * Supports Principal: "*", Principal: { AWS: "arn:..." },
 * and Principal: { AWS: ["arn:...", ...] }.
 */
function statementMatchesPrincipal(
  stmt: PolicyStatement,
  roleArn: string
): boolean {
  if (stmt.Effect?.toLowerCase() === "deny") return false;

  const principal = stmt.Principal;
  if (!principal) return false;

  // Principal: "*"
  if (principal === "*") return true;

  if (typeof principal === "object") {
    const aws = (principal as Record<string, string | string[]>).AWS;
    if (!aws) return false;
    const awsList = Array.isArray(aws) ? aws : [aws];
    return awsList.some((a) => a === roleArn || a === "*");
  }

  return false;
}

/**
 * Extract the first matching Sid from a parsed policy document.
 */
function findMatchingSid(
  policyDoc: { Statement?: PolicyStatement[] },
  roleArn: string
): string {
  if (!policyDoc?.Statement) return "";
  const match = policyDoc.Statement.find((s) =>
    statementMatchesPrincipal(s, roleArn)
  );
  return match?.Sid ?? "";
}

// ── S3 bucket policy scanner (DB) ───────────────────────────────────

export async function scanS3BucketPolicies(
  roleArn: string,
  accountId: string,
  db: Pool
): Promise<ResourcePolicyRef[]> {
  if (!roleArn) return [];

  const { rows } = await db.query(
    `SELECT bucket_name, bucket_policy, aws_account_id
     FROM aws_s3_buckets
     WHERE aws_account_id = $1
       AND bucket_policy IS NOT NULL
       AND bucket_policy::text ILIKE $2`,
    [accountId, `%${roleArn}%`]
  );

  const results: ResourcePolicyRef[] = [];
  for (const row of rows) {
    const policy =
      typeof row.bucket_policy === "string"
        ? JSON.parse(row.bucket_policy)
        : row.bucket_policy;

    if (!policy?.Statement) continue;

    const hasMatch = policy.Statement.some((s: PolicyStatement) =>
      statementMatchesPrincipal(s, roleArn)
    );
    if (!hasMatch) continue;

    results.push({
      resourceArn: `arn:aws:s3:::${row.bucket_name}`,
      resourceType: "S3Bucket",
      resourceName: row.bucket_name,
      statementSid: findMatchingSid(policy, roleArn),
      source: "db",
      confidenceScore: 88,
    });
  }

  return results;
}

// ── KMS key policy scanner (DB) ─────────────────────────────────────

export async function scanKmsKeyPolicies(
  roleArn: string,
  accountId: string,
  db: Pool
): Promise<ResourcePolicyRef[]> {
  if (!roleArn) return [];

  const { rows } = await db.query(
    `SELECT key_id, key_policy, aws_account_id, key_arn
     FROM aws_kms_keys
     WHERE aws_account_id = $1
       AND key_policy IS NOT NULL
       AND key_policy::text ILIKE $2`,
    [accountId, `%${roleArn}%`]
  );

  const results: ResourcePolicyRef[] = [];
  for (const row of rows) {
    const policy =
      typeof row.key_policy === "string"
        ? JSON.parse(row.key_policy)
        : row.key_policy;

    if (!policy?.Statement) continue;

    const hasMatch = policy.Statement.some((s: PolicyStatement) =>
      statementMatchesPrincipal(s, roleArn)
    );
    if (!hasMatch) continue;

    results.push({
      resourceArn: row.key_arn ?? `arn:aws:kms:::key/${row.key_id}`,
      resourceType: "KMSKey",
      resourceName: row.key_id,
      statementSid: findMatchingSid(policy, roleArn),
      source: "db",
      confidenceScore: 92,
    });
  }

  return results;
}

// ── SQS queue policy scanner (live SDK) ─────────────────────────────

/**
 * Extract queue name from SQS URL.
 * Format: https://sqs.{region}.amazonaws.com/{account}/{queueName}
 */
function extractQueueName(queueUrl: string): string {
  const parts = queueUrl.split("/");
  return parts[parts.length - 1] ?? queueUrl;
}

export async function scanSqsQueuePolicies(
  roleArn: string,
  sqsClient: SQSClient,
  region: string
): Promise<ResourcePolicyRef[]> {
  if (!roleArn) return [];

  const results: ResourcePolicyRef[] = [];
  let nextToken: string | undefined;

  do {
    const listResp = await sqsClient.send(
      new ListQueuesCommand({ NextToken: nextToken })
    );
    const queueUrls = listResp.QueueUrls ?? [];
    nextToken = listResp.NextToken;

    for (const queueUrl of queueUrls) {
      try {
        const attrResp = await sqsClient.send(
          new GetQueueAttributesCommand({
            QueueUrl: queueUrl,
            AttributeNames: ["Policy", "QueueArn"],
          })
        );

        const policyStr = attrResp.Attributes?.Policy;
        if (!policyStr) continue;

        const policy = JSON.parse(policyStr);
        if (!policy?.Statement) continue;

        const hasMatch = policy.Statement.some((s: PolicyStatement) =>
          statementMatchesPrincipal(s, roleArn)
        );
        if (!hasMatch) continue;

        const queueName = extractQueueName(queueUrl);
        results.push({
          resourceArn:
            attrResp.Attributes?.QueueArn ??
            `arn:aws:sqs:${region}::${queueName}`,
          resourceType: "SQSQueue",
          resourceName: queueName,
          statementSid: findMatchingSid(policy, roleArn),
          source: "live",
          confidenceScore: 85,
        });
      } catch {
        // Non-fatal: skip queues we can't read
      }
    }
  } while (nextToken);

  return results;
}

// ── SNS topic policy scanner (live SDK) ─────────────────────────────

/**
 * Extract topic name from SNS ARN.
 * Format: arn:aws:sns:{region}:{account}:{topicName}
 */
function extractTopicName(topicArn: string): string {
  const parts = topicArn.split(":");
  return parts[parts.length - 1] ?? topicArn;
}

export async function scanSnsTopicPolicies(
  roleArn: string,
  snsClient: SNSClient,
  region: string
): Promise<ResourcePolicyRef[]> {
  if (!roleArn) return [];

  const results: ResourcePolicyRef[] = [];
  let nextToken: string | undefined;

  do {
    const listResp = await snsClient.send(
      new ListTopicsCommand({ NextToken: nextToken })
    );
    const topics = listResp.Topics ?? [];
    nextToken = listResp.NextToken;

    for (const topic of topics) {
      if (!topic.TopicArn) continue;

      try {
        const attrResp = await snsClient.send(
          new GetTopicAttributesCommand({ TopicArn: topic.TopicArn })
        );

        const policyStr = attrResp.Attributes?.Policy;
        if (!policyStr) continue;

        const policy = JSON.parse(policyStr);
        if (!policy?.Statement) continue;

        const hasMatch = policy.Statement.some((s: PolicyStatement) =>
          statementMatchesPrincipal(s, roleArn)
        );
        if (!hasMatch) continue;

        results.push({
          resourceArn: topic.TopicArn,
          resourceType: "SNSTopic",
          resourceName: extractTopicName(topic.TopicArn),
          statementSid: findMatchingSid(policy, roleArn),
          source: "live",
          confidenceScore: 85,
        });
      } catch {
        // Non-fatal: skip topics we can't read
      }
    }
  } while (nextToken);

  return results;
}

// ── Combined scanner ────────────────────────────────────────────────

/**
 * Scan all four resource policy sources for a given role ARN.
 * S3 + KMS from DB (no SDK calls), SQS + SNS from live SDK.
 */
export async function scanResourcePolicies(
  roleArn: string,
  accountId: string,
  db: Pool,
  sqsClient: SQSClient,
  snsClient: SNSClient,
  region: string
): Promise<ResourcePolicyRef[]> {
  if (!roleArn) return [];

  const [s3, kms, sqs, sns] = await Promise.all([
    scanS3BucketPolicies(roleArn, accountId, db),
    scanKmsKeyPolicies(roleArn, accountId, db),
    scanSqsQueuePolicies(roleArn, sqsClient, region),
    scanSnsTopicPolicies(roleArn, snsClient, region),
  ]);

  return [...s3, ...kms, ...sqs, ...sns];
}

// ── Persistence ─────────────────────────────────────────────────────

/**
 * Convert a ResourcePolicyRef to a ResourceBinding for persistence.
 */
function toResourceBinding(ref: ResourcePolicyRef): ResourceBinding {
  const resourceIdMap: Record<ResourcePolicyRef["resourceType"], string> = {
    S3Bucket: `resource-policy://s3/${ref.resourceName}`,
    KMSKey: `resource-policy://kms/${ref.resourceName}`,
    SQSQueue: `resource-policy://sqs/${ref.resourceName}`,
    SNSTopic: `resource-policy://sns/${ref.resourceName}`,
  };

  return {
    resourceId: resourceIdMap[ref.resourceType],
    resourceType: ref.resourceType,
    resourceName: ref.resourceName,
    resourceGroup: "",
    region: "",
    bindingMethod: "ResourcePolicyReference",
    bindingEvidence: { ...ref, cloud: "aws" },
    confidenceScore: ref.confidenceScore,
  };
}

/**
 * Persist resource policy refs as identity_lineage_bindings rows.
 */
export async function persistResourcePolicyBindings(
  db: Pool,
  spnId: string,
  connectionId: string,
  refs: ResourcePolicyRef[]
): Promise<void> {
  const bindings = refs.map(toResourceBinding);
  await upsertBindings(db, connectionId, spnId, bindings);
}
