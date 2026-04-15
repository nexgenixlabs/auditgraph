/**
 * ResourcePolicyScanner unit tests.
 *
 *   1. S3 bucket policy with matching roleArn → binding from DB, source:"db"
 *   2. S3 bucket policy without roleArn → not returned
 *   3. KMS key policy match → binding confidence 92, source:"db"
 *   4. SQS queue match → binding source:"live"
 *   5. SNS topic match → binding source:"live"
 *   6. roleArn not in any policy → []
 *   7. Verify zero SDK calls for S3 and KMS queries
 *   8. Empty roleArn returns []
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@aws-sdk/client-sqs", () => ({
  SQSClient: vi.fn(),
  ListQueuesCommand: vi.fn().mockImplementation((input: any) => ({
    constructor: { name: "ListQueuesCommand" },
    input,
  })),
  GetQueueAttributesCommand: vi.fn().mockImplementation((input: any) => ({
    constructor: { name: "GetQueueAttributesCommand" },
    input,
  })),
}));

vi.mock("@aws-sdk/client-sns", () => ({
  SNSClient: vi.fn(),
  ListTopicsCommand: vi.fn().mockImplementation((input: any) => ({
    constructor: { name: "ListTopicsCommand" },
    input,
  })),
  GetTopicAttributesCommand: vi.fn().mockImplementation((input: any) => ({
    constructor: { name: "GetTopicAttributesCommand" },
    input,
  })),
}));

import {
  scanS3BucketPolicies,
  scanKmsKeyPolicies,
  scanSqsQueuePolicies,
  scanSnsTopicPolicies,
  scanResourcePolicies,
} from "../../aws/ResourcePolicyScanner";

const ROLE_ARN = "arn:aws:iam::123456789012:role/MyRole";
const ACCOUNT_ID = "123456789012";

// ── Mock DB pool ────────────────────────────────────────────────────

function mockPool(rows: unknown[]) {
  return {
    query: vi.fn().mockResolvedValue({ rows }),
  } as any;
}

// ── S3 tests (DB) ──────────────────────────────────────────────────

describe("scanS3BucketPolicies", () => {
  it("returns binding for bucket with matching principal", async () => {
    const policy = {
      Statement: [
        {
          Sid: "AllowRole",
          Effect: "Allow",
          Principal: { AWS: ROLE_ARN },
          Action: "s3:GetObject",
          Resource: "arn:aws:s3:::my-bucket/*",
        },
      ],
    };
    const db = mockPool([
      {
        bucket_name: "my-bucket",
        bucket_policy: policy,
        aws_account_id: ACCOUNT_ID,
      },
    ]);

    const result = await scanS3BucketPolicies(ROLE_ARN, ACCOUNT_ID, db);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      resourceType: "S3Bucket",
      resourceName: "my-bucket",
      source: "db",
      confidenceScore: 88,
      statementSid: "AllowRole",
    });
  });

  it("skips bucket where roleArn is not in Principal.AWS", async () => {
    const policy = {
      Statement: [
        {
          Effect: "Allow",
          Principal: { AWS: "arn:aws:iam::999999999999:role/Other" },
          Action: "s3:GetObject",
        },
      ],
    };
    const db = mockPool([
      {
        bucket_name: "other-bucket",
        bucket_policy: policy,
        aws_account_id: ACCOUNT_ID,
      },
    ]);

    const result = await scanS3BucketPolicies(ROLE_ARN, ACCOUNT_ID, db);
    expect(result).toEqual([]);
  });

  it("returns [] for empty roleArn", async () => {
    const db = mockPool([]);
    const result = await scanS3BucketPolicies("", ACCOUNT_ID, db);
    expect(result).toEqual([]);
    expect(db.query).not.toHaveBeenCalled();
  });

  it("does not make any SDK calls", async () => {
    const db = mockPool([]);
    await scanS3BucketPolicies(ROLE_ARN, ACCOUNT_ID, db);
    // Only DB query, no SDK calls
    expect(db.query).toHaveBeenCalledTimes(1);
  });
});

// ── KMS tests (DB) ─────────────────────────────────────────────────

describe("scanKmsKeyPolicies", () => {
  it("returns binding with confidence 92 and source:'db'", async () => {
    const policy = {
      Statement: [
        {
          Sid: "EnableKeyAccess",
          Effect: "Allow",
          Principal: { AWS: [ROLE_ARN, "arn:aws:iam::123:root"] },
          Action: "kms:Decrypt",
        },
      ],
    };
    const db = mockPool([
      {
        key_id: "abc-123",
        key_policy: policy,
        aws_account_id: ACCOUNT_ID,
        key_arn: "arn:aws:kms:us-east-1:123456789012:key/abc-123",
      },
    ]);

    const result = await scanKmsKeyPolicies(ROLE_ARN, ACCOUNT_ID, db);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      resourceType: "KMSKey",
      resourceName: "abc-123",
      source: "db",
      confidenceScore: 92,
      statementSid: "EnableKeyAccess",
    });
  });

  it("skips Deny statements", async () => {
    const policy = {
      Statement: [
        {
          Effect: "Deny",
          Principal: { AWS: ROLE_ARN },
          Action: "kms:*",
        },
      ],
    };
    const db = mockPool([
      {
        key_id: "deny-key",
        key_policy: policy,
        aws_account_id: ACCOUNT_ID,
        key_arn: "arn:aws:kms:us-east-1:123:key/deny-key",
      },
    ]);

    const result = await scanKmsKeyPolicies(ROLE_ARN, ACCOUNT_ID, db);
    expect(result).toEqual([]);
  });

  it("does not make any SDK calls", async () => {
    const db = mockPool([]);
    await scanKmsKeyPolicies(ROLE_ARN, ACCOUNT_ID, db);
    expect(db.query).toHaveBeenCalledTimes(1);
  });
});

// ── SQS tests (live SDK) ──────────────────────────────────────────

describe("scanSqsQueuePolicies", () => {
  it("returns binding with source:'live' for matching queue", async () => {
    const policy = JSON.stringify({
      Statement: [
        {
          Sid: "AllowSQS",
          Effect: "Allow",
          Principal: { AWS: ROLE_ARN },
          Action: "sqs:SendMessage",
        },
      ],
    });

    const sqsClient = {
      send: vi.fn().mockImplementation((cmd: any) => {
        const name = cmd.constructor?.name;
        if (name === "ListQueuesCommand") {
          return {
            QueueUrls: [
              "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue",
            ],
            NextToken: undefined,
          };
        }
        if (name === "GetQueueAttributesCommand") {
          return {
            Attributes: {
              Policy: policy,
              QueueArn:
                "arn:aws:sqs:us-east-1:123456789012:my-queue",
            },
          };
        }
        return {};
      }),
    } as any;

    const result = await scanSqsQueuePolicies(
      ROLE_ARN,
      sqsClient,
      "us-east-1"
    );

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      resourceType: "SQSQueue",
      resourceName: "my-queue",
      source: "live",
      confidenceScore: 85,
      statementSid: "AllowSQS",
    });
  });

  it("returns [] when no queues exist", async () => {
    const sqsClient = {
      send: vi.fn().mockResolvedValue({
        QueueUrls: [],
        NextToken: undefined,
      }),
    } as any;

    const result = await scanSqsQueuePolicies(
      ROLE_ARN,
      sqsClient,
      "us-east-1"
    );
    expect(result).toEqual([]);
  });
});

// ── SNS tests (live SDK) ──────────────────────────────────────────

describe("scanSnsTopicPolicies", () => {
  it("returns binding with source:'live' for matching topic", async () => {
    const policy = JSON.stringify({
      Statement: [
        {
          Sid: "AllowSNS",
          Effect: "Allow",
          Principal: { AWS: ROLE_ARN },
          Action: "sns:Publish",
        },
      ],
    });

    const snsClient = {
      send: vi.fn().mockImplementation((cmd: any) => {
        const name = cmd.constructor?.name;
        if (name === "ListTopicsCommand") {
          return {
            Topics: [
              {
                TopicArn:
                  "arn:aws:sns:us-east-1:123456789012:my-topic",
              },
            ],
            NextToken: undefined,
          };
        }
        if (name === "GetTopicAttributesCommand") {
          return {
            Attributes: { Policy: policy },
          };
        }
        return {};
      }),
    } as any;

    const result = await scanSnsTopicPolicies(
      ROLE_ARN,
      snsClient,
      "us-east-1"
    );

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      resourceType: "SNSTopic",
      resourceName: "my-topic",
      source: "live",
      confidenceScore: 85,
      statementSid: "AllowSNS",
    });
  });
});

// ── Combined scan tests ────────────────────────────────────────────

describe("scanResourcePolicies", () => {
  it("combines all four sources", async () => {
    // S3 policy in DB
    const s3Policy = {
      Statement: [
        {
          Effect: "Allow",
          Principal: { AWS: ROLE_ARN },
          Action: "s3:*",
        },
      ],
    };

    let dbCallCount = 0;
    const db = {
      query: vi.fn().mockImplementation(() => {
        dbCallCount++;
        if (dbCallCount === 1) {
          return {
            rows: [
              {
                bucket_name: "b1",
                bucket_policy: s3Policy,
                aws_account_id: ACCOUNT_ID,
              },
            ],
          };
        }
        return { rows: [] }; // KMS empty
      }),
    } as any;

    // SQS returns no queues
    const sqsClient = {
      send: vi.fn().mockResolvedValue({
        QueueUrls: [],
        NextToken: undefined,
      }),
    } as any;

    // SNS returns no topics
    const snsClient = {
      send: vi.fn().mockResolvedValue({
        Topics: [],
        NextToken: undefined,
      }),
    } as any;

    const result = await scanResourcePolicies(
      ROLE_ARN,
      ACCOUNT_ID,
      db,
      sqsClient,
      snsClient,
      "us-east-1"
    );

    // Only S3 match
    expect(result).toHaveLength(1);
    expect(result[0].resourceType).toBe("S3Bucket");
  });

  it("returns [] for empty roleArn", async () => {
    const db = mockPool([]);
    const sqsClient = { send: vi.fn() } as any;
    const snsClient = { send: vi.fn() } as any;

    const result = await scanResourcePolicies(
      "",
      ACCOUNT_ID,
      db,
      sqsClient,
      snsClient,
      "us-east-1"
    );
    expect(result).toEqual([]);
  });
});
