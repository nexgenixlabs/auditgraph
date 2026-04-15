"""
AWS CloudTrail Ingestion Service — ingests CloudTrail management events
and backfills identity activity status from real API audit data.

Follows the same pattern as p2_ingestion.py (P2TelemetryService).

Required IAM permissions:
    - cloudtrail:LookupEvents
"""

import json
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


class AWSCloudTrailService:
    """Ingest CloudTrail events and backfill identity activity data."""

    def __init__(self, session, db, aws_account_id):
        """
        Args:
            session: boto3.Session with AWS credentials
            db: Database instance (with organization context set)
            aws_account_id: The AWS account ID for isolation validation
        """
        self.session = session
        self.db = db
        self.aws_account_id = aws_account_id
        self._client = None

    def _get_client(self):
        if self._client is None:
            self._client = self.session.client('cloudtrail')
        return self._client

    def ingest_events(self, run_id, organization_id, cloud_connection_id,
                      lookback_days=7):
        """Fetch CloudTrail events and bulk-insert into aws_cloudtrail_events.

        Returns total number of events ingested.
        """
        client = self._get_client()
        start_time = datetime.now(timezone.utc) - timedelta(days=lookback_days)

        # Build identity ARN → db_id map from current run's identities
        cursor = self.db.conn.cursor()
        cursor.execute(
            "SELECT id, identity_id FROM identities WHERE discovery_run_id = %s",
            (run_id,)
        )
        id_map = {}
        for row in cursor.fetchall():
            if row[1]:
                id_map[row[1]] = row[0]
        cursor.close()

        total_ingested = 0
        next_token = None

        while True:
            try:
                kwargs = {
                    'StartTime': start_time,
                    'MaxResults': 50,
                }
                if next_token:
                    kwargs['NextToken'] = next_token

                resp = client.lookup_events(**kwargs)
            except Exception as e:
                logger.error("CloudTrail lookup_events failed: %s", e)
                break

            events = resp.get('Events', [])
            if not events:
                break

            rows = []
            for evt in events:
                # Parse the CloudTrailEvent JSON blob
                try:
                    detail = json.loads(evt.get('CloudTrailEvent', '{}'))
                except (json.JSONDecodeError, TypeError):
                    detail = {}

                # Resolve identity
                user_identity = detail.get('userIdentity', {})
                identity_arn = user_identity.get('arn', '')
                identity_db_id = id_map.get(identity_arn)

                # Also try matching by principalId or accessKeyId
                if not identity_db_id:
                    principal_id = user_identity.get('principalId', '')
                    identity_db_id = id_map.get(principal_id)
                if not identity_db_id:
                    # Try role session: arn may be session ARN, map to role ARN
                    if ':assumed-role/' in identity_arn:
                        # Convert session ARN to role ARN
                        parts = identity_arn.split('/')
                        if len(parts) >= 2:
                            role_name = parts[1] if len(parts) > 1 else ''
                            account = identity_arn.split(':')[4] if ':' in identity_arn else ''
                            role_arn = f"arn:aws:iam::{account}:role/{role_name}"
                            identity_db_id = id_map.get(role_arn)

                event_time = evt.get('EventTime')
                if isinstance(event_time, datetime) and event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)

                rows.append((
                    organization_id,
                    identity_db_id,
                    identity_arn,
                    evt.get('EventId'),
                    evt.get('EventName'),
                    evt.get('EventSource'),
                    event_time,
                    detail.get('awsRegion'),
                    detail.get('sourceIPAddress'),
                    detail.get('userAgent'),
                    detail.get('errorCode'),
                    detail.get('errorMessage'),
                    json.dumps(detail.get('requestParameters') or {}),
                    json.dumps(detail.get('responseElements') or {}),
                    json.dumps(evt.get('Resources') or []),
                    detail.get('readOnly', False),
                    detail.get('managementEvent', True),
                    detail.get('eventCategory', 'Management'),
                    run_id,
                    self.aws_account_id,
                    cloud_connection_id,
                ))

            if rows:
                cursor = self.db.conn.cursor()
                from psycopg2.extras import execute_values
                execute_values(cursor, """
                    INSERT INTO aws_cloudtrail_events
                    (organization_id, identity_db_id, identity_id, event_id,
                     event_name, event_source, event_time, aws_region,
                     source_ip_address, user_agent, error_code, error_message,
                     request_parameters, response_elements, resources,
                     read_only, management_event, event_category,
                     discovery_run_id, aws_account_id, cloud_connection_id)
                    VALUES %s
                    ON CONFLICT DO NOTHING
                """, rows)
                self.db._commit()
                cursor.close()
                total_ingested += len(rows)

            next_token = resp.get('NextToken')
            if not next_token:
                break

        logger.info("Ingested %s CloudTrail events for account %s",
                     total_ingested, self.aws_account_id)
        return total_ingested

    def backfill_last_activity(self, run_id):
        """Update identities.last_sign_in and activity_status from CloudTrail events.

        Only updates when CloudTrail timestamp is more recent than existing value.
        Same pattern as P2's backfill_last_sign_in().
        """
        cursor = self.db.conn.cursor()
        try:
            # Update last_sign_in from CloudTrail events (only if more recent)
            cursor.execute("""
                UPDATE identities i
                SET last_sign_in = sub.latest,
                    activity_status = CASE
                        WHEN sub.latest > NOW() - INTERVAL '90 days' THEN 'active'
                        ELSE 'stale'
                    END
                FROM (
                    SELECT identity_db_id, MAX(event_time) AS latest
                    FROM aws_cloudtrail_events
                    WHERE discovery_run_id = %s AND identity_db_id IS NOT NULL
                    GROUP BY identity_db_id
                ) sub
                WHERE i.id = sub.identity_db_id
                  AND (i.last_sign_in IS NULL OR sub.latest > i.last_sign_in)
            """, (run_id,))
            updated = cursor.rowcount
            self.db._commit()
            if updated:
                logger.info("Backfilled last_sign_in for %s identities from CloudTrail",
                            updated)
            return updated
        except Exception as e:
            self.db._rollback()
            logger.error("CloudTrail last_sign_in backfill error: %s", e)
            return 0
        finally:
            cursor.close()
