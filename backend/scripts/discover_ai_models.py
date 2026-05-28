#!/usr/bin/env python3
"""
Phase 2.1 — Standalone AI Model Discovery trigger.

Discovers Cognitive Services / Azure OpenAI accounts + their model deployments
for a given org's cloud connection, and persists to:
  - azure_cognitive_services_accounts
  - azure_ai_model_deployments

This answers "which model is this AI agent using?" from architecture alone —
no logs / telemetry required.

Usage:
  python scripts/discover_ai_models.py --org-id 10 --connection-id 87

Credentials are read from the cloud_connections row (azure_directory_id,
client_id, client_secret). Persists under the latest completed discovery_run
for the connection (so the API enrichment picks it up immediately).
"""
import argparse
import os
import sys

try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env.local')
    if os.path.exists(env_path):
        load_dotenv(env_path)
except ImportError:
    pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def main():
    ap = argparse.ArgumentParser(description='Discover Azure AI model deployments for an org connection.')
    ap.add_argument('--org-id', type=int, required=True)
    ap.add_argument('--connection-id', type=int, required=True)
    ap.add_argument('--skip-resources', action='store_true',
                    help='Only discover AI models; skip storage/KV network inventory')
    args = ap.parse_args()

    # Credentials live in cloud_connections.metadata (JSONB) — read via the
    # same admin accessor the scheduler uses (bypasses RLS, includes secrets).
    from app.database import Database
    admin_db = Database()
    try:
        connections = admin_db.get_cloud_connections(args.org_id, include_secrets=True)
    finally:
        admin_db.close()
    conn_row = next((c for c in connections if c['id'] == args.connection_id), None)
    if not conn_row:
        sys.exit(f"No cloud_connection id={args.connection_id} for org {args.org_id}")
    metadata = conn_row.get('metadata') or {}
    directory_id = conn_row.get('azure_directory_id')
    client_id = conn_row.get('client_id')
    client_secret = metadata.get('client_secret')
    if not all([directory_id, client_id, client_secret]):
        sys.exit("Connection has incomplete credentials (directory_id / client_id / client_secret).")

    # Latest completed run for this connection — we attach deployments to it
    import psycopg2
    conn = psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        port=int(os.environ.get('DB_PORT', '5434')),
        dbname=os.environ.get('DB_NAME', 'auditgraph'),
        user=os.environ.get('DB_ADMIN_USER', os.environ.get('DB_USER', 'auditgraph')),
        password=os.environ.get('DB_ADMIN_PASSWORD', os.environ.get('DB_PASSWORD', 'auditgraph')),
        sslmode=os.environ.get('DB_SSLMODE', 'prefer'),
    )
    cur = conn.cursor()
    cur.execute("""
        SELECT id FROM discovery_runs
        WHERE cloud_connection_id = %s AND status = 'completed'
        ORDER BY id DESC LIMIT 1
    """, (args.connection_id,))
    run_row = cur.fetchone()
    if not run_row:
        sys.exit("No completed discovery_run for this connection — run a scan first.")
    run_id = run_row[0]
    cur.close()
    conn.close()

    print(f"Discovering AI models for org={args.org_id} connection={args.connection_id} run={run_id} ...")

    from app.engines.discovery.azure_discovery import AzureDiscoveryEngine
    engine = AzureDiscoveryEngine(
        azure_directory_id=directory_id,
        client_id=client_id,
        client_secret=client_secret,
        db_org_id=args.org_id,
        cloud_connection_id=args.connection_id,
    )
    result = engine.discover_cognitive_services_and_deployments(run_id)
    print(f"AI models — accounts: {result['accounts']}  deployments: {result['deployments']}")

    # Phase 2.2: also collect storage / key-vault / resource network posture so
    # the egress-verdict feature has data (architecture-only network exposure).
    if not args.skip_resources:
        try:
            from app.database import Database
            from app.engines.resource_inventory_collector import ResourceInventoryCollector
            sub_ids = [s['id'] for s in getattr(engine, 'subscriptions', []) if s.get('id')]
            if sub_ids:
                rdb = Database(organization_id=args.org_id)
                try:
                    collector = ResourceInventoryCollector(engine.credential, sub_ids, rdb, args.org_id)
                    stats = collector.collect_and_persist(run_id)
                    print(f"Resource inventory — enumerated: {stats.get('total_resources', 0)}  "
                          f"persisted: {stats.get('persisted', 0)} (storage/KV network posture)")
                finally:
                    rdb.close()
            else:
                print("Resource inventory — no subscriptions resolved; skipped.")
        except Exception as e:
            print(f"Resource inventory — skipped ({e})")

    print("Re-open any AI agent in the drawer: 'Models Reachable' + per-resource egress verdicts.")


if __name__ == '__main__':
    main()
