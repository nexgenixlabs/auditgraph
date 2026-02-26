#!/usr/bin/env python3
"""
Phase 6 Task 0a: Synthetic Data Seeder for Performance Testing

Seeds 500+ identities, 150 role assignments, 60 resources, drift events,
and 30 days of discovery run history for a given tenant.

Usage:
    python scripts/seed_performance_data.py [--tenant-id 1] [--clean]
"""
import os
import sys
import random
import argparse
import uuid
from datetime import datetime, timedelta, timezone

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv()

from app.database import Database

# ── Configuration ─────────────────────────────────────────────────────────────

IDENTITY_COUNT = 520
ROLE_ASSIGNMENT_COUNT = 160
STORAGE_ACCOUNT_COUNT = 35
KEY_VAULT_COUNT = 25
DISCOVERY_RUN_DAYS = 30

# Realistic Azure-style names
FIRST_NAMES = [
    'James', 'Mary', 'Robert', 'Patricia', 'John', 'Jennifer', 'Michael',
    'Linda', 'David', 'Elizabeth', 'William', 'Barbara', 'Richard', 'Susan',
    'Joseph', 'Jessica', 'Thomas', 'Sarah', 'Charles', 'Karen', 'Daniel',
    'Lisa', 'Matthew', 'Nancy', 'Anthony', 'Betty', 'Mark', 'Margaret',
    'Donald', 'Sandra', 'Steven', 'Ashley', 'Paul', 'Dorothy', 'Andrew',
    'Kimberly', 'Joshua', 'Emily', 'Kenneth', 'Donna', 'Kevin', 'Michelle',
    'Brian', 'Carol', 'George', 'Amanda', 'Timothy', 'Melissa', 'Ronald',
]

LAST_NAMES = [
    'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller',
    'Davis', 'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez',
    'Wilson', 'Anderson', 'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin',
    'Lee', 'Perez', 'Thompson', 'White', 'Harris', 'Sanchez', 'Clark',
    'Ramirez', 'Lewis', 'Robinson', 'Walker', 'Young', 'Allen', 'King',
    'Wright', 'Scott', 'Torres', 'Nguyen', 'Hill', 'Flores', 'Green',
    'Adams', 'Nelson', 'Baker', 'Hall', 'Rivera', 'Campbell', 'Mitchell',
]

DEPARTMENTS = [
    'Engineering', 'Security', 'Operations', 'Finance', 'Compliance',
    'IT Infrastructure', 'DevOps', 'Data Analytics', 'Clinical Systems',
    'Network Operations', 'Identity & Access', 'Cloud Architecture',
]

SPN_NAMES = [
    'ehr-data-sync', 'hipaa-audit-service', 'patient-portal-api',
    'claims-processor', 'rx-integration', 'lab-results-importer',
    'appointment-scheduler', 'billing-gateway', 'insurance-verifier',
    'medical-imaging-pipeline', 'hl7-fhir-bridge', 'consent-manager',
    'telehealth-connector', 'clinical-decision-support', 'pharmacy-integrator',
    'radiology-pacs-sync', 'bed-management-api', 'vitals-aggregator',
    'nurse-call-integration', 'supply-chain-tracker', 'compliance-scanner',
    'backup-orchestrator', 'log-aggregation-svc', 'alert-dispatcher',
    'identity-sync-agent', 'certificate-rotator', 'secret-scanner',
    'vulnerability-tracker', 'patch-management-svc', 'config-drift-monitor',
    'cost-analyzer', 'resource-tagger', 'policy-enforcer',
    'network-watcher-svc', 'dns-zone-manager', 'waf-rule-updater',
    'container-scanner', 'image-builder-pipeline', 'terraform-runner',
    'ansible-automation', 'grafana-datasource', 'prometheus-scraper',
]

AZURE_ROLES = [
    'Owner', 'Contributor', 'Reader', 'User Access Administrator',
    'Security Admin', 'Security Reader', 'Storage Blob Data Reader',
    'Storage Blob Data Contributor', 'Key Vault Administrator',
    'Key Vault Secrets Officer', 'Key Vault Reader', 'Virtual Machine Contributor',
    'Network Contributor', 'SQL DB Contributor', 'Monitoring Reader',
    'Log Analytics Reader', 'Backup Operator', 'Managed Identity Operator',
]

SUBSCRIPTION_NAMES = [
    'NGH-Production', 'NGH-Staging', 'NGH-Development', 'NGH-DR',
    'NGH-Compliance-Sandbox', 'NGH-Research', 'NGH-SharedServices',
]

RESOURCE_GROUPS = [
    'rg-ehr-prod', 'rg-patient-data', 'rg-analytics', 'rg-networking',
    'rg-security', 'rg-backup', 'rg-shared', 'rg-compliance',
    'rg-imaging', 'rg-telehealth', 'rg-billing', 'rg-infrastructure',
]

LOCATIONS = ['eastus', 'eastus2', 'westus2', 'centralus', 'northeurope']


def gen_uuid():
    return str(uuid.uuid4())


def gen_subscription_id():
    return gen_uuid()


def weighted_choice(choices_weights):
    """choices_weights = [(value, weight), ...]"""
    values, weights = zip(*choices_weights)
    return random.choices(values, weights=weights, k=1)[0]


def seed_discovery_runs(db, tenant_id, sub_ids, sub_names):
    """Create 30 days of discovery runs."""
    runs = []
    now = datetime.now(timezone.utc)
    cursor = db.conn.cursor()

    for day in range(DISCOVERY_RUN_DAYS, 0, -1):
        started = now - timedelta(days=day, hours=random.randint(1, 6))
        completed = started + timedelta(minutes=random.randint(2, 15))
        total = random.randint(480, 530)
        critical = random.randint(20, 35)
        high = random.randint(60, 90)
        medium = random.randint(120, 180)
        low_count = total - critical - high - medium

        cursor.execute("""
            INSERT INTO discovery_runs
            (subscription_id, subscription_name, started_at, completed_at, status,
             total_identities, critical_count, high_count, medium_count, low_count, tenant_id)
            VALUES (%s, %s, %s, %s, 'completed', %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            sub_ids[0], sub_names[0][:250],
            started, completed, total, critical, high, medium, low_count, tenant_id
        ))
        run_id = cursor.fetchone()[0]
        runs.append({'id': run_id, 'started_at': started, 'total': total})

    db.conn.commit()
    cursor.close()
    print(f"  Created {len(runs)} discovery runs")
    return runs


def seed_identities(db, tenant_id, latest_run_id):
    """Create 520 identities across all categories."""
    cursor = db.conn.cursor()
    identity_ids = []

    # Distribution: 200 human, 150 SPN, 80 system MI, 50 user MI, 30 guest, 10 microsoft
    categories = (
        [('human_user', i) for i in range(200)] +
        [('service_principal', i) for i in range(150)] +
        [('managed_identity_system', i) for i in range(80)] +
        [('managed_identity_user', i) for i in range(50)] +
        [('guest', i) for i in range(30)] +
        [('microsoft_internal', i) for i in range(10)]
    )

    for cat, idx in categories:
        identity_id = gen_uuid()
        object_id = gen_uuid()
        app_id = gen_uuid() if cat in ('service_principal',) else None

        # Generate realistic names
        if cat == 'human_user':
            first = random.choice(FIRST_NAMES)
            last = random.choice(LAST_NAMES)
            display_name = f'{first} {last}'
            upn = f'{first.lower()}.{last.lower()}@nexgenhealthcare.com'
            dept = random.choice(DEPARTMENTS)
        elif cat == 'service_principal':
            display_name = random.choice(SPN_NAMES) + f'-{idx:03d}'
            upn = None
            dept = None
        elif cat == 'managed_identity_system':
            display_name = f'sys-mi-{random.choice(RESOURCE_GROUPS)}-{idx:02d}'
            upn = None
            dept = None
        elif cat == 'managed_identity_user':
            display_name = f'umi-{random.choice(SPN_NAMES)[:20]}-{idx:02d}'
            upn = None
            dept = None
        elif cat == 'guest':
            first = random.choice(FIRST_NAMES)
            last = random.choice(LAST_NAMES)
            display_name = f'{first} {last} (Guest)'
            upn = f'{first.lower()}.{last.lower()}_ext@nexgenhealthcare.com'
            dept = None
        else:  # microsoft_internal
            display_name = f'Microsoft.{random.choice(SPN_NAMES)[:15]}'
            upn = None
            dept = None

        # Risk distribution
        risk_level = weighted_choice([
            ('critical', 5), ('high', 15), ('medium', 30), ('low', 50)
        ])
        risk_score = {
            'critical': random.randint(76, 100),
            'high': random.randint(51, 75),
            'medium': random.randint(26, 50),
            'low': random.randint(0, 25),
        }[risk_level]

        # Activity
        activity_status = weighted_choice([
            ('active', 50), ('inactive', 20), ('stale', 15),
            ('never_used', 10), ('unknown', 5)
        ])

        # Credentials
        cred_status = weighted_choice([
            ('good', 40), ('warning', 20), ('expired', 15),
            ('critical', 10), ('unknown', 15)
        ])

        now = datetime.now(timezone.utc)
        last_sign_in = now - timedelta(days=random.randint(0, 365)) if activity_status == 'active' else None
        created_dt = now - timedelta(days=random.randint(30, 730))
        cred_exp = now + timedelta(days=random.randint(-90, 365)) if cat in ('service_principal', 'managed_identity_user') else None

        enabled = activity_status != 'inactive'
        is_ms = cat == 'microsoft_internal'

        # Map category to identity_type
        type_map = {
            'human_user': 'user', 'service_principal': 'servicePrincipal',
            'managed_identity_system': 'managedIdentity', 'managed_identity_user': 'managedIdentity',
            'guest': 'user', 'microsoft_internal': 'servicePrincipal',
        }
        identity_type = type_map.get(cat, 'user')

        cursor.execute("""
            INSERT INTO identities
            (discovery_run_id, identity_id, display_name, identity_category,
             identity_type, app_id, object_id, enabled, is_microsoft_system,
             risk_level, risk_score, risk_reasons,
             credential_expiration, credential_status,
             activity_status, last_sign_in, created_datetime,
             source, cloud, status, upn, department, tenant_id,
             api_permission_count, app_role_count, owner_count,
             pim_eligible_count, pim_active_count)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (discovery_run_id, identity_id) DO NOTHING
            RETURNING id
        """, (
            latest_run_id, identity_id, display_name, cat,
            identity_type, app_id, object_id, enabled, is_ms,
            risk_level, risk_score,
            '{' + ','.join([f'"{r}"' for r in random.sample([
                'Dormant with high privileges', 'Expired credentials',
                'Owner role on production', 'No MFA configured',
                'Cross-tenant access', 'Excessive permissions',
                'Stale service principal', 'Missing owner',
                'High blast radius', 'Credential expiring soon',
            ], min(3, random.randint(0, 5)))]) + '}',
            cred_exp, cred_status,
            activity_status, last_sign_in, created_dt,
            'azure', 'azure', 'active' if enabled else 'disabled',
            upn, dept, tenant_id,
            random.randint(0, 25), random.randint(0, 10), random.randint(0, 3),
            random.randint(0, 5), random.randint(0, 2),
        ))
        row = cursor.fetchone()
        if row:
            identity_ids.append({'db_id': row[0], 'identity_id': identity_id, 'category': cat})

    db.conn.commit()
    cursor.close()
    print(f"  Created {len(identity_ids)} identities")
    return identity_ids


def seed_role_assignments(db, tenant_id, identity_ids, sub_ids):
    """Create 160 role assignments spread across identities."""
    cursor = db.conn.cursor()
    count = 0

    # Pick identities that get role assignments (not all need them)
    candidates = random.sample(identity_ids, min(ROLE_ASSIGNMENT_COUNT, len(identity_ids)))

    for ident in candidates:
        sub_id = random.choice(sub_ids)
        rg = random.choice(RESOURCE_GROUPS)
        role = random.choice(AZURE_ROLES)

        scope_type = weighted_choice([
            ('subscription', 30), ('resource_group', 50), ('resource', 20)
        ])
        if scope_type == 'subscription':
            scope = f'/subscriptions/{sub_id}'
        elif scope_type == 'resource_group':
            scope = f'/subscriptions/{sub_id}/resourceGroups/{rg}'
        else:
            scope = f'/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/sa{random.randint(1,35):03d}'

        cursor.execute("""
            INSERT INTO role_assignments
            (identity_db_id, role_name, scope, scope_type, principal_id, assignment_id, tenant_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (
            ident['db_id'], role, scope, scope_type,
            ident['identity_id'], gen_uuid(), tenant_id
        ))
        count += 1

    db.conn.commit()
    cursor.close()
    print(f"  Created {count} role assignments")


def seed_resources(db, tenant_id, latest_run_id, sub_ids):
    """Create 60 resources (35 storage accounts + 25 key vaults)."""
    cursor = db.conn.cursor()

    # Storage accounts
    for i in range(STORAGE_ACCOUNT_COUNT):
        sub_id = random.choice(sub_ids)
        rg = random.choice(RESOURCE_GROUPS)
        name = f'sa{random.choice(["ehr","patient","analytics","backup","logs","imaging","billing"])}{i:03d}'
        resource_id = f'/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}'

        risk_level = weighted_choice([('critical', 10), ('high', 20), ('medium', 40), ('low', 30)])
        risk_score = {'critical': random.randint(76, 100), 'high': random.randint(51, 75),
                      'medium': random.randint(26, 50), 'low': random.randint(0, 25)}[risk_level]

        # Some have PHI/PCI classifications
        classification = None
        if i < 10:
            classification = random.choice(['PHI', 'PCI', 'PII', 'Confidential'])

        cursor.execute("""
            INSERT INTO azure_storage_accounts
            (discovery_run_id, resource_id, name, location, resource_group,
             subscription_id, subscription_name, sku, kind, access_tier,
             public_blob_access, https_only, minimum_tls_version,
             shared_key_access, default_network_action,
             risk_level, risk_score, blast_radius_score,
             data_classification, tenant_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (discovery_run_id, resource_id) DO NOTHING
        """, (
            latest_run_id, resource_id, name,
            random.choice(LOCATIONS), rg, sub_id,
            random.choice(SUBSCRIPTION_NAMES),
            random.choice(['Standard_LRS', 'Standard_GRS', 'Premium_LRS']),
            random.choice(['StorageV2', 'BlobStorage']),
            random.choice(['Hot', 'Cool']),
            random.random() < 0.15,  # 15% public blob
            True, 'TLS1_2',
            random.random() < 0.3,  # 30% shared key
            random.choice(['Allow', 'Deny']),
            risk_level, risk_score,
            random.randint(1, 10),
            classification, tenant_id,
        ))

    # Key vaults
    for i in range(KEY_VAULT_COUNT):
        sub_id = random.choice(sub_ids)
        rg = random.choice(RESOURCE_GROUPS)
        name = f'kv-{random.choice(["ehr","secrets","certs","keys","config","tls"])}-{i:03d}'
        resource_id = f'/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}'

        risk_level = weighted_choice([('critical', 15), ('high', 25), ('medium', 35), ('low', 25)])
        risk_score = {'critical': random.randint(76, 100), 'high': random.randint(51, 75),
                      'medium': random.randint(26, 50), 'low': random.randint(0, 25)}[risk_level]

        classification = None
        if i < 10:
            classification = random.choice(['PHI', 'PCI', 'PII', 'Confidential'])

        cursor.execute("""
            INSERT INTO azure_key_vaults
            (discovery_run_id, resource_id, name, location, resource_group,
             subscription_id, subscription_name, sku,
             soft_delete_enabled, soft_delete_retention_days, purge_protection,
             enable_rbac_authorization, public_network_access, default_network_action,
             secrets_total, secrets_expired, secrets_expiring_soon,
             keys_total, keys_expired, keys_expiring_soon,
             risk_level, risk_score, blast_radius_score,
             data_classification, tenant_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (discovery_run_id, resource_id) DO NOTHING
        """, (
            latest_run_id, resource_id, name,
            random.choice(LOCATIONS), rg, sub_id,
            random.choice(SUBSCRIPTION_NAMES),
            random.choice(['standard', 'premium']),
            True, 90, random.random() > 0.2,
            random.random() > 0.4,
            random.choice(['Enabled', 'Disabled']),
            random.choice(['Allow', 'Deny']),
            random.randint(5, 50), random.randint(0, 5), random.randint(0, 8),
            random.randint(2, 20), random.randint(0, 3), random.randint(0, 5),
            risk_level, risk_score,
            random.randint(1, 10),
            classification, tenant_id,
        ))

    db.conn.commit()
    cursor.close()
    print(f"  Created {STORAGE_ACCOUNT_COUNT} storage accounts + {KEY_VAULT_COUNT} key vaults")


def seed_drift_reports(db, tenant_id, runs):
    """Create drift reports between consecutive runs."""
    cursor = db.conn.cursor()
    count = 0

    for i in range(1, len(runs)):
        prev_run = runs[i - 1]
        curr_run = runs[i]

        new_count = random.randint(0, 5)
        removed_count = random.randint(0, 3)
        perm_changes = random.randint(0, 8)
        risk_changes = random.randint(0, 6)
        cred_changes = random.randint(0, 4)
        total = new_count + removed_count + perm_changes + risk_changes + cred_changes

        cursor.execute("""
            INSERT INTO drift_reports
            (current_run_id, previous_run_id, new_identities_count, removed_identities_count,
             permission_changes_count, risk_changes_count, credential_changes_count,
             total_changes, changes, tenant_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (current_run_id, previous_run_id) DO NOTHING
        """, (
            curr_run['id'], prev_run['id'],
            new_count, removed_count, perm_changes, risk_changes, cred_changes,
            total, '{}', tenant_id,
        ))
        count += 1

    db.conn.commit()
    cursor.close()
    print(f"  Created {count} drift reports")


def seed_cloud_subscriptions(db, tenant_id, sub_ids, sub_names):
    """Create cloud subscription records."""
    cursor = db.conn.cursor()

    for sub_id, sub_name in zip(sub_ids, sub_names):
        monitored = random.random() > 0.3  # 70% activated
        cursor.execute("""
            INSERT INTO cloud_subscriptions
            (tenant_id, cloud, account_id, account_name, status, monitored,
             activated_at, rate_cents)
            VALUES (%s, 'azure', %s, %s, %s, %s, %s, 6900)
            ON CONFLICT (tenant_id, cloud, account_id) DO NOTHING
        """, (
            tenant_id, sub_id, sub_name,
            'active' if monitored else 'discovered',
            monitored,
            datetime.now(timezone.utc) if monitored else None,
        ))

    db.conn.commit()
    cursor.close()
    print(f"  Created {len(sub_ids)} cloud subscriptions")


def clean_test_data(db, tenant_id):
    """Remove all seeded data for the tenant."""
    cursor = db.conn.cursor()
    # Order matters due to FK constraints
    tables = [
        'drift_reports', 'role_assignments', 'azure_storage_accounts',
        'azure_key_vaults', 'identities', 'discovery_runs', 'cloud_subscriptions',
    ]
    for table in tables:
        cursor.execute(f"DELETE FROM {table} WHERE tenant_id = %s", (tenant_id,))
        print(f"  Cleaned {table}: {cursor.rowcount} rows")
    db.conn.commit()
    cursor.close()


def main():
    parser = argparse.ArgumentParser(description='Seed performance test data')
    parser.add_argument('--tenant-id', type=int, default=1, help='Tenant ID to seed data for')
    parser.add_argument('--clean', action='store_true', help='Remove existing test data first')
    args = parser.parse_args()

    print(f"=== AuditGraph Performance Data Seeder ===")
    print(f"Tenant ID: {args.tenant_id}")

    # Use admin DB to bypass RLS
    db = Database()

    try:
        if args.clean:
            print("\nCleaning existing data...")
            clean_test_data(db, args.tenant_id)

        # Generate subscription IDs
        sub_ids = [gen_subscription_id() for _ in range(len(SUBSCRIPTION_NAMES))]

        print("\n1. Seeding cloud subscriptions...")
        seed_cloud_subscriptions(db, args.tenant_id, sub_ids, SUBSCRIPTION_NAMES)

        print("\n2. Seeding discovery runs (30 days)...")
        runs = seed_discovery_runs(db, args.tenant_id, sub_ids, SUBSCRIPTION_NAMES)

        latest_run_id = runs[-1]['id']
        print(f"   Latest run ID: {latest_run_id}")

        print("\n3. Seeding identities (520)...")
        identity_ids = seed_identities(db, args.tenant_id, latest_run_id)

        print("\n4. Seeding role assignments (160)...")
        seed_role_assignments(db, args.tenant_id, identity_ids, sub_ids)

        print("\n5. Seeding resources (60)...")
        seed_resources(db, args.tenant_id, latest_run_id, sub_ids)

        print("\n6. Seeding drift reports...")
        seed_drift_reports(db, args.tenant_id, runs)

        print("\n=== Seeding Complete ===")
        print(f"  Identities: {len(identity_ids)}")
        print(f"  Role assignments: {ROLE_ASSIGNMENT_COUNT}")
        print(f"  Resources: {STORAGE_ACCOUNT_COUNT + KEY_VAULT_COUNT}")
        print(f"  Discovery runs: {len(runs)}")
        print(f"  Drift reports: {len(runs) - 1}")

    finally:
        db.close()


if __name__ == '__main__':
    main()
