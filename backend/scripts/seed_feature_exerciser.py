#!/usr/bin/env python3
"""
AG-DEMO-FEATURE-EXERCISER (2026-06-10)
======================================

Plants demo identities + populates field distributions on the AuditGraph
Demo org (org_id=9 locally) so EVERY feature surface has data to render.

Why this exists
---------------
Founder review (2026-06-10): new Identity Security Graph pages (Human
Access, Human Governance, NHI Governance, NHI Secrets, Attack Paths
scoped, etc.) all rendered "No identities in scope" because the
existing demo identities had:

  - 0 mfa_status set                 → Human Access can't show MFA gaps
  - 0 credential_status='expired'    → NHI Secrets shows empty
  - 0 credential_risk='expiring_soon'→ NHI Secrets shows empty
  - 0 ai_agents in org=9             → AI bucket empty
  - 8 of 291 had owner_display_name  → Ownership Center sparse
  - 0 federated identities           → CI/CD attack paths blank

This script fixes both:

  1. UPDATEs existing org=9 demo identities so MFA / credential / owner
     fields have realistic distributions (most healthy, a meaningful tail
     unhealthy so the feature surfaces actually have something to show).

  2. INSERTs ~15 named "demo-feature-*" identities each one explicitly
     exercising a specific feature surface (NHI Secrets > Expired,
     NHI Governance > Sub-Owner, Human Access > No MFA + Privileged, etc).
     Naming makes it obvious in the UI what each row is demonstrating.

Safety guardrails (HARD)
------------------------
  - Refuses to run if not org_id=9 (AuditGraph Demo).
  - NEVER deletes existing identities — INSERT + UPDATE only.
  - All planted identities have display_name prefixed `demo-*` and
    owner_display_name='AuditGraph Demo' so they're unmistakable.
  - Idempotent: re-runs detect existing demo-feature-* rows by
    identity_id and UPDATE in place rather than re-INSERT.

Run from backend/: `python3 scripts/seed_feature_exerciser.py`
"""

import os
import sys
import uuid
import random
import logging
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2
from psycopg2.extras import RealDictCursor, Json

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
log = logging.getLogger("feature_exerciser")

DEMO_ORG_ID = 9
DEMO_OWNER = "AuditGraph Demo"
NOW = datetime.now(timezone.utc)

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5434"))
DB_NAME = os.environ.get("DB_NAME", "auditgraph")
DB_USER = os.environ.get("DB_ADMIN_USER", "auditgraph")
DB_PASS = os.environ.get("DB_ADMIN_PASSWORD", "auditgraph")


def connect():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASS, cursor_factory=RealDictCursor,
    )


def verify_safe(cur):
    cur.execute("SELECT name FROM organizations WHERE id=%s", (DEMO_ORG_ID,))
    row = cur.fetchone()
    if not row:
        raise SystemExit(f"FATAL: org_id={DEMO_ORG_ID} does not exist")
    if "demo" not in row["name"].lower():
        raise SystemExit(
            f"FATAL: org_id={DEMO_ORG_ID} is '{row['name']}', not a demo org. "
            f"This script only operates on demo orgs."
        )
    log.info(f"Safety check passed: org_id={DEMO_ORG_ID} is '{row['name']}'")


def latest_run_id(cur):
    cur.execute(
        "SELECT discovery_run_id, COUNT(*) AS c FROM identities "
        "WHERE organization_id=%s GROUP BY discovery_run_id ORDER BY c DESC LIMIT 1",
        (DEMO_ORG_ID,),
    )
    row = cur.fetchone()
    if not row:
        raise SystemExit("No identities in demo org — run the base demo seeder first")
    return row["discovery_run_id"]


# ─── Step 1: UPDATE existing demo identities with realistic distributions ───

def populate_mfa_distribution(cur, run_id):
    """
    For humans: ~55% enabled, ~20% disabled, ~15% unknown, ~10% NULL (Entra P2 missing).
    Disabled-MFA humans are the headline finding the page surfaces.
    """
    # Reset to a known base — then deterministic-random by id
    cur.execute("""
        UPDATE identities
        SET mfa_status = CASE
            WHEN id %% 100 < 55 THEN 'enabled'
            WHEN id %% 100 < 75 THEN 'disabled'
            WHEN id %% 100 < 90 THEN 'unknown'
            ELSE NULL
        END
        WHERE organization_id=%s AND discovery_run_id=%s
          AND identity_category IN ('human_user', 'guest')
    """, (DEMO_ORG_ID, run_id))
    log.info(f"MFA distribution applied to {cur.rowcount} human identities")


def populate_stale_humans(cur, run_id):
    """~15% of humans haven't signed in for 90+ days."""
    stale_cutoff = NOW - timedelta(days=120)
    cur.execute("""
        UPDATE identities
        SET last_seen_auth = %s,
            activity_status = 'stale'
        WHERE organization_id=%s AND discovery_run_id=%s
          AND identity_category='human_user' AND id %% 7 = 0
    """, (stale_cutoff, DEMO_ORG_ID, run_id))
    log.info(f"Marked {cur.rowcount} humans as stale (>120d)")


def populate_credential_distribution(cur, run_id):
    """
    For SPNs:
      ~8% expired secrets
      ~12% expiring within 30d
      ~5% federated only (no static secret)
      rest healthy / no creds
    """
    # Expired
    cur.execute("""
        UPDATE identities
        SET credential_status='expired',
            credential_risk='expired',
            credential_expiration = %s,
            credential_count = 1,
            credential_age_days = 400
        WHERE organization_id=%s AND discovery_run_id=%s
          AND identity_category='service_principal' AND id %% 12 = 0
    """, (NOW - timedelta(days=30), DEMO_ORG_ID, run_id))
    expired_n = cur.rowcount

    # Expiring soon
    cur.execute("""
        UPDATE identities
        SET credential_status='valid',
            credential_risk='expiring_soon',
            credential_expiration = %s,
            credential_count = 1,
            credential_age_days = 350
        WHERE organization_id=%s AND discovery_run_id=%s
          AND identity_category='service_principal' AND id %% 12 = 1
    """, (NOW + timedelta(days=15), DEMO_ORG_ID, run_id))
    expiring_n = cur.rowcount

    # Federated only — GitHub Actions / Terraform Cloud / Azure DevOps
    issuers = ['github_actions', 'terraform_cloud', 'azure_devops']
    cur.execute("""
        UPDATE identities
        SET has_federated_credentials=true,
            federated_trust=true,
            is_federated=true,
            federated_issuer_types = %s,
            federated_cred_count = 1,
            credential_count = 0,
            credential_expiration = NULL,
            credential_status = NULL
        WHERE organization_id=%s AND discovery_run_id=%s
          AND identity_category='service_principal' AND id %% 17 = 0
    """, (Json(issuers), DEMO_ORG_ID, run_id))
    fed_n = cur.rowcount

    log.info(f"Credentials: {expired_n} expired, {expiring_n} expiring<30d, {fed_n} federated-only")


def populate_owner_distribution(cur, run_id):
    """~50% of NHIs get an owner so Ownership Center shows mixed state."""
    cur.execute("""
        UPDATE identities
        SET owner_display_name = CASE
            WHEN id %% 5 = 0 THEN 'Sarah Chen'
            WHEN id %% 5 = 1 THEN 'David Kim'
            WHEN id %% 5 = 2 THEN 'Jessica Lee'
            ELSE owner_display_name
            END,
            owner_count = CASE WHEN id %% 5 <= 2 THEN 1 ELSE owner_count END,
            owner_status = CASE WHEN id %% 5 <= 2 THEN 'owned' ELSE owner_status END
        WHERE organization_id=%s AND discovery_run_id=%s
          AND identity_category IN ('service_principal','managed_identity_system','managed_identity_user')
    """, (DEMO_ORG_ID, run_id))
    log.info(f"Owner distribution applied to {cur.rowcount} NHIs")


def populate_blast_radius(cur, run_id):
    """Diversify blast_radius_score across NHIs."""
    cur.execute("""
        UPDATE identities
        SET blast_radius_score = CASE
            WHEN id %% 9 = 0 THEN 95
            WHEN id %% 9 = 1 THEN 80
            WHEN id %% 9 = 2 THEN 65
            WHEN id %% 9 = 3 THEN 50
            WHEN id %% 9 = 4 THEN 35
            ELSE 15
            END,
            can_escalate = (id %% 11 = 0)
        WHERE organization_id=%s AND discovery_run_id=%s
          AND identity_category IN ('service_principal','managed_identity_system','managed_identity_user')
    """, (DEMO_ORG_ID, run_id))
    log.info(f"Blast radius distribution applied to {cur.rowcount} NHIs")


def populate_data_classifications(cur, run_id):
    """
    Tag a meaningful sample of storage accounts + key vaults with
    PHI / PCI / PII so the CISO Business Impact rollup shows realistic
    asset counts. Idempotent: UPDATE never re-classifies an already-
    classified row to a different value.
    """
    # Storage accounts: ~30% PHI, ~25% PCI, ~20% PII, rest unclassified.
    cur.execute("""
        UPDATE azure_storage_accounts
        SET data_classification = CASE
            WHEN id %% 10 < 3 THEN 'PHI'
            WHEN id %% 10 < 5 THEN 'PCI'
            WHEN id %% 10 < 7 THEN 'PII'
            ELSE data_classification
            END
        WHERE discovery_run_id = %s
          AND (data_classification IS NULL OR data_classification = '')
    """, (run_id,))
    storage_n = cur.rowcount

    # Key vaults: tag a few as PHI / PCI so the "Key Vault" critical-asset
    # signal lights up too.
    cur.execute("""
        UPDATE azure_key_vaults
        SET data_classification = CASE
            WHEN id %% 5 = 0 THEN 'PHI'
            WHEN id %% 5 = 1 THEN 'PCI'
            ELSE data_classification
            END
        WHERE discovery_run_id = %s
          AND (data_classification IS NULL OR data_classification = '')
    """, (run_id,))
    kv_n = cur.rowcount

    log.info(f"Data classifications applied to {storage_n} storage + {kv_n} key vaults")


def populate_pim_eligibility(cur, run_id):
    """~20% of privileged humans are PIM-eligible (the good state)."""
    cur.execute("""
        UPDATE identities
        SET pim_eligible_count = CASE WHEN risk_score >= 70 AND id %% 5 = 0 THEN 1 ELSE 0 END,
            pim_active_count = CASE WHEN risk_score >= 70 AND id %% 5 = 0 THEN 1 ELSE 0 END
        WHERE organization_id=%s AND discovery_run_id=%s
          AND identity_category IN ('human_user', 'guest')
    """, (DEMO_ORG_ID, run_id))
    log.info(f"PIM eligibility applied to {cur.rowcount} humans")


# ─── Step 2: INSERT named hero demo identities ──────────────────────────────

HERO_IDENTITIES = [
    # NHI Secrets surface
    dict(name="demo-spn-expired-secret-01",      cat="service_principal", risk_level="critical", risk_score=78,
         credential_status="expired", credential_risk="expired",
         credential_age_days=400, credential_count=1,
         exp_offset_days=-30, feature="NHI Secrets · Expired bucket"),
    dict(name="demo-spn-expiring-3days-01",       cat="service_principal", risk_level="high", risk_score=65,
         credential_status="valid", credential_risk="expiring_soon",
         credential_age_days=362, credential_count=1,
         exp_offset_days=3, feature="NHI Secrets · Expiring < 30d bucket"),
    dict(name="demo-spn-github-actions-fic-01",   cat="service_principal", risk_level="high", risk_score=72,
         federated=["github_actions"], credential_count=0,
         feature="NHI Secrets · Federated-only + CI/CD Attack Paths"),
    dict(name="demo-spn-terraform-cloud-fic-01",  cat="service_principal", risk_level="high", risk_score=70,
         federated=["terraform_cloud"], credential_count=0,
         feature="NHI Secrets · Federated-only + CI/CD Attack Paths"),

    # NHI Governance surface
    dict(name="demo-spn-orphan-critical-01",      cat="service_principal", risk_level="critical", risk_score=85,
         no_owner=True, blast_radius=92,
         feature="NHI Governance · Human owner policy violation"),
    dict(name="demo-spn-sub-owner-violation-01",  cat="service_principal", risk_level="critical", risk_score=88,
         no_owner=False, can_escalate=True, blast_radius=95,
         feature="NHI Governance · Subscription Owner policy violation"),
    dict(name="demo-spn-blast-radius-high-01",    cat="service_principal", risk_level="high", risk_score=74,
         blast_radius=88, feature="NHI Governance · Blast radius cap"),

    # Human Access surface
    dict(name="demo-human-no-mfa-priv-01",        cat="human_user", risk_level="critical", risk_score=82,
         mfa_status="disabled", upn="demo.nomfa.priv@auditgraph-demo.com",
         department="Engineering", job_title="Cloud Admin",
         feature="Human Access · No MFA + Privileged"),
    dict(name="demo-human-stale-180d-01",         cat="human_user", risk_level="medium", risk_score=42,
         mfa_status="enabled", stale_days=180,
         upn="demo.stale@auditgraph-demo.com",
         department="Sales", job_title="Account Executive",
         feature="Human Access · Stale > 90d"),
    dict(name="demo-human-unknown-mfa-01",        cat="human_user", risk_level="high", risk_score=68,
         mfa_status="unknown",
         upn="demo.mfaunknown@auditgraph-demo.com",
         department="Operations", job_title="DevOps Engineer",
         feature="Human Access · Unknown MFA (no Entra P2)"),

    # Human Governance surface
    dict(name="demo-guest-permanent-01",          cat="guest", risk_level="high", risk_score=58,
         mfa_status="disabled",
         upn="demo.guest.permanent@partner-corp.com",
         feature="Human Governance · Guest lifecycle policy"),
    dict(name="demo-human-standing-admin-01",     cat="human_user", risk_level="critical", risk_score=92,
         mfa_status="enabled", pim_eligible=False,
         upn="demo.standing.admin@auditgraph-demo.com",
         department="Platform", job_title="Subscription Owner",
         feature="Human Governance · No standing admin policy"),

    # AI Identity surface (AI agents missing entirely from current demo)
    dict(name="demo-ai-agent-copilot-overpriv-01", cat="service_principal", identity_type="ai_agent",
         risk_level="critical", risk_score=89,
         feature="AI Inventory + AI Access · Overprivileged AI agent"),
    dict(name="demo-ai-agent-rag-indexer-01",      cat="service_principal", identity_type="ai_agent",
         risk_level="high", risk_score=74,
         feature="AI Inventory · RAG indexer reaching Storage"),
    dict(name="demo-ai-agent-claude-connector-01", cat="service_principal", identity_type="ai_agent",
         risk_level="high", risk_score=76,
         feature="AI Inventory · Anthropic connector for Unified Identity Graph"),
]


def upsert_hero_identities(cur, run_id):
    """
    Insert (or update) the hero demo identities. Idempotent by identity_id
    which is deterministic from the demo name.
    """
    planted = []
    for hero in HERO_IDENTITIES:
        identity_id = f"demo-{hero['name']}-id"
        display_name = hero["name"]
        identity_category = hero["cat"]
        identity_type = hero.get("identity_type", identity_category)
        risk_level = hero["risk_level"]
        risk_score = hero["risk_score"]
        mfa = hero.get("mfa_status")
        upn = hero.get("upn")
        department = hero.get("department")
        job_title = hero.get("job_title")
        cred_status = hero.get("credential_status")
        cred_risk = hero.get("credential_risk")
        cred_count = hero.get("credential_count", 0)
        cred_age = hero.get("credential_age_days", 0)
        exp_offset = hero.get("exp_offset_days")
        cred_exp = NOW + timedelta(days=exp_offset) if exp_offset is not None else None
        federated = hero.get("federated")
        has_fed = bool(federated)
        no_owner = hero.get("no_owner", False)
        owner_name = None if no_owner else DEMO_OWNER
        owner_count = 0 if no_owner else 1
        owner_status = "unowned" if no_owner else "owned"
        blast_radius = hero.get("blast_radius", 0)
        can_escalate = hero.get("can_escalate", False)
        stale_days = hero.get("stale_days")
        last_seen = NOW - timedelta(days=stale_days) if stale_days else (NOW - timedelta(days=2))
        activity = "stale" if stale_days and stale_days > 90 else "active"

        cur.execute(
            "SELECT id FROM identities WHERE identity_id=%s AND organization_id=%s",
            (identity_id, DEMO_ORG_ID),
        )
        existing = cur.fetchone()

        if existing:
            cur.execute("""
                UPDATE identities SET
                    display_name=%s, identity_category=%s, identity_type=%s,
                    risk_level=%s, risk_score=%s,
                    mfa_status=%s, upn=%s, department=%s, job_title=%s,
                    credential_status=%s, credential_risk=%s,
                    credential_count=%s, credential_age_days=%s,
                    credential_expiration=%s,
                    has_federated_credentials=%s, federated_trust=%s, is_federated=%s,
                    federated_issuer_types=%s, federated_cred_count=%s,
                    owner_display_name=%s, owner_count=%s, owner_status=%s,
                    blast_radius_score=%s, can_escalate=%s,
                    last_seen_auth=%s, activity_status=%s,
                    discovery_run_id=%s,
                    enabled=true
                WHERE id=%s
            """, (
                display_name, identity_category, identity_type,
                risk_level, risk_score,
                mfa, upn, department, job_title,
                cred_status, cred_risk, cred_count, cred_age, cred_exp,
                has_fed, has_fed, has_fed,
                Json(federated or []), len(federated) if federated else 0,
                owner_name, owner_count, owner_status,
                blast_radius, can_escalate,
                last_seen, activity,
                run_id, existing["id"],
            ))
            planted.append((display_name, "updated", hero["feature"]))
        else:
            cur.execute("""
                INSERT INTO identities (
                    discovery_run_id, identity_id, display_name, source,
                    identity_type, identity_category, organization_id,
                    risk_level, risk_score, enabled,
                    mfa_status, upn, department, job_title,
                    credential_status, credential_risk, credential_count,
                    credential_age_days, credential_expiration,
                    has_federated_credentials, federated_trust, is_federated,
                    federated_issuer_types, federated_cred_count,
                    owner_display_name, owner_count, owner_status,
                    blast_radius_score, can_escalate,
                    last_seen_auth, activity_status, status
                ) VALUES (
                    %s, %s, %s, 'azure',
                    %s, %s, %s,
                    %s, %s, true,
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s, 'active'
                )
            """, (
                run_id, identity_id, display_name,
                identity_type, identity_category, DEMO_ORG_ID,
                risk_level, risk_score,
                mfa, upn, department, job_title,
                cred_status, cred_risk, cred_count, cred_age, cred_exp,
                has_fed, has_fed, has_fed,
                Json(federated or []), len(federated) if federated else 0,
                owner_name, owner_count, owner_status,
                blast_radius, can_escalate,
                last_seen, activity,
            ))
            planted.append((display_name, "inserted", hero["feature"]))
    return planted


def main():
    log.info("AuditGraph feature-exerciser starting")
    log.info(f"Target: org_id={DEMO_ORG_ID}, DB={DB_HOST}:{DB_PORT}/{DB_NAME}")
    log.info(f"Time:   {NOW.isoformat()}")
    log.info("=" * 60)

    with connect() as conn:
        with conn.cursor() as cur:
            verify_safe(cur)
            run_id = latest_run_id(cur)
            log.info(f"Operating on discovery_run_id={run_id}")

            log.info("\n--- Step 1: populate field distributions on existing identities ---")
            populate_mfa_distribution(cur, run_id)
            populate_stale_humans(cur, run_id)
            populate_credential_distribution(cur, run_id)
            populate_owner_distribution(cur, run_id)
            populate_blast_radius(cur, run_id)
            populate_pim_eligibility(cur, run_id)
            populate_data_classifications(cur, run_id)

            log.info("\n--- Step 2: upsert hero demo identities ---")
            planted = upsert_hero_identities(cur, run_id)
            for name, action, feature in planted:
                log.info(f"  [{action:>8}] {name:42s} → {feature}")

        conn.commit()

    log.info("=" * 60)
    log.info(f"Done. {len(planted)} hero identities, distributions applied to run {run_id}.")
    log.info("See docs/AG_DEMO_DATA_INVENTORY.md for the complete mapping.")


if __name__ == "__main__":
    main()
