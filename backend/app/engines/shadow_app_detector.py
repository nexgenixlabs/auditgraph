"""AG-86: Shadow App detection engine.

For each org, evaluate every SPN / App Registration against the
`approved_apps` allowlist. Flag identities that:
  - Are NOT covered by an allowlist entry, AND
  - Match a shadow signature (any of):
      * publisher unverified
      * display name matches AI / unsanctioned-tool patterns
      * has a high-scope Graph grant (Mail.Read*, Files.Read*, etc.)
      * created in last 30 days
      * was already classified by AgentClassifier
Stores verdict on identities (is_shadow_app + shadow_reasons) so the
inventory list endpoint doesn't pay for the evaluation on every read.

This module is read-mostly (one UPDATE per identity that changes verdict).
Discovery calls `refresh_shadow_verdicts(db, run_id, org_id)` at the end
of the SPN pass.
"""
from __future__ import annotations

import logging
import json
from typing import Iterable, Optional

logger = logging.getLogger(__name__)

# High-risk Graph permissions whose presence on an unsanctioned app is by
# itself a shadow signal. Keep this list deliberately small — every entry
# is a "you should know this app personally" scope.
HIGH_RISK_SCOPE_TOKENS = (
    'Mail.Read', 'Mail.ReadWrite', 'Mail.Send',
    'Files.Read.All', 'Files.ReadWrite.All',
    'Sites.Read.All', 'Sites.ReadWrite.All',
    'Directory.Read.All', 'Directory.ReadWrite.All',
    'User.Read.All', 'User.ReadWrite.All',
    'Group.Read.All', 'Group.ReadWrite.All',
    'RoleManagement.ReadWrite.Directory',
    'AppRoleAssignment.ReadWrite.All',
    'offline_access',
)

# Display-name fragments that suggest "consumer AI assistant" or
# "automation tool installed without IT review". The agent_pattern_loader
# already covers the strong AI vendor matches; this is a coarser sweep.
SHADOW_NAME_FRAGMENTS = (
    'gpt', 'chatgpt', 'openai', 'anthropic', 'claude',
    'copilot', 'gemini', 'llama', 'mistral', 'perplexity',
    'context.ai', 'vercel',
    'zapier', 'make.com', 'integromat',
    'browser', 'extension',
)


def seed_default_approved_apps(cursor, organization_id: int) -> int:
    """Seed the per-org allowlist with the canonical Microsoft built-ins
    so brand-new orgs don't see hundreds of false positives on day one.

    Returns the count of rows inserted (0 if the org was already seeded).
    """
    # Microsoft well-known first-party app IDs that should never flag.
    # These are documented in Microsoft Entra and are tenant-independent.
    builtins = [
        # (app_id, display_name, publisher)
        ('00000003-0000-0000-c000-000000000000', 'Microsoft Graph', 'Microsoft'),
        ('00000002-0000-0000-c000-000000000000', 'Microsoft Graph (legacy)', 'Microsoft'),
        ('00000003-0000-0ff1-ce00-000000000000', 'Office 365 SharePoint Online', 'Microsoft'),
        ('00000007-0000-0000-c000-000000000000', 'Dynamics CRM Online', 'Microsoft'),
        ('00000008-0000-0000-c000-000000000000', 'Office 365 Management APIs', 'Microsoft'),
        ('1950a258-227b-4e31-a9cf-717495945fc2', 'Microsoft Azure PowerShell', 'Microsoft'),
        ('04b07795-8ddb-461a-bbee-02f9e1bf7b46', 'Microsoft Azure CLI', 'Microsoft'),
        ('00000002-0000-0ff1-ce00-000000000000', 'Office 365 Exchange Online', 'Microsoft'),
        ('00000006-0000-0ff1-ce00-000000000000', 'Microsoft Office 365 Portal', 'Microsoft'),
        ('29d9ed98-a469-4536-ade2-f981bc1d605e', 'Microsoft Authentication Broker', 'Microsoft'),
        ('cf36b471-5b44-428c-9ce7-313bf84528de', 'Microsoft Search in Bing', 'Microsoft'),
        ('1fec8e78-bce4-4aaf-ab1b-5451cc387264', 'Microsoft Teams', 'Microsoft'),
        ('c44b4083-3bb0-49c1-b47d-974e53cbdf3c', 'Azure Portal', 'Microsoft'),
        ('797f4846-ba00-4fd7-ba43-dac1f8f63013', 'Windows Azure Service Management API', 'Microsoft'),
    ]
    inserted = 0
    for app_id, name, pub in builtins:
        try:
            cursor.execute("""
                INSERT INTO approved_apps
                    (organization_id, app_id, display_name, publisher_name,
                     app_category, match_kind, is_seeded)
                VALUES (%s, %s, %s, %s, 'general', 'app_id', TRUE)
                ON CONFLICT (organization_id, app_id) WHERE app_id IS NOT NULL DO NOTHING
            """, (organization_id, app_id, name, pub))
            if cursor.rowcount:
                inserted += 1
        except Exception as e:
            logger.warning("seed_default_approved_apps: failed for %s: %s", app_id, e)
            try:
                cursor.connection.rollback()
            except Exception:
                pass
    return inserted


def _load_approved_set(cursor, organization_id: int) -> dict:
    """Return {app_ids: set, publishers: set, name_prefixes: list} for this org."""
    out = {'app_ids': set(), 'publishers': set(), 'name_prefixes': []}
    try:
        cursor.execute("""
            SELECT match_kind, app_id, publisher_name, display_name
            FROM approved_apps
            WHERE organization_id = %s
        """, (organization_id,))
        for row in cursor.fetchall():
            kind = row['match_kind'] if isinstance(row, dict) else row[0]
            app_id = row['app_id'] if isinstance(row, dict) else row[1]
            pub = row['publisher_name'] if isinstance(row, dict) else row[2]
            name = row['display_name'] if isinstance(row, dict) else row[3]
            if kind == 'app_id' and app_id:
                out['app_ids'].add(app_id.lower())
            elif kind == 'publisher' and pub:
                out['publishers'].add(pub.lower())
            elif kind == 'display_name_prefix' and name:
                out['name_prefixes'].append(name.lower())
    except Exception as e:
        logger.warning("_load_approved_set: %s", e)
        try:
            cursor.connection.rollback()
        except Exception:
            pass
    return out


def _matches_approved(identity: dict, approved: dict) -> bool:
    """True if identity is covered by any allowlist entry."""
    app_id = (identity.get('app_id') or identity.get('identity_id') or '').lower()
    pub = (identity.get('publisher_name') or '').lower()
    name = (identity.get('display_name') or '').lower()

    if app_id and app_id in approved['app_ids']:
        return True
    if pub and pub in approved['publishers']:
        return True
    if name:
        for prefix in approved['name_prefixes']:
            if name.startswith(prefix):
                return True
    # Microsoft-published apps are always approved (they're built-ins by
    # definition; covered above only if explicitly seeded, but treat
    # publisher == "Microsoft" as a coarse safety net).
    if pub == 'microsoft' or pub == 'microsoft corporation':
        return True
    return False


def _shadow_reasons(identity: dict, high_risk_grants: Iterable[str], ai_classified: bool) -> list:
    """Build the human-readable list of why this identity is shadow."""
    reasons = []
    name = (identity.get('display_name') or '').lower()
    pub = (identity.get('publisher_name') or '').strip()
    verified = identity.get('verified_publisher')
    created = identity.get('created_datetime')

    if pub == '' or pub.lower() == 'unknown':
        reasons.append('Publisher missing — no organizational accountability for this app.')
    elif verified is False:
        reasons.append(f'Unverified publisher ({pub}) — Microsoft has not validated the developer.')

    if ai_classified:
        reasons.append('Classified as AI agent by signature engine — not in approved tool registry.')
    else:
        for frag in SHADOW_NAME_FRAGMENTS:
            if frag in name:
                reasons.append(f'Display name contains "{frag}" — suggests AI/automation tool.')
                break

    grants_present = sorted(set(high_risk_grants))
    if grants_present:
        sample = ', '.join(grants_present[:3])
        more = f' (+{len(grants_present) - 3} more)' if len(grants_present) > 3 else ''
        reasons.append(f'High-risk Graph scopes granted: {sample}{more}')

    if created:
        try:
            from datetime import datetime, timezone, timedelta
            if hasattr(created, 'isoformat'):
                created_dt = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
            else:
                created_dt = datetime.fromisoformat(str(created).replace('Z', '+00:00'))
                if not created_dt.tzinfo:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - created_dt
            if age <= timedelta(days=30):
                reasons.append(f'Created {age.days} day(s) ago — recent intake.')
        except Exception:
            pass

    return reasons


def refresh_shadow_verdicts(db, run_id: int, organization_id: int) -> dict:
    """Evaluate every SPN in the run, set is_shadow_app + shadow_reasons.

    Returns counts: {evaluated, shadow, cleared}
    """
    counts = {'evaluated': 0, 'shadow': 0, 'cleared': 0}
    cursor = db.cursor()

    # Make sure the org has its default seed.
    try:
        cursor.execute(
            "SELECT 1 FROM approved_apps WHERE organization_id = %s AND is_seeded = TRUE LIMIT 1",
            (organization_id,),
        )
        if cursor.fetchone() is None:
            seed_default_approved_apps(cursor, organization_id)
            cursor.connection.commit()
    except Exception as e:
        logger.warning("refresh_shadow_verdicts: seed check failed: %s", e)
        try:
            cursor.connection.rollback()
        except Exception:
            pass

    approved = _load_approved_set(cursor, organization_id)

    # Pull candidate identities (SPNs + App Registrations only — humans
    # and managed identities can't be "shadow apps").
    try:
        cursor.execute("""
            SELECT i.id, i.identity_id, i.display_name,
                   i.publisher_name, i.verified_publisher,
                   i.created_datetime, i.identity_category,
                   COALESCE(ac.platform, '') AS ai_platform
            FROM identities i
            LEFT JOIN agent_classifications ac
                   ON ac.identity_db_id = i.id
                  AND ac.discovery_run_id = i.discovery_run_id
            WHERE i.discovery_run_id = %s
              AND i.organization_id = %s
              AND i.identity_category IN ('service_principal',)
        """, (run_id, organization_id))
        candidates = cursor.fetchall()
    except Exception as e:
        logger.error("refresh_shadow_verdicts: candidate query failed: %s", e)
        try:
            cursor.connection.rollback()
        except Exception:
            pass
        return counts

    # Pull high-risk grants for all candidates in one shot.
    candidate_ids = [
        (r['id'] if isinstance(r, dict) else r[0]) for r in candidates
    ]
    grants_by_id: dict = {}
    if candidate_ids:
        try:
            cursor.execute("""
                SELECT identity_db_id, permission
                FROM graph_api_permissions
                WHERE identity_db_id = ANY(%s)
            """, (candidate_ids,))
            for r in cursor.fetchall():
                iid = r['identity_db_id'] if isinstance(r, dict) else r[0]
                perm = r['permission'] if isinstance(r, dict) else r[1]
                if perm and any(t.lower() in perm.lower() for t in HIGH_RISK_SCOPE_TOKENS):
                    grants_by_id.setdefault(iid, set()).add(perm)
        except Exception as e:
            logger.warning("refresh_shadow_verdicts: grants query failed: %s", e)
            try:
                cursor.connection.rollback()
            except Exception:
                pass

    for row in candidates:
        identity = {
            'db_id': row['id'] if isinstance(row, dict) else row[0],
            'identity_id': row['identity_id'] if isinstance(row, dict) else row[1],
            'app_id': row['identity_id'] if isinstance(row, dict) else row[1],  # SPN.appId
            'display_name': row['display_name'] if isinstance(row, dict) else row[2],
            'publisher_name': row['publisher_name'] if isinstance(row, dict) else row[3],
            'verified_publisher': row['verified_publisher'] if isinstance(row, dict) else row[4],
            'created_datetime': row['created_datetime'] if isinstance(row, dict) else row[5],
        }
        ai_platform = row['ai_platform'] if isinstance(row, dict) else row[7]
        ai_classified = bool(ai_platform and ai_platform != '')

        counts['evaluated'] += 1
        is_approved = _matches_approved(identity, approved)
        high_risk = grants_by_id.get(identity['db_id'], set())

        if is_approved:
            verdict, reasons = False, []
        else:
            reasons = _shadow_reasons(identity, high_risk, ai_classified)
            # Require at least one risk signal in addition to "not approved"
            # otherwise every minor SPN flags as shadow.
            verdict = bool(reasons)

        if verdict:
            counts['shadow'] += 1
        else:
            counts['cleared'] += 1

        try:
            cursor.execute("""
                UPDATE identities
                   SET is_shadow_app = %s,
                       shadow_reasons = %s::jsonb
                 WHERE id = %s
            """, (verdict, json.dumps(reasons) if reasons else None, identity['db_id']))
        except Exception as e:
            logger.warning("refresh_shadow_verdicts: update failed for %s: %s",
                           identity['db_id'], e)
            try:
                cursor.connection.rollback()
            except Exception:
                pass

    try:
        cursor.connection.commit()
    except Exception:
        pass

    logger.info(
        "[AG-86] Shadow app verdict refreshed for org=%s run=%s evaluated=%d shadow=%d cleared=%d",
        organization_id, run_id, counts['evaluated'], counts['shadow'], counts['cleared'],
    )
    return counts
