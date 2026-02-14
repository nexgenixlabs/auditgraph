"""
Notification Service for AuditGraph.

Generates in-app notifications from discovery events. Called by the scheduler
after each discovery run alongside email and webhook notifications.
"""

import logging
from app.database import Database

logger = logging.getLogger(__name__)


class NotificationService:
    """Generates in-app notifications from discovery events."""

    def notify_discovery_completed(self, run_id: int, summary: dict, tenant_id=None):
        """Create info notification for completed discovery."""
        db = Database()
        try:
            total = summary.get('total_identities', 0)
            critical = summary.get('critical', 0)
            high = summary.get('high', 0)

            severity = 'info'
            if critical > 0:
                severity = 'high'

            db.create_notification(
                event_type='discovery_completed',
                category='discovery_completed',
                severity=severity,
                title=f'Discovery run #{run_id} completed',
                description=f'Scanned {total} identities — {critical} critical, {high} high risk',
                payload=summary,
                related_run_id=run_id,
                tenant_id=tenant_id,
            )
        except Exception as e:
            logger.warning(f"Failed to create discovery notification: {e}")
        finally:
            db.close()

    def notify_new_identities(self, run_id: int, new_identities: list, tenant_id=None):
        """Create notifications for new identities (aggregate if >5)."""
        if not new_identities:
            return
        db = Database()
        try:
            count = len(new_identities)
            if count <= 5:
                for identity in new_identities:
                    name = identity.get('display_name', 'Unknown')
                    category = identity.get('identity_category', 'unknown')
                    db.create_notification(
                        event_type='new_identities',
                        category='new_identity',
                        severity='medium',
                        title=f'New identity discovered: {name}',
                        description=f'{category.replace("_", " ").title()} added to environment',
                        payload={'identity': identity},
                        related_identity_id=identity.get('identity_id'),
                        related_identity_name=name,
                        related_run_id=run_id,
                        tenant_id=tenant_id,
                    )
            else:
                names = [i.get('display_name', '?') for i in new_identities[:5]]
                db.create_notification(
                    event_type='new_identities',
                    category='new_identity',
                    severity='medium',
                    title=f'{count} new identities discovered',
                    description=f'Including {", ".join(names)}' + (f' and {count - 5} more' if count > 5 else ''),
                    payload={'count': count, 'identities': new_identities[:20]},
                    related_run_id=run_id,
                    tenant_id=tenant_id,
                )
        except Exception as e:
            logger.warning(f"Failed to create new identity notifications: {e}")
        finally:
            db.close()

    def notify_removed_identities(self, run_id: int, removed: list, tenant_id=None):
        """Aggregate notification for removed identities."""
        if not removed:
            return
        db = Database()
        try:
            count = len(removed)
            names = [r.get('display_name', '?') for r in removed[:5]]
            db.create_notification(
                event_type='removed_identities',
                category='removal',
                severity='low',
                title=f'{count} {"identity" if count == 1 else "identities"} removed',
                description=f'Removed: {", ".join(names)}' + (f' and {count - 5} more' if count > 5 else ''),
                payload={'count': count, 'identities': removed[:20]},
                related_run_id=run_id,
                tenant_id=tenant_id,
            )
        except Exception as e:
            logger.warning(f"Failed to create removal notifications: {e}")
        finally:
            db.close()

    def notify_risk_escalations(self, run_id: int, escalations: list, tenant_id=None):
        """Create individual notification per risk escalation."""
        if not escalations:
            return
        db = Database()
        try:
            for esc in escalations:
                name = esc.get('display_name', 'Unknown')
                old_risk = esc.get('old_risk', 'unknown')
                new_risk = esc.get('new_risk', 'unknown')

                severity = 'critical' if new_risk == 'critical' else 'high'

                db.create_notification(
                    event_type='risk_escalation',
                    category='risk_escalation',
                    severity=severity,
                    title=f'Risk escalation: {name}',
                    description=f'Risk level changed from {old_risk} to {new_risk}',
                    payload={'escalation': esc},
                    related_identity_id=esc.get('identity_id'),
                    related_identity_name=name,
                    related_run_id=run_id,
                    tenant_id=tenant_id,
                )
        except Exception as e:
            logger.warning(f"Failed to create risk escalation notifications: {e}")
        finally:
            db.close()

    def notify_permission_changes(self, run_id: int, changes: list, tenant_id=None):
        """Aggregate notification for permission/role changes."""
        if not changes:
            return
        db = Database()
        try:
            count = len(changes)
            names = [c.get('display_name', '?') for c in changes[:5]]
            db.create_notification(
                event_type='permission_changes',
                category='permission_change',
                severity='medium',
                title=f'{count} permission {"change" if count == 1 else "changes"} detected',
                description=f'Affected: {", ".join(names)}' + (f' and {count - 5} more' if count > 5 else ''),
                payload={'count': count, 'changes': changes[:20]},
                related_run_id=run_id,
                tenant_id=tenant_id,
            )
        except Exception as e:
            logger.warning(f"Failed to create permission change notifications: {e}")
        finally:
            db.close()

    def notify_credential_changes(self, run_id: int, changes: list, tenant_id=None):
        """Create notifications for credential changes (individual if <=5, aggregate otherwise)."""
        if not changes:
            return
        db = Database()
        try:
            count = len(changes)
            if count <= 5:
                for change in changes:
                    name = change.get('display_name', 'Unknown')
                    db.create_notification(
                        event_type='credential_changes',
                        category='credential_expiring',
                        severity='high',
                        title=f'Credential alert: {name}',
                        description=f'Credential status changed for {name}',
                        payload={'change': change},
                        related_identity_id=change.get('identity_id'),
                        related_identity_name=name,
                        related_run_id=run_id,
                        tenant_id=tenant_id,
                    )
            else:
                names = [c.get('display_name', '?') for c in changes[:5]]
                db.create_notification(
                    event_type='credential_changes',
                    category='credential_expiring',
                    severity='high',
                    title=f'{count} credential changes detected',
                    description=f'Affected: {", ".join(names)}' + (f' and {count - 5} more' if count > 5 else ''),
                    payload={'count': count, 'changes': changes[:20]},
                    related_run_id=run_id,
                    tenant_id=tenant_id,
                )
        except Exception as e:
            logger.warning(f"Failed to create credential change notifications: {e}")
        finally:
            db.close()
