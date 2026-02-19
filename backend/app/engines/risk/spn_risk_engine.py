"""
Workload Identity Exposure Intelligence Engine

Attack-based risk scoring (0-100) with 5 weighted components,
P2-independent activity inference, 7 derived flags, and
detailed findings generation for workload identity exposure assessment.

Supports SPNs, Managed Identities, and App Registrations.
"""

from datetime import datetime, timedelta


# ── High-Risk Permission GUIDs (MS Graph) ──────────────────────────
HIGH_RISK_PERMISSION_GUIDS = {
    '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8',  # RoleManagement.ReadWrite.Directory
    '06b708a9-e830-4db3-a914-8e69da51d44f',  # AppRoleAssignment.ReadWrite.All
    '19dbc75e-c2e2-444c-a770-ec69d8559fc7',  # Directory.ReadWrite.All
    '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9',  # Application.ReadWrite.All
    '62a82d76-70ea-41e2-9197-370581804d09',  # Group.ReadWrite.All
    '741f803b-c850-494e-b5df-cde7c675a1ca',  # User.ReadWrite.All
    'df021288-bdef-4463-88db-98f22de89214',  # User.ManageIdentities.All
    '5b567255-7703-4780-807c-7be8301ae99b',  # Group.Create
    'e1fe6dd8-ba31-4d61-89e7-88639da4683d',  # User.Read.All (Application)
    '7ab1d382-f21e-4acd-a863-ba3e13f7da61',  # Directory.Read.All (Application)
}

# ── Tenant-Admin Entra Roles ────────────────────────────────────────
TENANT_ADMIN_ROLES = {
    'global administrator', 'privileged role administrator',
    'privileged authentication administrator',
}

# ── Dangerous RBAC Roles ────────────────────────────────────────────
SUBSCRIPTION_OWNER_ROLES = {'owner', 'user access administrator'}
CONTRIBUTOR_ROLES = {'contributor'}
ELEVATED_RBAC_ROLES = SUBSCRIPTION_OWNER_ROLES | CONTRIBUTOR_ROLES | {
    'security administrator', 'key vault administrator',
    'storage blob data owner',
}


class WorkloadExposureEngine:
    """Compute exposure scores and findings for all workload identity types."""

    def compute_exposure(self, identity_data, roles, entra_roles, credentials,
                         permissions, owners, pim_data, identity_type='spn'):
        """
        Main entry point for SPNs and Managed Identities. Returns:
        {
            scores: {total, privilege, credential_risk, exposure, lifecycle, visibility},
            flags: {can_escalate, effective_scope_flag, lifecycle_state, credential_age_days,
                    owner_status, federated_trust, cross_subscription},
            findings: [{finding_type, severity, title, description, evidence, remediation,
                       component, score_impact}],
            activity_inference: {confidence, classification, evidence_sources}
        }
        """
        scores = {
            'privilege': 0,
            'credential_risk': 0,
            'exposure': 0,
            'lifecycle': 0,
            'visibility': 0,
            'total': 0,
        }
        findings = []
        flags = {
            'can_escalate': False,
            'effective_scope_flag': 'resource',
            'lifecycle_state': 'blind',
            'credential_age_days': 0,
            'owner_status': 'unknown',
            'federated_trust': False,
            'cross_subscription': False,
        }

        is_managed_identity = identity_type in ('managed_identity', 'managed_identity_system', 'managed_identity_user')

        # Normalize roles
        rbac_roles = roles or []
        entra = entra_roles or []
        creds = credentials or []
        perms = permissions or []
        owns = owners or []
        pim = pim_data or {}

        # ── Component 1: Privilege (max 40) ─────────────────────────
        priv_score, priv_findings, can_escalate, scope_flag = self._score_privilege(
            rbac_roles, entra, perms, pim)
        scores['privilege'] = min(priv_score, 40)
        findings.extend(priv_findings)
        flags['can_escalate'] = can_escalate
        flags['effective_scope_flag'] = scope_flag

        # ── Component 2: Credential Risk (max 25) ───────────────────
        if is_managed_identity:
            # Azure manages credentials for managed identities — no credential risk
            scores['credential_risk'] = 0
            flags['credential_age_days'] = 0
            flags['federated_trust'] = False
        else:
            cred_score, cred_findings, cred_age, has_federated = self._score_credential_risk(creds)
            scores['credential_risk'] = min(cred_score, 25)
            findings.extend(cred_findings)
            flags['credential_age_days'] = cred_age
            flags['federated_trust'] = has_federated

        # ── Component 3: Exposure (max 20) ──────────────────────────
        exp_score, exp_findings, cross_sub = self._score_exposure(rbac_roles, identity_data)
        scores['exposure'] = min(exp_score, 20)
        findings.extend(exp_findings)
        flags['cross_subscription'] = cross_sub

        # ── Component 4: Lifecycle (max 10) ─────────────────────────
        if is_managed_identity:
            lc_score, lc_findings, owner_status = self._score_lifecycle(
                identity_data, creds, owns)
            # System-assigned MIs are bound to their parent resource
            cat = (identity_data.get('identity_category') or '').lower()
            if cat == 'managed_identity_system' and owner_status == 'orphaned':
                owner_status = 'resource_bound'
                # Remove the orphaned finding we just generated
                lc_findings = [f for f in lc_findings if f['finding_type'] != 'orphaned']
                lc_score = max(lc_score - 10, 0)
        else:
            lc_score, lc_findings, owner_status = self._score_lifecycle(
                identity_data, creds, owns)
        scores['lifecycle'] = min(lc_score, 10)
        findings.extend(lc_findings)
        flags['owner_status'] = owner_status

        # ── Component 5: Visibility (max 5) ─────────────────────────
        vis_score, vis_findings = self._score_visibility(identity_data)
        scores['visibility'] = min(vis_score, 5)
        findings.extend(vis_findings)

        # ── Activity Inference ──────────────────────────────────────
        activity = self._infer_activity(identity_data, creds, rbac_roles, pim)
        flags['lifecycle_state'] = activity['classification']

        # ── Total Score ─────────────────────────────────────────────
        scores['total'] = (
            scores['privilege'] + scores['credential_risk'] +
            scores['exposure'] + scores['lifecycle'] + scores['visibility']
        )

        # ── Critical Overrides (force to 100) ──────────────────────
        overrides = self._check_critical_overrides(
            flags, entra, rbac_roles, identity_data, creds)
        if overrides:
            scores['total'] = 100

        return {
            'scores': scores,
            'flags': flags,
            'findings': findings,
            'activity_inference': activity,
            'critical_overrides': overrides,
        }

    def compute_app_reg_exposure(self, app_reg_data, linked_spn_roles=None,
                                  linked_spn_entra_roles=None):
        """
        Compute exposure for an App Registration.

        Args:
            app_reg_data: dict with app registration columns
            linked_spn_roles: RBAC roles from linked SPN (if any)
            linked_spn_entra_roles: Entra roles from linked SPN (if any)
        """
        scores = {
            'privilege': 0,
            'credential_risk': 0,
            'exposure': 0,
            'lifecycle': 0,
            'visibility': 0,
            'total': 0,
        }
        findings = []
        flags = {
            'can_escalate': False,
            'effective_scope_flag': 'resource',
            'lifecycle_state': 'blind',
            'credential_age_days': 0,
            'owner_status': 'unknown',
            'federated_trust': False,
            'cross_subscription': False,
        }

        spn_roles = linked_spn_roles or []
        spn_entra = linked_spn_entra_roles or []

        # ── Component 1: Privilege (max 40) ─────────────────────────
        # Convert high_risk_permissions to permissions format for scoring
        perms = []
        high_risk_perms_list = app_reg_data.get('high_risk_permissions') or []
        if isinstance(high_risk_perms_list, list):
            for pname in high_risk_perms_list:
                perms.append({
                    'permission_id': pname.lower() if isinstance(pname, str) else '',
                    'permission_name': pname,
                    'permission_type': 'application',
                })

        # Also parse required_permissions JSONB for high-risk GUIDs
        required_perms = app_reg_data.get('required_permissions') or []
        if isinstance(required_perms, str):
            import json
            try:
                required_perms = json.loads(required_perms)
            except Exception:
                required_perms = []
        for rp in required_perms:
            resource_perms = rp.get('resourceAccess') or []
            for ra in resource_perms:
                pid = (ra.get('id') or '').lower()
                if pid in HIGH_RISK_PERMISSION_GUIDS:
                    perms.append({
                        'permission_id': pid,
                        'permission_name': ra.get('id', pid),
                        'permission_type': ra.get('type', 'Role').lower().replace('role', 'application'),
                    })

        priv_score, priv_findings, can_escalate, scope_flag = self._score_privilege(
            spn_roles, spn_entra, perms, {})
        scores['privilege'] = min(priv_score, 40)
        findings.extend(priv_findings)
        flags['can_escalate'] = can_escalate
        flags['effective_scope_flag'] = scope_flag

        # App-reg-specific: excessive application permissions
        app_perm_count = app_reg_data.get('application_permission_count') or 0
        if app_perm_count > 5:
            scores['privilege'] = min(scores['privilege'] + 10, 40)
            findings.append({
                'finding_type': 'excessive_application_permissions',
                'severity': 'high',
                'title': f'{app_perm_count} application-level permissions',
                'description': 'Excessive application permissions increase blast radius if app is compromised.',
                'evidence': {'application_permission_count': app_perm_count},
                'remediation': 'Review and reduce to minimum required permissions. Prefer delegated permissions.',
                'component': 'privilege',
                'score_impact': 10,
            })

        # ── Component 2: Credential Risk (max 25) ───────────────────
        creds = []
        cred_details = app_reg_data.get('credential_details') or []
        if isinstance(cred_details, str):
            import json
            try:
                cred_details = json.loads(cred_details)
            except Exception:
                cred_details = []
        for cd in cred_details:
            creds.append({
                'credential_type': cd.get('type', 'secret'),
                'start_datetime': cd.get('startDateTime') or cd.get('start_datetime'),
                'end_datetime': cd.get('endDateTime') or cd.get('end_datetime'),
                'display_name': cd.get('displayName') or cd.get('display_name', ''),
                'key_id': cd.get('keyId') or cd.get('key_id', ''),
            })

        cred_score, cred_findings, cred_age, has_federated = self._score_credential_risk(creds)
        scores['credential_risk'] = min(cred_score, 25)
        findings.extend(cred_findings)
        flags['credential_age_days'] = cred_age
        flags['federated_trust'] = has_federated

        # ── Component 3: Exposure (max 20) ──────────────────────────
        # Use linked SPN roles for cross-subscription analysis
        exp_score, exp_findings, cross_sub = self._score_exposure(spn_roles, {
            'sign_in_audience': app_reg_data.get('sign_in_audience', ''),
            'service_principal_type': '',
        })
        scores['exposure'] = min(exp_score, 20)
        findings.extend(exp_findings)
        flags['cross_subscription'] = cross_sub

        # App-reg-specific exposure: redirect URI issues
        if app_reg_data.get('has_localhost_redirect'):
            findings.append({
                'finding_type': 'localhost_redirect',
                'severity': 'medium',
                'title': 'Localhost redirect URI configured',
                'description': 'Localhost redirect URIs should be removed from production registrations.',
                'evidence': {},
                'remediation': 'Remove localhost redirect URIs. Use proper deployment URLs.',
                'component': 'exposure',
                'score_impact': 3,
            })
            scores['exposure'] = min(scores['exposure'] + 3, 20)

        if app_reg_data.get('has_http_redirect'):
            findings.append({
                'finding_type': 'http_redirect',
                'severity': 'medium',
                'title': 'HTTP (non-HTTPS) redirect URI configured',
                'description': 'HTTP redirect URIs are vulnerable to token interception.',
                'evidence': {},
                'remediation': 'Upgrade all redirect URIs to HTTPS.',
                'component': 'exposure',
                'score_impact': 3,
            })
            scores['exposure'] = min(scores['exposure'] + 3, 20)

        # ── Component 4: Lifecycle (max 10) ─────────────────────────
        owner_count = app_reg_data.get('owner_count') or 0
        owners_list = []
        if owner_count > 0:
            owners_list = [{'owner_display_name': 'owner'}] * owner_count

        # Build identity_data for lifecycle scoring
        lifecycle_identity = {
            'activity_status': app_reg_data.get('spn_activity_status') or 'unknown',
            'last_sign_in': app_reg_data.get('spn_last_sign_in'),
            'created_datetime': app_reg_data.get('created_datetime'),
        }

        lc_score, lc_findings, owner_status = self._score_lifecycle(
            lifecycle_identity, creds, owners_list)

        # App-reg-specific: no service principal
        if not app_reg_data.get('has_service_principal'):
            lc_score += 5
            findings.append({
                'finding_type': 'no_service_principal',
                'severity': 'medium',
                'title': 'No service principal — app registration without usage path',
                'description': 'This app registration has no corresponding service principal, suggesting it may be abandoned.',
                'evidence': {},
                'remediation': 'Verify if this registration is still needed. Delete if unused.',
                'component': 'lifecycle',
                'score_impact': 5,
            })

        scores['lifecycle'] = min(lc_score, 10)
        findings.extend(lc_findings)
        flags['owner_status'] = owner_status

        # ── Component 5: Visibility (max 5) ─────────────────────────
        # App regs have no direct sign-in telemetry
        vis_score = 3
        vis_findings = [{
            'finding_type': 'no_direct_telemetry',
            'severity': 'medium',
            'title': 'No direct sign-in telemetry for app registration',
            'description': 'App registrations rely on linked SPN for activity data.',
            'evidence': {'has_spn': app_reg_data.get('has_service_principal', False)},
            'remediation': 'Monitor via linked service principal sign-in logs.',
            'component': 'visibility',
            'score_impact': 3,
        }]

        # If linked SPN has CA coverage, reduce
        if app_reg_data.get('has_service_principal'):
            vis_score = max(vis_score - 1, 0)

        scores['visibility'] = min(vis_score, 5)
        findings.extend(vis_findings)

        # ── Activity Inference ──────────────────────────────────────
        activity = self._infer_activity(lifecycle_identity, creds, spn_roles, {})
        flags['lifecycle_state'] = activity['classification']

        # ── Total Score ─────────────────────────────────────────────
        scores['total'] = (
            scores['privilege'] + scores['credential_risk'] +
            scores['exposure'] + scores['lifecycle'] + scores['visibility']
        )

        # ── Critical Overrides ──────────────────────────────────────
        overrides = self._check_app_reg_critical_overrides(app_reg_data, flags)
        if overrides:
            scores['total'] = 100

        return {
            'scores': scores,
            'flags': flags,
            'findings': findings,
            'activity_inference': activity,
            'critical_overrides': overrides,
        }

    def _check_app_reg_critical_overrides(self, app_reg_data, flags):
        """App-registration-specific critical overrides."""
        overrides = []

        owner_count = app_reg_data.get('owner_count') or 0
        sign_in_audience = (app_reg_data.get('sign_in_audience') or '').lower()
        high_risk = app_reg_data.get('high_risk_permissions') or []
        is_multi_tenant = 'multiple' in sign_in_audience or 'personal' in sign_in_audience

        # Override: Ownerless + multi-tenant + high-risk API permissions
        if owner_count == 0 and is_multi_tenant and len(high_risk) > 0:
            overrides.append({
                'type': 'ownerless_multitenant_highrisk',
                'description': 'Ownerless app registration with multi-tenant audience and high-risk API permissions — maximum exposure',
            })

        # Override: Ownerless + has SPN + expired credentials
        has_expired = app_reg_data.get('has_expired_credential', False)
        if owner_count == 0 and has_expired and flags.get('can_escalate'):
            overrides.append({
                'type': 'ownerless_escalation_expired',
                'description': 'Ownerless app with escalation capability and expired credentials — abandoned privileged identity',
            })

        return overrides

    # ── Privilege Scoring ───────────────────────────────────────────

    def _score_privilege(self, rbac_roles, entra_roles, permissions, pim):
        score = 0
        findings = []
        can_escalate = False
        scope_flag = 'resource'

        # Entra directory roles
        entra_role_names = set()
        for r in entra_roles:
            rn = (r.get('role_name') or '').lower()
            entra_role_names.add(rn)

        if entra_role_names & TENANT_ADMIN_ROLES:
            score += 40
            can_escalate = True
            scope_flag = 'tenant'
            matched = entra_role_names & TENANT_ADMIN_ROLES
            findings.append({
                'finding_type': 'tenant_admin_role',
                'severity': 'critical',
                'title': 'Tenant-level administrative role assigned',
                'description': f'This workload identity has {", ".join(matched)} — full tenant administrative control.',
                'evidence': {'roles': list(matched)},
                'remediation': 'Remove tenant-admin roles from workload identities. Use PIM for just-in-time elevation.',
                'component': 'privilege',
                'score_impact': 40,
            })

        # RBAC roles
        for r in rbac_roles:
            rn = (r.get('role_name') or '').lower()
            st = (r.get('scope_type') or '').lower()
            scope = (r.get('scope') or '')

            is_sub_scope = st == 'subscription' or (
                scope.startswith('/subscriptions/') and '/resourceGroups/' not in scope)
            is_mg_scope = st == 'management_group' or scope.startswith('/providers/Microsoft.Management/managementGroups/')

            if is_mg_scope:
                scope_flag = self._higher_scope(scope_flag, 'management_group')
            elif is_sub_scope:
                scope_flag = self._higher_scope(scope_flag, 'subscription')
            elif st == 'resource_group' or '/resourceGroups/' in scope:
                scope_flag = self._higher_scope(scope_flag, 'resource_group')

            if rn in SUBSCRIPTION_OWNER_ROLES and (is_sub_scope or is_mg_scope):
                add = 30
                score += add
                can_escalate = True
                findings.append({
                    'finding_type': 'subscription_owner',
                    'severity': 'critical',
                    'title': f'{r.get("role_name", "")} at subscription scope',
                    'description': f'Has {r.get("role_name", "")} role at {scope or "subscription"} — can control all resources.',
                    'evidence': {'role': r.get('role_name'), 'scope': scope},
                    'remediation': 'Scope down to specific resource groups. Use PIM for time-limited access.',
                    'component': 'privilege',
                    'score_impact': add,
                })
            elif rn in CONTRIBUTOR_ROLES and (is_sub_scope or is_mg_scope):
                add = 20
                score += add
                findings.append({
                    'finding_type': 'subscription_contributor',
                    'severity': 'high',
                    'title': 'Contributor at subscription scope',
                    'description': f'Has Contributor role at {scope or "subscription"} — can modify all resources.',
                    'evidence': {'role': r.get('role_name'), 'scope': scope},
                    'remediation': 'Replace with least-privilege custom role scoped to specific resource groups.',
                    'component': 'privilege',
                    'score_impact': add,
                })

        # High-risk Graph API permissions
        high_risk_perms = []
        for p in permissions:
            pid = (p.get('permission_id') or '').lower()
            ptype = (p.get('permission_type') or '').lower()
            if pid in HIGH_RISK_PERMISSION_GUIDS and ptype == 'application':
                high_risk_perms.append(p.get('permission_name', pid))
        if high_risk_perms:
            score += 15
            can_escalate = True
            findings.append({
                'finding_type': 'high_risk_api_permissions',
                'severity': 'high',
                'title': f'{len(high_risk_perms)} high-risk Graph API permissions',
                'description': f'Application-level permissions: {", ".join(high_risk_perms[:5])}',
                'evidence': {'permissions': high_risk_perms},
                'remediation': 'Review necessity. Prefer delegated permissions or more granular scopes.',
                'component': 'privilege',
                'score_impact': 15,
            })

        # PIM eligible
        eligible_count = len(pim.get('eligible', []))
        if eligible_count > 0:
            score += 10
            findings.append({
                'finding_type': 'pim_eligible',
                'severity': 'medium',
                'title': f'{eligible_count} PIM-eligible role assignments',
                'description': 'Workload identity can activate privileged roles via PIM.',
                'evidence': {'eligible_count': eligible_count},
                'remediation': 'Review if workload identities should have PIM eligibility.',
                'component': 'privilege',
                'score_impact': 10,
            })

        return score, findings, can_escalate, scope_flag

    # ── Credential Risk Scoring ─────────────────────────────────────

    def _score_credential_risk(self, credentials):
        score = 0
        findings = []
        max_age = 0
        has_federated = False
        now = datetime.utcnow()

        expired_creds = []
        old_creds = []
        active_secrets = 0

        for c in credentials:
            ctype = (c.get('credential_type') or '').lower()
            if ctype == 'federated':
                has_federated = True

            # Check expiry
            end = c.get('end_datetime')
            if end:
                if isinstance(end, str):
                    try:
                        end_dt = datetime.fromisoformat(end.replace('Z', '+00:00')).replace(tzinfo=None)
                    except Exception:
                        end_dt = None
                else:
                    end_dt = end.replace(tzinfo=None) if hasattr(end, 'replace') else end
                if end_dt and end_dt < now:
                    expired_creds.append(c)

            # Check age
            start = c.get('start_datetime')
            if start:
                if isinstance(start, str):
                    try:
                        start_dt = datetime.fromisoformat(start.replace('Z', '+00:00')).replace(tzinfo=None)
                    except Exception:
                        start_dt = None
                else:
                    start_dt = start.replace(tzinfo=None) if hasattr(start, 'replace') else start
                if start_dt:
                    age = (now - start_dt).days
                    max_age = max(max_age, age)
                    if age > 365:
                        old_creds.append(c)

            if ctype == 'secret':
                # Check if not expired
                if end:
                    if isinstance(end, str):
                        try:
                            end_dt2 = datetime.fromisoformat(end.replace('Z', '+00:00')).replace(tzinfo=None)
                        except Exception:
                            end_dt2 = None
                    else:
                        end_dt2 = end.replace(tzinfo=None) if hasattr(end, 'replace') else end
                    if end_dt2 and end_dt2 >= now:
                        active_secrets += 1
                else:
                    active_secrets += 1

        if expired_creds:
            score += 15
            findings.append({
                'finding_type': 'expired_credentials',
                'severity': 'critical',
                'title': f'{len(expired_creds)} expired credential(s) still attached',
                'description': 'Expired credentials indicate abandoned or poorly maintained workload identity.',
                'evidence': {'count': len(expired_creds)},
                'remediation': 'Remove expired credentials immediately. Investigate if SPN is still needed.',
                'component': 'credential_risk',
                'score_impact': 15,
            })

        if old_creds:
            score += 10
            findings.append({
                'finding_type': 'old_credentials',
                'severity': 'high',
                'title': f'Credential(s) older than 365 days ({max_age}d oldest)',
                'description': 'Long-lived secrets increase exposure window if compromised.',
                'evidence': {'oldest_days': max_age, 'count': len(old_creds)},
                'remediation': 'Rotate credentials. Adopt certificate-based or federated authentication.',
                'component': 'credential_risk',
                'score_impact': 10,
            })

        if active_secrets > 1:
            score += 8
            findings.append({
                'finding_type': 'multiple_active_secrets',
                'severity': 'medium',
                'title': f'{active_secrets} active client secrets',
                'description': 'Multiple active secrets increase attack surface.',
                'evidence': {'count': active_secrets},
                'remediation': 'Consolidate to single credential. Remove unused secrets.',
                'component': 'credential_risk',
                'score_impact': 8,
            })

        has_cert = any((c.get('credential_type') or '').lower() == 'certificate' for c in credentials)
        if credentials and not has_cert and not has_federated:
            score += 5
            findings.append({
                'finding_type': 'no_certificate_auth',
                'severity': 'low',
                'title': 'No certificate or federated credential',
                'description': 'Relies solely on client secrets — less secure than certificate-based auth.',
                'evidence': {},
                'remediation': 'Migrate to certificate-based or workload identity federation.',
                'component': 'credential_risk',
                'score_impact': 5,
            })

        return score, findings, max_age, has_federated

    # ── Exposure Scoring ────────────────────────────────────────────

    def _score_exposure(self, rbac_roles, identity_data):
        score = 0
        findings = []
        cross_sub = False

        # Cross-subscription access
        subs = set()
        for r in rbac_roles:
            scope = r.get('scope') or ''
            if scope.startswith('/subscriptions/'):
                parts = scope.split('/')
                if len(parts) >= 3:
                    subs.add(parts[2])
        if len(subs) > 1:
            cross_sub = True
            score += 10
            findings.append({
                'finding_type': 'cross_subscription',
                'severity': 'high',
                'title': f'Access across {len(subs)} subscriptions',
                'description': 'Workload identity has roles in multiple subscriptions — blast radius extends across boundaries.',
                'evidence': {'subscription_count': len(subs)},
                'remediation': 'Create separate SPNs per subscription. Follow blast-radius isolation.',
                'component': 'exposure',
                'score_impact': 10,
            })

        # Management group scope
        for r in rbac_roles:
            scope = r.get('scope') or ''
            st = (r.get('scope_type') or '').lower()
            if st == 'management_group' or scope.startswith('/providers/Microsoft.Management/managementGroups/'):
                score += 8
                findings.append({
                    'finding_type': 'management_group_scope',
                    'severity': 'critical',
                    'title': 'Management group-scoped role assignment',
                    'description': 'Roles at management group scope affect all child subscriptions.',
                    'evidence': {'scope': scope},
                    'remediation': 'Scope roles to individual subscriptions or resource groups.',
                    'component': 'exposure',
                    'score_impact': 8,
                })
                break

        # Broad resource group scope (many RGs)
        rgs = set()
        for r in rbac_roles:
            scope = r.get('scope') or ''
            if '/resourceGroups/' in scope:
                parts = scope.split('/resourceGroups/')
                if len(parts) >= 2:
                    rg_name = parts[1].split('/')[0]
                    rgs.add(rg_name)
        if len(rgs) >= 5:
            score += 5
            findings.append({
                'finding_type': 'broad_rg_scope',
                'severity': 'medium',
                'title': f'Access to {len(rgs)} resource groups',
                'description': 'Broad resource group access suggests overly permissive scoping.',
                'evidence': {'rg_count': len(rgs)},
                'remediation': 'Reduce to minimum required resource groups.',
                'component': 'exposure',
                'score_impact': 5,
            })

        # Multi-tenant / public app
        spn_type = (identity_data.get('service_principal_type') or '').lower()
        sign_in_audience = (identity_data.get('sign_in_audience') or '').lower()
        if 'multitenant' in sign_in_audience or spn_type == 'legacy':
            score += 7
            findings.append({
                'finding_type': 'public_facing_app',
                'severity': 'high',
                'title': 'Multi-tenant or public-facing application',
                'description': 'Application accepts sign-ins from external tenants.',
                'evidence': {'sign_in_audience': sign_in_audience, 'spn_type': spn_type},
                'remediation': 'Restrict to single-tenant unless external access is required.',
                'component': 'exposure',
                'score_impact': 7,
            })

        return score, findings, cross_sub

    # ── Lifecycle Scoring ───────────────────────────────────────────

    def _score_lifecycle(self, identity_data, credentials, owners):
        score = 0
        findings = []

        # Owner status
        if not owners or len(owners) == 0:
            owner_status = 'orphaned'
            score += 10
            findings.append({
                'finding_type': 'orphaned',
                'severity': 'critical',
                'title': 'No registered owner — orphaned workload identity',
                'description': 'No accountability for this identity. Orphaned SPNs are prime attack targets.',
                'evidence': {},
                'remediation': 'Assign at least one owner. Establish attestation schedule.',
                'component': 'lifecycle',
                'score_impact': 10,
            })
        elif len(owners) == 1:
            owner_status = 'single_owner'
        else:
            owner_status = 'owned'

        # Dormant check
        activity = (identity_data.get('activity_status') or '').lower()
        last_sign_in = identity_data.get('last_sign_in')

        days_since_sign_in = None
        if last_sign_in:
            if isinstance(last_sign_in, str):
                try:
                    ls_dt = datetime.fromisoformat(last_sign_in.replace('Z', '+00:00')).replace(tzinfo=None)
                    days_since_sign_in = (datetime.utcnow() - ls_dt).days
                except Exception:
                    pass
            elif hasattr(last_sign_in, 'replace'):
                days_since_sign_in = (datetime.utcnow() - last_sign_in.replace(tzinfo=None)).days

        if days_since_sign_in is not None and days_since_sign_in > 180:
            score += 8
            findings.append({
                'finding_type': 'dormant_identity',
                'severity': 'high',
                'title': f'No sign-in for {days_since_sign_in} days',
                'description': 'Dormant workload identity with active credentials is a security risk.',
                'evidence': {'days_since_sign_in': days_since_sign_in},
                'remediation': 'Verify if still needed. Disable or remove if unused.',
                'component': 'lifecycle',
                'score_impact': 8,
            })
        elif activity in ('stale', 'never_used'):
            score += 8
            findings.append({
                'finding_type': 'stale_identity',
                'severity': 'high',
                'title': f'Activity status: {activity}',
                'description': 'Identity is stale or never used — credentials may be abandoned.',
                'evidence': {'activity_status': activity},
                'remediation': 'Investigate usage. Remove if confirmed unused.',
                'component': 'lifecycle',
                'score_impact': 8,
            })

        # Created long ago, no rotation
        created = identity_data.get('created_datetime')
        if created:
            if isinstance(created, str):
                try:
                    created_dt = datetime.fromisoformat(created.replace('Z', '+00:00')).replace(tzinfo=None)
                except Exception:
                    created_dt = None
            else:
                created_dt = created.replace(tzinfo=None) if hasattr(created, 'replace') else created
            if created_dt:
                age_days = (datetime.utcnow() - created_dt).days
                if age_days > 730:  # 2 years
                    newest_cred_start = None
                    for c in credentials:
                        s = c.get('start_datetime')
                        if s:
                            if isinstance(s, str):
                                try:
                                    s_dt = datetime.fromisoformat(s.replace('Z', '+00:00')).replace(tzinfo=None)
                                except Exception:
                                    s_dt = None
                            else:
                                s_dt = s.replace(tzinfo=None) if hasattr(s, 'replace') else s
                            if s_dt:
                                if newest_cred_start is None or s_dt > newest_cred_start:
                                    newest_cred_start = s_dt
                    if newest_cred_start is None or (datetime.utcnow() - newest_cred_start).days > 365:
                        score += 5
                        findings.append({
                            'finding_type': 'aging_no_rotation',
                            'severity': 'medium',
                            'title': f'Created {age_days} days ago, no recent rotation',
                            'description': 'Long-lived identity without credential rotation.',
                            'evidence': {'age_days': age_days},
                            'remediation': 'Implement automated credential rotation.',
                            'component': 'lifecycle',
                            'score_impact': 5,
                        })

        return score, findings, owner_status

    # ── Visibility Scoring ──────────────────────────────────────────

    def _score_visibility(self, identity_data):
        score = 0
        findings = []

        activity = (identity_data.get('activity_status') or '').lower()
        if activity in ('unknown', ''):
            score += 3
            findings.append({
                'finding_type': 'no_audit_logging',
                'severity': 'medium',
                'title': 'Visibility gap — no sign-in telemetry',
                'description': 'Sign-in data unavailable. Cannot determine if this identity is actively used or compromised.',
                'evidence': {'activity_status': activity or 'unknown'},
                'remediation': 'Enable sign-in logging. This is a visibility gap, not a product limitation.',
                'component': 'visibility',
                'score_impact': 3,
            })

        ca_covered = identity_data.get('ca_coverage_status')
        if not ca_covered or ca_covered == 'not_covered':
            score += 2
            findings.append({
                'finding_type': 'no_ca_coverage',
                'severity': 'low',
                'title': 'No Conditional Access coverage',
                'description': 'Not protected by any Conditional Access policy.',
                'evidence': {'ca_status': ca_covered or 'unknown'},
                'remediation': 'Include workload identities in CA policies where supported.',
                'component': 'visibility',
                'score_impact': 2,
            })

        return score, findings

    # ── Activity Inference (P2-independent) ─────────────────────────

    def _infer_activity(self, identity_data, credentials, rbac_roles, pim):
        confidence = 0
        evidence_sources = []
        now = datetime.utcnow()

        # Credential last-modified < 30d
        for c in credentials:
            start = c.get('start_datetime')
            if start:
                if isinstance(start, str):
                    try:
                        start_dt = datetime.fromisoformat(start.replace('Z', '+00:00')).replace(tzinfo=None)
                    except Exception:
                        continue
                else:
                    start_dt = start.replace(tzinfo=None) if hasattr(start, 'replace') else start
                if start_dt and (now - start_dt).days < 30:
                    confidence += 30
                    evidence_sources.append('credential_recently_modified')
                    break

        # Sign-in data from basic logs
        last_sign_in = identity_data.get('last_sign_in')
        if last_sign_in:
            if isinstance(last_sign_in, str):
                try:
                    ls_dt = datetime.fromisoformat(last_sign_in.replace('Z', '+00:00')).replace(tzinfo=None)
                except Exception:
                    ls_dt = None
            else:
                ls_dt = last_sign_in.replace(tzinfo=None) if hasattr(last_sign_in, 'replace') else last_sign_in
            if ls_dt and (now - ls_dt).days < 90:
                confidence += 30
                evidence_sources.append('recent_sign_in')

        # Role assignment changes in last 90d
        for r in rbac_roles:
            created_on = r.get('created_on')
            if created_on:
                if isinstance(created_on, str):
                    try:
                        co_dt = datetime.fromisoformat(created_on.replace('Z', '+00:00')).replace(tzinfo=None)
                    except Exception:
                        continue
                else:
                    co_dt = created_on.replace(tzinfo=None) if hasattr(created_on, 'replace') else created_on
                if co_dt and (now - co_dt).days < 90:
                    confidence += 20
                    evidence_sources.append('recent_role_change')
                    break

        # PIM activations in last 90d
        for a in pim.get('activations', []):
            activated_at = a.get('start_datetime') or a.get('activated_at')
            if activated_at:
                if isinstance(activated_at, str):
                    try:
                        a_dt = datetime.fromisoformat(activated_at.replace('Z', '+00:00')).replace(tzinfo=None)
                    except Exception:
                        continue
                else:
                    a_dt = activated_at.replace(tzinfo=None) if hasattr(activated_at, 'replace') else activated_at
                if a_dt and (now - a_dt).days < 90:
                    confidence += 20
                    evidence_sources.append('recent_pim_activation')
                    break

        confidence = min(confidence, 100)

        if confidence >= 70:
            classification = 'active'
        elif confidence >= 40:
            classification = 'possibly_active'
        elif confidence >= 15:
            classification = 'likely_dormant'
        else:
            classification = 'blind'

        return {
            'confidence': confidence,
            'classification': classification,
            'evidence_sources': evidence_sources,
        }

    # ── Critical Overrides ──────────────────────────────────────────

    def _check_critical_overrides(self, flags, entra_roles, rbac_roles, identity_data, credentials):
        """Check conditions that force exposure score to 100."""
        overrides = []

        entra_names = {(r.get('role_name') or '').lower() for r in entra_roles}
        has_tenant_admin = bool(entra_names & TENANT_ADMIN_ROLES)

        has_expired = any(
            self._is_expired(c) for c in credentials
        )

        has_sub_owner = any(
            (r.get('role_name') or '').lower() in SUBSCRIPTION_OWNER_ROLES
            and ((r.get('scope_type') or '').lower() == 'subscription'
                 or (r.get('scope') or '').startswith('/subscriptions/'))
            for r in rbac_roles
        )

        # Override 1: Tenant-admin + expired credentials
        if has_tenant_admin and has_expired:
            overrides.append({
                'type': 'tenant_admin_expired_creds',
                'description': 'Tenant-admin role with expired credentials — abandoned privileged identity',
            })

        # Override 2: Orphaned + subscription Owner
        if flags.get('owner_status') == 'orphaned' and has_sub_owner:
            overrides.append({
                'type': 'orphaned_sub_owner',
                'description': 'Orphaned identity with subscription Owner role — no accountability for high privilege',
            })

        # Override 3: Cross-subscription + no audit logging
        activity = (identity_data.get('activity_status') or '').lower()
        if flags.get('cross_subscription') and activity in ('unknown', ''):
            overrides.append({
                'type': 'cross_sub_no_audit',
                'description': 'Cross-subscription access with no sign-in telemetry — invisible blast radius',
            })

        # Override 4: Can escalate + blind lifecycle
        if flags.get('can_escalate') and flags.get('lifecycle_state') == 'blind':
            overrides.append({
                'type': 'escalation_blind',
                'description': 'Can escalate privileges but has no activity telemetry — maximum uncertainty',
            })

        return overrides

    # ── Helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _higher_scope(current, new):
        order = {'resource': 0, 'resource_group': 1, 'subscription': 2, 'management_group': 3, 'tenant': 4}
        if order.get(new, 0) > order.get(current, 0):
            return new
        return current

    @staticmethod
    def _is_expired(cred):
        end = cred.get('end_datetime')
        if not end:
            return False
        now = datetime.utcnow()
        if isinstance(end, str):
            try:
                end_dt = datetime.fromisoformat(end.replace('Z', '+00:00')).replace(tzinfo=None)
            except Exception:
                return False
        else:
            end_dt = end.replace(tzinfo=None) if hasattr(end, 'replace') else end
        return end_dt < now if end_dt else False


# Backward compatibility alias
SPNExposureEngine = WorkloadExposureEngine
