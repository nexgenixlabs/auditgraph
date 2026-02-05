"""
Activity Tracking for Azure Service Principals

This module provides the ActivityTracker class that queries Microsoft Graph API
sign-in logs to determine when a service principal was last used. This information
is critical for identifying dormant or orphaned accounts that may pose security risks.

Activity Status Levels:
    - 'active': Activity within the last 30 days (healthy)
    - 'inactive': Activity 30-90 days ago (review recommended)
    - 'stale': No activity in 90+ days (consider removal)
    - 'never_used': Created > 30 days ago but never authenticated
    - 'unknown': No sign-in data available

Security Implications:
    - Dormant accounts with high privileges are prime attack targets
    - Never-used accounts may indicate provisioning errors or orphaned apps
    - Regular activity review is required for HIPAA compliance (§164.308(a)(3))

API Requirements:
    - Microsoft Graph API access
    - AuditLog.Read.All permission (for sign-in log access)

Note: If AuditLog.Read.All permission is not granted, the API returns 403
and activity status defaults to 'unknown'.

Usage:
    tracker = ActivityTracker(azure_credential)
    last_sign_in = tracker.get_last_sign_in(app_id)
    status = tracker.get_activity_status(last_sign_in, created_date)
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

import requests


class ActivityTracker:
    """Track service principal last activity"""
    
    def __init__(self, credential):
        """
        Initialize with Azure credential
        
        Args:
            credential: Azure ClientSecretCredential object
        """
        self.credential = credential
        # Whether the current token has access to sign-in logs.
        # None = not yet determined, True/False after first call.
        self.has_auditlog_access: Optional[bool] = None

        # Reuse HTTP connections
        self._session = requests.Session()
    
    def get_last_sign_in(self, app_id: str) -> Optional[datetime]:
        """
        Get the last sign-in time for a service principal
        
        Args:
            app_id: Application ID of the service principal
            
        Returns:
            Datetime of last sign-in, or None if never signed in
        """
        try:
            # Get access token for Microsoft Graph
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }
            
            # Query sign-in logs for this service principal
            # Look back 90 days (Graph API limit)
            url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
            params = {
                '$filter': f"appId eq '{app_id}'",
                '$top': 1,
                '$orderby': 'createdDateTime desc',
                '$select': 'createdDateTime,appId,appDisplayName,servicePrincipalId'
            }
            
            response = self._session.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 200:
                self.has_auditlog_access = True
                data = response.json()
                sign_ins = data.get('value', [])
                
                if sign_ins:
                    # Get the most recent sign-in
                    last_sign_in = sign_ins[0].get('createdDateTime')
                    if last_sign_in:
                        return self._parse_datetime(last_sign_in)
                
                return None
            
            elif response.status_code == 403:
                # Permission issue - this is expected if we don't have AuditLog.Read.All
                self.has_auditlog_access = False
                return None
            
            return None
            
        except Exception as e:
            # Don't print error for each SPN - too noisy
            # Just return None and we'll handle it in the summary
            return None
    
    def get_activity_status(
        self, 
        last_sign_in: Optional[datetime],
        created_date: Optional[datetime]
    ) -> str:
        """
        Get human-readable activity status
        
        Args:
            last_sign_in: When the SPN last signed in
            created_date: When the SPN was created
            
        Returns:
            Status string (never_used, stale, active, unknown)
        """
        if last_sign_in is None:
            # Check if it's truly never used or just no data
            # If we definitively don't have audit log access, we cannot conclude never_used.
            if self.has_auditlog_access is False:
                return "unknown"

            if created_date:
                # Handle timezone-aware datetime
                if created_date.tzinfo is not None:
                    created_date = created_date.replace(tzinfo=None)
                days_since_creation = (datetime.utcnow() - created_date).days
                if days_since_creation > 30:
                    return "never_used"  # Created >30 days ago but never used
            return "unknown"  # No data available
        
        now = datetime.utcnow()
        # Handle timezone-aware datetime
        if last_sign_in.tzinfo is not None:
            last_sign_in = last_sign_in.replace(tzinfo=None)
        days_since_activity = (now - last_sign_in).days
        
        if days_since_activity > 90:
            return "stale"      # No activity in 90+ days
        elif days_since_activity > 30:
            return "inactive"   # No activity in 30-90 days
        else:
            return "active"     # Activity within last 30 days
    
    @staticmethod
    def _parse_datetime(dt_string: Optional[str]) -> Optional[datetime]:
        """Parse ISO datetime string"""
        if not dt_string:
            return None
        try:
            # Handle both formats: with and without microseconds
            if '.' in dt_string:
                return datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
            else:
                return datetime.strptime(dt_string.replace('Z', ''), '%Y-%m-%dT%H:%M:%S')
        except:
            return None
