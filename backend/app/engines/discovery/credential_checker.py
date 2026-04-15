"""
Credential Expiration Checker for Azure Service Principals

This module provides the CredentialChecker class that queries Microsoft Graph API
to check when service principal credentials (secrets and certificates) will expire.
This is critical for preventing service outages and maintaining security hygiene.

Credential Types Checked:
    - Password Credentials (Secrets): Client secrets with configurable expiry
    - Key Credentials (Certificates): X.509 certificates for authentication

Expiration Status Levels:
    - 'expired': Credential has already expired (immediate action needed)
    - 'critical': Expires within 7 days (urgent)
    - 'warning': Expires within 30 days (plan rotation)
    - 'good': More than 30 days until expiration
    - 'no_expiration': Federated credentials or no credentials found

API Requirements:
    - Microsoft Graph API access
    - Application.Read.All permission (to read credential metadata)

Usage:
    checker = CredentialChecker(azure_credential)
    expiration = checker.check_credential_expiration(app_id)
    status = checker.get_expiration_status(expiration)

Note: This checker queries credential metadata only - it does not have access
to actual secret values or private keys.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

import requests


class CredentialChecker:
    """Check service principal credential expiration"""
    
    def __init__(self, credential):
        """
        Initialize with Azure credential
        
        Args:
            credential: Azure ClientSecretCredential object
        """
        self.credential = credential
        # Whether the current token has access to read application credentials.
        # None = not yet determined, True/False after first call.
        self.has_app_read_access: Optional[bool] = None

        self._session = requests.Session()
    
    def check_credential_expiration(self, app_id: str) -> Optional[datetime]:
        """
        Check when the service principal's credentials expire
        
        Args:
            app_id: Application ID of the service principal
            
        Returns:
            Datetime of earliest credential expiration, or None if no credentials
        """
        try:
            # Get access token for Microsoft Graph
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }
            
            # Query the application to get credential info
            url = f"https://graph.microsoft.com/v1.0/applications"
            params = {
                '$filter': f"appId eq '{app_id}'",
                '$select': 'id,appId,displayName,passwordCredentials,keyCredentials'
            }
            
            response = self._session.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 200:
                self.has_app_read_access = True
                data = response.json()
                apps = data.get('value', [])
                
                if not apps:
                    return None
                
                app = apps[0]
                
                # Check password credentials (secrets)
                password_creds = app.get('passwordCredentials', [])
                key_creds = app.get('keyCredentials', [])
                
                expiration_dates = []
                
                # Collect all expiration dates
                for cred in password_creds:
                    end_date = cred.get('endDateTime')
                    if end_date:
                        expiration_dates.append(self._parse_datetime(end_date))
                
                for cred in key_creds:
                    end_date = cred.get('endDateTime')
                    if end_date:
                        expiration_dates.append(self._parse_datetime(end_date))
                
                # Return the earliest expiration date
                if expiration_dates:
                    valid_dates = [d for d in expiration_dates if d]
                    return min(valid_dates) if valid_dates else None
                
                return None
            
            if response.status_code == 403:
                self.has_app_read_access = False
            return None
            
        except Exception:
            # Keep silent at scale; caller can treat as unknown.
            return None
    
    def get_expiration_status(self, expiration_date: Optional[datetime]) -> str:
        """
        Get human-readable expiration status
        
        Args:
            expiration_date: When credentials expire
            
        Returns:
            Status string (expired, critical, warning, good)
        """
        if not expiration_date:
            # Could be federated-only or no credentials, or missing permission.
            return "no_expiration"
        
        now = datetime.utcnow()
        
        if expiration_date < now:
            return "expired"
        
        days_until_expiration = (expiration_date - now).days
        
        if days_until_expiration < 7:
            return "critical"  # Less than 7 days
        elif days_until_expiration < 30:
            return "warning"   # 7-30 days
        else:
            return "good"      # More than 30 days
    
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
        except Exception:
            return None
