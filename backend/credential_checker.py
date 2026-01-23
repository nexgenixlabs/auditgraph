"""
Credential expiration checking for Azure service principals
"""
from datetime import datetime, timedelta
from typing import List, Optional
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
            
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
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
            
            return None
            
        except Exception as e:
            print(f"  ⚠️  Error checking credentials for {app_id}: {str(e)}")
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
        except:
            return None
