# Read current models.py
with open('app/engines/discovery/models.py', 'r') as f:
    content = f.read()

# Find the patterns list
import re
pattern_start = content.find('MICROSOFT_DISPLAY_NAME_PATTERNS = [')
pattern_end = content.find(']', pattern_start) + 1
old_patterns_section = content[pattern_start:pattern_end]

# New complete patterns list
new_patterns_section = '''MICROSOFT_DISPLAY_NAME_PATTERNS = [
    'Microsoft',
    'Office 365',
    'Office365',
    'Office',
    'Windows',
    'Azure',
    'Skype',
    'SharePoint',
    'Teams',
    'Exchange',
    'Dynamics',
    'Power',
    'Intune',
    'Substrate',
    'Conferencing',
    'Sway',
    'Bing',
    'Cortana',
    'Viva',
    'M365',
    'O365',
    'o365',
    'AAD',
    'MS ',  # "MS Teams Griffin Assistant"
    'Device Registration',
    'Messaging Bot',
    'Media Analysis',
    'Customer Experience',
    'Customer Service',
    'Signup',
    'OneProfile',
    'SubscriptionRP',
    'Common Data Service',
    'Portfolios',
    'ProductsLifecycle',
    'CAP',
    'CAB',
    'OMS',
    'OCaaS',
    'MCAPI',
    'Safelinks',
    'IC3',
    'IDS-PROD',
    'Graph Connector',
    'SPAuthEvent',
    'Request Approvals',
    'Policy Administration',
    'Narada',
    'WeveEngine',
    'Dataverse',
    'Billing RP',
    'IAM',
    'CloudLicensing',
    'IPSubstrate',
    'aciapi',
    'ESTS',
    'CompliancePolicy',
    'Configuration Manager',
    'ProjectWorkManagement',
    'PushChannel',
    'WindowsUpdate',
    'TenantSearchProcessors',
    'DeploymentScheduler',
    'Connectors',
    'Virtual Visits',
    'Conference Auto Attendant',
    'PPE-',
    'Privacy Management',
    'People Profile',
    'Group Configuration',
    'SalesInsights',
    'Meeting Migration',
]'''

content = content.replace(old_patterns_section, new_patterns_section)

with open('app/engines/discovery/models.py', 'w') as f:
    f.write(content)

print("✅ Added final Microsoft service patterns")
print("New patterns added:")
print("  - Customer Service")
print("  - ProductsLifecycle")
print("  - Connectors")
print("  - Virtual Visits")
print("  - Conference Auto Attendant")
print("  - PPE- (pre-production environment)")
print("  - Privacy Management")
print("  - People Profile")
print("  - Group Configuration")
print("  - SalesInsights")
print("  - Meeting Migration")
print("  - MS (for MS Teams Griffin)")
print("  - o365 (lowercase)")
