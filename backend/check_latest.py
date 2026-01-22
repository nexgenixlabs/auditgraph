import json
import glob
import os

# Find the most recent file
files = glob.glob('discovery_results_*.json')
if files:
    latest_file = max(files, key=os.path.getctime)
    print(f"Reading: {latest_file}\n")
    
    with open(latest_file, 'r') as f:
        data = json.load(f)
    
    print(f"Statistics from latest run:")
    print(f"  Total: {data['statistics']['total_identities']}")
    print(f"  Microsoft: {data['statistics']['microsoft_system_spns']}")
    print(f"  Custom: {data['statistics']['custom_spns']}")
    print(f"  Medium Risks: {data['statistics']['medium_risks']}\n")
    
    medium_risks = [i for i in data['identities'] if i['risk_level'] == 'medium']
    
    print(f"Actual Medium Risks Found: {len(medium_risks)}\n")
    
    for i, identity in enumerate(medium_risks, 1):
        print(f"{i}. {identity['display_name']}")
        print(f"   is_microsoft: {identity.get('is_microsoft_system', 'N/A')}")
        print(f"   reasons: {identity.get('risk_reasons', [])}")
        print()
else:
    print("No discovery results found!")
