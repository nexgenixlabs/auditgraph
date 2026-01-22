import json

with open('discovery_results_20260122_114138.json', 'r') as f:
    data = json.load(f)

medium_risks = [i for i in data['identities'] if i['risk_level'] == 'medium']

print(f"Total Medium Risks: {len(medium_risks)}\n")
print("First 20 Medium Risk Identities:\n")

for i, identity in enumerate(medium_risks[:20]):
    print(f"{i+1}. {identity['display_name']}")
    print(f"   is_microsoft_system: {identity.get('is_microsoft_system')}")
    print()
