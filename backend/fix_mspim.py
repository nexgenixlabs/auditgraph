with open('app/engines/discovery/models.py', 'r') as f:
    content = f.read()

# Add MS-PIM to patterns (it's there but maybe not matching)
# Actually, let's check if the pattern 'MS ' is matching 'MS-PIM'
# The issue is 'MS ' with space won't match 'MS-PIM'

content = content.replace("'MS ',  # \"MS Teams Griffin Assistant\"", "'MS',  # Matches MS-PIM, MS Teams, etc")

with open('app/engines/discovery/models.py', 'w') as f:
    f.write(content)

print("✅ Fixed MS pattern to catch MS-PIM")
