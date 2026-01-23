# Test 1: Health check
echo "Testing /api/health..."
curl http://localhost:5000/api/health | python3 -m json.tool

echo -e "\n\n"

# Test 2: Get stats
echo "Testing /api/stats..."
curl http://localhost:5000/api/stats | python3 -m json.tool

echo -e "\n\n"

# Test 3: Get risks
echo "Testing /api/risks..."
curl http://localhost:5000/api/risks | python3 -m json.tool

echo -e "\n\n"

# Test 4: Get all identities
echo "Testing /api/identities..."
curl http://localhost:5000/api/identities | python3 -m json.tool

echo -e "\n\n"

# Test 5: Get discovery runs
echo "Testing /api/runs..."
curl http://localhost:5000/api/runs | python3 -m json.tool
