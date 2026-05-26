#!/bin/bash
# ============================================================
# AuditGraph — Kill + Restart Backend
# Usage: bash auditgraph_restart.sh
# ============================================================

BACKEND_DIR="/Users/sangabattula/projects/auditgraph/backend"
LOG_FILE="/tmp/auditgraph-5001.log"
ENV_FILE=".env.local"

echo ""
echo "============================================================"
echo "  AuditGraph Backend Restart"
echo "============================================================"

# Step 1 — Find and kill anything on port 5000
echo ""
echo "► Step 1: Checking port 5000..."
PID=$(lsof -ti :5000)
if [ -n "$PID" ]; then
  echo "  Found process PID=$PID on port 5000 — killing..."
  kill -9 $PID
  sleep 2
  echo "  ✅ Process killed"
else
  echo "  ✅ Port 5000 is free"
fi

# Step 2 — Also check port 5001 just in case
echo ""
echo "► Step 2: Checking port 5001..."
PID2=$(lsof -ti :5001)
if [ -n "$PID2" ]; then
  echo "  Found process PID=$PID2 on port 5001 — killing..."
  kill -9 $PID2
  sleep 2
  echo "  ✅ Process killed"
else
  echo "  ✅ Port 5001 is free"
fi

# Step 3 — Clear stale .pyc cache
echo ""
echo "► Step 3: Clearing .pyc cache..."
find "$BACKEND_DIR" -name "*.pyc" -delete 2>/dev/null
find "$BACKEND_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
echo "  ✅ Cache cleared"

# Step 4 — Start backend
echo ""
echo "► Step 4: Starting backend..."
cd "$BACKEND_DIR"
source venv/bin/activate
ENV_FILE=$ENV_FILE python wsgi.py > "$LOG_FILE" 2>&1 &
NEW_PID=$!
echo "  Backend started with PID=$NEW_PID"
echo "  Log: $LOG_FILE"

# Step 5 — Wait and verify
echo ""
echo "► Step 5: Waiting for startup (10s)..."
sleep 10

# Check it's still running
if kill -0 $NEW_PID 2>/dev/null; then
  echo "  ✅ Process is running"
else
  echo "  ❌ Process died — check log:"
  tail -20 "$LOG_FILE"
  exit 1
fi

# Step 6 — Confirm key flags
echo ""
echo "► Step 6: Verifying configuration..."
AI_GOV=$(grep "AI_AGENT_GOV" "$LOG_FILE" | tail -1)
POST_SCAN=$(grep "POST-SCAN" "$LOG_FILE" | tail -1)
RUNNING=$(grep "Running on" "$LOG_FILE" | tail -1)

if [ -n "$AI_GOV" ]; then
  echo "  ✅ $AI_GOV"
else
  echo "  ❌ AI_AGENT_GOV not found in log"
fi

if [ -n "$POST_SCAN" ]; then
  echo "  ✅ $POST_SCAN"
else
  echo "  ❌ POST-SCAN not found in log"
fi

if [ -n "$RUNNING" ]; then
  echo "  ✅ $RUNNING"
else
  echo "  ❌ Server not listening yet"
fi

echo ""
echo "============================================================"
echo "  Backend ready. Tail logs with:"
echo "  tail -f $LOG_FILE | grep -E '\[POST-SCAN\]|ERROR|WARNING'"
echo "============================================================"
echo ""
