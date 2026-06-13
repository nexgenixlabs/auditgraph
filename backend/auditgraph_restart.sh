#!/bin/bash
# ============================================================
# AuditGraph — Restart Backend + Frontend
#
# Usage:
#   bash auditgraph_restart.sh            # restart both (default)
#   bash auditgraph_restart.sh backend    # backend only
#   bash auditgraph_restart.sh frontend   # frontend only
#   bash auditgraph_restart.sh stop       # stop both, don't restart
# ============================================================

set -u

BACKEND_DIR="/Users/sangabattula/projects/auditgraph/backend"
FRONTEND_DIR="/Users/sangabattula/projects/auditgraph/frontend"
BACKEND_LOG="/tmp/auditgraph-5001.log"
FRONTEND_LOG="/tmp/auditgraph-3000.log"
ENV_FILE=".env.local"

BACKEND_PORTS=(5000 5001)
FRONTEND_PORT=3000

MODE="${1:-all}"

# ── helpers ────────────────────────────────────────────────
kill_port() {
  local port="$1"
  local pid
  pid=$(lsof -ti :"$port" 2>/dev/null)
  if [ -n "$pid" ]; then
    echo "  Found PID=$pid on port $port — killing..."
    kill -9 $pid 2>/dev/null || true
    sleep 2
    echo "  ✅ Killed"
  else
    echo "  ✅ Port $port is free"
  fi
}

stop_backend() {
  echo ""
  echo "► Stopping backend..."
  for p in "${BACKEND_PORTS[@]}"; do
    echo "  Port $p:"
    kill_port "$p"
  done
}

stop_frontend() {
  echo ""
  echo "► Stopping frontend..."
  echo "  Port $FRONTEND_PORT:"
  kill_port "$FRONTEND_PORT"
  # Kill stray react-scripts node processes that may have detached from the port
  local node_pids
  node_pids=$(pgrep -f "react-scripts/scripts/start" 2>/dev/null || true)
  if [ -n "$node_pids" ]; then
    echo "  Killing react-scripts: $node_pids"
    kill -9 $node_pids 2>/dev/null || true
  fi
}

start_backend() {
  echo ""
  echo "► Starting backend..."

  # Clear stale .pyc cache so freshly edited handlers are picked up
  echo "  Clearing .pyc cache..."
  find "$BACKEND_DIR" -name "*.pyc" -delete 2>/dev/null || true
  find "$BACKEND_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

  cd "$BACKEND_DIR" || { echo "❌ cannot cd $BACKEND_DIR"; return 1; }

  if [ ! -d "venv" ]; then
    echo "  ❌ venv/ missing in $BACKEND_DIR"
    return 1
  fi
  # shellcheck disable=SC1091
  source venv/bin/activate

  ENV_FILE=$ENV_FILE nohup python wsgi.py > "$BACKEND_LOG" 2>&1 &
  local pid=$!
  disown $pid 2>/dev/null || true
  echo "  Backend started · PID=$pid · log=$BACKEND_LOG"

  echo "  Waiting up to 15s for /api/health..."
  for i in $(seq 1 15); do
    if curl -sf http://localhost:5001/api/health >/dev/null 2>&1; then
      echo "  ✅ /api/health responding after ${i}s"
      break
    fi
    if ! kill -0 $pid 2>/dev/null; then
      echo "  ❌ Process died — log tail:"
      tail -20 "$BACKEND_LOG"
      return 1
    fi
    sleep 1
  done

  echo ""
  echo "  Backend config:"
  grep -E "AI_AGENT_GOV|POST-SCAN" "$BACKEND_LOG" | tail -2 | sed 's/^/    /'
  grep -E "Running on" "$BACKEND_LOG" | tail -1 | sed 's/^/    /'
}

start_frontend() {
  echo ""
  echo "► Starting frontend (react-scripts on port $FRONTEND_PORT)..."

  cd "$FRONTEND_DIR" || { echo "❌ cannot cd $FRONTEND_DIR"; return 1; }

  if [ ! -d "node_modules" ]; then
    echo "  ⚠ node_modules missing — running npm install (this can take a few minutes)..."
    npm install --no-audit --no-fund || { echo "  ❌ npm install failed"; return 1; }
  fi

  # BROWSER=none keeps a new Chrome tab from popping every restart
  BROWSER=none nohup npm start > "$FRONTEND_LOG" 2>&1 &
  local pid=$!
  disown $pid 2>/dev/null || true
  echo "  Frontend started · PID=$pid · log=$FRONTEND_LOG"

  echo "  Waiting up to 60s for webpack to compile..."
  for i in $(seq 1 60); do
    if curl -sf http://localhost:$FRONTEND_PORT >/dev/null 2>&1; then
      echo "  ✅ http://localhost:$FRONTEND_PORT responding after ${i}s"
      break
    fi
    if ! kill -0 $pid 2>/dev/null; then
      echo "  ❌ Process died — log tail:"
      tail -20 "$FRONTEND_LOG"
      return 1
    fi
    sleep 1
  done

  if grep -qE "Compiled with problems|Failed to compile" "$FRONTEND_LOG"; then
    echo "  ⚠ Compiled with problems — see $FRONTEND_LOG"
  fi
}

# ── main ──────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  AuditGraph Restart · mode=$MODE"
echo "============================================================"

case "$MODE" in
  backend)
    stop_backend
    start_backend
    ;;
  frontend)
    stop_frontend
    start_frontend
    ;;
  stop)
    stop_backend
    stop_frontend
    ;;
  all|both|"")
    stop_backend
    stop_frontend
    start_backend
    start_frontend
    ;;
  *)
    echo "Unknown mode: $MODE"
    echo "Usage: bash auditgraph_restart.sh [backend|frontend|stop|all]"
    exit 1
    ;;
esac

echo ""
echo "============================================================"
echo "  Done."
echo "  Backend log:  tail -f $BACKEND_LOG  | grep -E '\[POST-SCAN\]|ERROR|WARNING'"
echo "  Frontend log: tail -f $FRONTEND_LOG | grep -E 'Compiled|ERROR|WARNING'"
echo "============================================================"
echo ""
