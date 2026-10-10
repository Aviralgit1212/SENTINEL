#!/usr/bin/env bash
# Starts the Sentinel API server detached on the configured port.
# Usage: ./start-server.sh [port] [python-executable]
set -e
cd "$(dirname "$0")/server"

PORT="${1:-5001}"
PYTHON="${2:-${PYTHON_EXECUTABLE:-}}"

mkdir -p /tmp
LOG=/tmp/sentinel-server.log

# Stop any previous instance
pkill -f "tsx src/server.ts" 2>/dev/null || true
sleep 1

if [ -n "$PYTHON" ]; then
  PYTHON_EXECUTABLE="$PYTHON" setsid nohup node --no-warnings node_modules/.bin/tsx src/server.ts "$PORT" > "$LOG" 2>&1 < /dev/null &
else
  setsid nohup node --no-warnings node_modules/.bin/tsx src/server.ts "$PORT" > "$LOG" 2>&1 < /dev/null &
fi

# Wait for readiness
for i in $(seq 1 20); do
  sleep 0.5
  if curl -sf --max-time 2 "http://127.0.0.1:${PORT}/api/health" > /dev/null 2>&1; then
    echo "server ready on :${PORT} (log: $LOG)"
    exit 0
  fi
done
echo "server failed to start:" >&2
tail -20 "$LOG" >&2
exit 1
