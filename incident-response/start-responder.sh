#!/usr/bin/env bash
# Start/stop the incident responder on the WSL host.
#
#   incident-response/start-responder.sh start    # background, logs to incident-response/logs/responder.log
#   incident-response/start-responder.sh stop     # SIGTERM: stops accepting, ends any running claude, exits
#   incident-response/start-responder.sh status
#
# Listens on 127.0.0.1:8001 (POST /alerts, GET /healthz). logs/ and state/ are gitignored.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
LOG_DIR="incident-response/logs"
PID_FILE="incident-response/state/responder.pid"

running() { [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; }

case "${1:-}" in
  start)
    if running; then echo "responder already running (pid $(cat "$PID_FILE"))"; exit 0; fi
    mkdir -p "$LOG_DIR" "$(dirname "$PID_FILE")"
    nohup uv run --frozen python incident-response/responder.py >> "$LOG_DIR/responder.log" 2>&1 &
    echo $! > "$PID_FILE"
    for _ in $(seq 50); do
      curl -sf -m 1 http://127.0.0.1:8001/healthz >/dev/null 2>&1 && { echo "responder started (pid $(cat "$PID_FILE"))"; exit 0; }
      running || break
      sleep 0.2
    done
    echo "responder failed to start; see $LOG_DIR/responder.log" >&2
    exit 1
    ;;
  stop)
    if ! running; then echo "responder not running"; rm -f "$PID_FILE"; exit 0; fi
    pid="$(cat "$PID_FILE")"
    # The pid is `uv run`'s; uv forwards SIGTERM to its python child (checked: clean exit, no orphan).
    kill -TERM "$pid"
    for _ in $(seq 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
    if kill -0 "$pid" 2>/dev/null; then echo "responder did not stop in 20s" >&2; exit 1; fi
    rm -f "$PID_FILE"
    echo "responder stopped"
    ;;
  status)
    if running; then echo "running (pid $(cat "$PID_FILE"))"; curl -s -m 2 http://127.0.0.1:8001/healthz || true; echo
    else echo "not running"; fi
    ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
