#!/usr/bin/env bash
# Canary: can Grafana (in the order-tracker compose network) reach an alert receiver?
#
#   incident-response/canary/network-probe.sh
#
# Probes two designs and prints a PASS/FAIL matrix:
#   A. a listener on the WSL host (python http.server), bound to 127.0.0.1 and to
#      0.0.0.0, reached from the grafana container (host.docker.internal, WSL IP)
#      and from a throwaway busybox on the compose network (--add-host=hostgw:host-gateway);
#   B. a throwaway receiver container on the compose network that publishes
#      127.0.0.1:$RECV_PORT and writes each POST body to incident-response/inbox/.
# Needs the stack running (`docker compose up -d --wait`). Everything it starts
# (listeners, containers, inbox files it wrote) is removed on exit.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

HOST_PORT="${HOST_PORT:-18765}"
RECV_PORT="${RECV_PORT:-18766}"
NET="order-tracker_default"
RECV_NAME="ot-canary-receiver"
RECV_ALIAS="responder"
INBOX="$ROOT/incident-response/inbox"
BUSYBOX="busybox:1.37"
RECV_IMAGE="python:3.12-slim"
WSL_IP="$(hostname -I | awk '{print $1}')"
TAG="canary-$(date -u +%Y%m%dT%H%M%SZ)-$$"

SERVER_PID=""
SERVE_DIR=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
  [ -n "$SERVE_DIR" ] && rm -rf "$SERVE_DIR"
  docker rm -f "$RECV_NAME" >/dev/null 2>&1
  docker ps -aq --filter "label=ot-canary=1" | xargs -r docker rm -f >/dev/null 2>&1
  rm -f "$INBOX"/"$TAG"-* 2>/dev/null
  rmdir "$INBOX" 2>/dev/null   # only if empty
}
trap cleanup EXIT

docker network inspect "$NET" >/dev/null 2>&1 || { echo "network $NET not found: start the stack first" >&2; exit 2; }
docker compose ps --status running --services | grep -qx grafana || { echo "grafana is not running" >&2; exit 2; }

row() { printf '%-4s | %-58s | %s\n' "$1" "$2" "$3"; }
probe() { # <label> <command...>: PASS if the command exits 0
  local label="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then row PASS "$label" ""; else row FAIL "$label" "$(echo "$out" | tail -1 | cut -c1-70)"; fi
}
from_grafana() { docker compose exec -T grafana wget -q -O /dev/null -T 3 "$1"; }
from_busybox() {
  docker run --rm --label ot-canary=1 --network "$NET" --add-host=hostgw:host-gateway "$BUSYBOX" \
    wget -q -O /dev/null -T 3 "$1"
}

echo "WSL IP: $WSL_IP   host.docker.internal (as seen from grafana): $(docker compose exec -T grafana getent hosts host.docker.internal | awk '{print $1}')"
echo
echo "== A. listener on the WSL host (port $HOST_PORT)"
for BIND in 127.0.0.1 0.0.0.0; do
  SERVE_DIR="$(mktemp -d)"
  python3 -m http.server "$HOST_PORT" --bind "$BIND" --directory "$SERVE_DIR" >/dev/null 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 20); do curl -s -o /dev/null "http://127.0.0.1:$HOST_PORT/" 2>/dev/null && break; sleep 0.2; done
  probe "bind $BIND: WSL curl localhost" curl -sf -m 3 -o /dev/null "http://localhost:$HOST_PORT/"
  probe "bind $BIND: grafana -> host.docker.internal" from_grafana "http://host.docker.internal:$HOST_PORT/"
  probe "bind $BIND: grafana -> WSL IP $WSL_IP" from_grafana "http://$WSL_IP:$HOST_PORT/"
  probe "bind $BIND: busybox -> hostgw (host-gateway)" from_busybox "http://hostgw:$HOST_PORT/"
  probe "bind $BIND: busybox -> host.docker.internal" from_busybox "http://host.docker.internal:$HOST_PORT/"
  kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=""
  rm -rf "$SERVE_DIR"; SERVE_DIR=""
done

echo
echo "== B. receiver container on $NET, published on 127.0.0.1:$RECV_PORT, inbox bind-mounted"
mkdir -p "$INBOX"
docker run -d --name "$RECV_NAME" --label ot-canary=1 --network "$NET" --network-alias "$RECV_ALIAS" \
  --user "$(id -u):$(id -g)" -p "127.0.0.1:$RECV_PORT:8001" \
  -v "$INBOX:/inbox" -e TAG="$TAG" "$RECV_IMAGE" python -c '
import http.server, os, time
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        name = "/inbox/%s-%d.json" % (os.environ["TAG"], time.time_ns())
        with open(name, "wb") as f:
            f.write(body)
        self.send_response(202); self.end_headers(); self.wfile.write(b"accepted\n")
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8001), H).serve_forever()
' >/dev/null
for _ in $(seq 30); do curl -s -o /dev/null -X POST -d '{}' "http://127.0.0.1:$RECV_PORT/" 2>/dev/null && break; sleep 0.3; done
rm -f "$INBOX"/"$TAG"-*   # drop the readiness probe's file

post_from_grafana() { docker compose exec -T grafana wget -q -O /dev/null -T 3 --header 'Content-Type: application/json' --post-data "$2" "$1"; }
probe "WSL curl POST localhost:$RECV_PORT" curl -sf -m 3 -o /dev/null -H 'Content-Type: application/json' -d '{"from":"wsl"}' "http://localhost:$RECV_PORT/alerts"
probe "grafana POST -> $RECV_NAME:8001 (container name)" post_from_grafana "http://$RECV_NAME:8001/alerts" '{"from":"grafana-name"}'
probe "grafana POST -> $RECV_ALIAS:8001 (network alias)" post_from_grafana "http://$RECV_ALIAS:8001/alerts" '{"from":"grafana-alias"}'

echo
echo "== inbox files written by the receiver (as seen from WSL; owner uid:gid mode)"
me="$(id -u):$(id -g)"
count=0
for f in "$INBOX"/"$TAG"-*; do
  [ -e "$f" ] || continue
  count=$((count + 1))
  owner="$(stat -c '%u:%g' "$f")"
  printf '  %s  %s  %s  %s\n' "$(basename "$f" | sed "s/$TAG/<tag>/")" "$owner" "$(stat -c '%a' "$f")" "$(cat "$f")"
  [ "$owner" = "$me" ] || row FAIL "inbox file owned by $owner, expected $me" ""
done
[ "$count" -eq 3 ] && row PASS "3 POST bodies landed in incident-response/inbox/ owned by $me" "" \
                   || row FAIL "expected 3 inbox files, found $count" ""
