#!/usr/bin/env bash
# End-to-end check of the browser egress guard against a canary on a private
# Docker network. Usage: egress-e2e.sh <solver-image>
set -euo pipefail

image="${1:?usage: egress-e2e.sh <solver-image>}"
run="fsk-e2e-$$"
network="$run-net"
canary="$run-canary"
solver="$run-solver"

cleanup() {
  docker rm -f "$solver" "$canary" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  echo "--- solver log" >&2; docker logs "$solver" 2>&1 | tail -40 >&2 || true
  echo "--- canary log" >&2; docker logs "$canary" 2>&1 | tail -20 >&2 || true
  exit 1
}

docker network create "$network" >/dev/null
docker run -d --name "$canary" --network "$network" python:3.11-slim \
  python -u -m http.server 8000 >/dev/null
docker run -d --name "$solver" --network "$network" -p 127.0.0.1::8191 \
  -e LOG_LEVEL=info "$image" >/dev/null

port="$(docker port "$solver" 8191/tcp | head -1 | sed 's/.*://')"
solver_url="http://127.0.0.1:$port"
canary_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$canary")"

for _ in $(seq 1 60); do
  curl -sf "$solver_url/" >/dev/null && break
  sleep 2
done
index="$(curl -sf "$solver_url/")" || fail "solver never became ready"
grep -q '"kani.egress-guard/1"' <<<"$index" || fail "index does not advertise kani.egress-guard/1"

# Control: without the browser, the canary is reachable from the solver.
docker exec "$solver" curl -s -o /dev/null "http://$canary:8000/control"
docker logs "$canary" 2>&1 | grep -q 'GET /control' || fail "control request never reached the canary"

capture() {
  local url="$1"
  curl -s -X POST "$solver_url/v1" -H 'Content-Type: application/json' --data @- <<JSON >/dev/null
{"cmd": "kani.capture", "url": "$url",
 "initScript": "window.addEventListener('load', function () { window.passPayload('loaded'); });",
 "captureTimeout": 8000, "maxTimeout": 60000}
JSON
}

capture "http://$canary:8000/nav-by-name"
capture "http://$canary_ip:8000/nav-by-ip"

if docker logs "$canary" 2>&1 | grep -q 'GET /nav-'; then
  fail "the browser reached the canary"
fi
docker logs "$solver" 2>&1 | grep -q "Egress guard refused: $canary resolves to a forbidden address" \
  || fail "no guard refusal logged for the canary's name"
docker logs "$solver" 2>&1 | grep -q "Egress guard refused: $canary_ip resolves to a forbidden address" \
  || fail "no guard refusal logged for the canary's IP"

echo "egress guard end-to-end: OK"
