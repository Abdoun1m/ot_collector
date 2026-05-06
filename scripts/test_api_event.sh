#!/usr/bin/env sh
set -eu

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8088}"

echo "POST /test-event on ${HOST}:${PORT}"
curl -sS -X POST "http://${HOST}:${PORT}/test-event" \
  -H "Content-Type: application/json" \
  -d '{"raw":"May 06 10:25:00 fuxa-server node[1881]: [INFO] User '\''admin'\'' wrote value 1 to Coils 0 (Motor_Start)","source_ip":"192.168.1.60"}'
echo

