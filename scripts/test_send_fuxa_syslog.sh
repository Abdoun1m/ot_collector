#!/usr/bin/env sh
set -eu

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5514}"

echo "Sending FUXA-like syslog to ${HOST}:${PORT}/udp"
printf "%s\n" "May 06 10:15:30 fuxa-server node[1881]: [INFO] FUXA Server started on port 1881" | nc -u -w1 "${HOST}" "${PORT}"
printf "%s\n" "May 06 10:22:10 fuxa-server node[1881]: [WARN] [OpenPLC_Master] Timeout reading Holding Register 1024" | nc -u -w1 "${HOST}" "${PORT}"
printf "%s\n" "May 06 10:30:00 fuxa-server node[1881]: [WARN] Failed login attempt for user: admin from 192.168.1.99" | nc -u -w1 "${HOST}" "${PORT}"
echo "Done."

