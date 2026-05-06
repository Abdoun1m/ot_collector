#!/usr/bin/env sh
set -eu

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5514}"

echo "Sending OpenPLC-like RFC5424 syslog to ${HOST}:${PORT}/udp"
printf "%s\n" "<134>1 2026-05-06T09:12:01.458Z openplc-rt - - - [OpenPLC Runtime] version v3.0 starting..." | nc -u -w1 "${HOST}" "${PORT}"
printf "%s\n" "<134>1 2026-05-06T09:12:05.120Z openplc-rt - - - [Modbus] Server: Client accepted! ID: 10 (IP: 192.168.1.50)" | nc -u -w1 "${HOST}" "${PORT}"
printf "%s\n" "<132>1 2026-05-06T09:15:22.980Z openplc-rt - - - [Warning] Scan cycle time exceeded! Actual: 14ms (Limit: 10ms)" | nc -u -w1 "${HOST}" "${PORT}"
echo "Done."

