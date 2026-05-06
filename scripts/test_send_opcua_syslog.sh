#!/usr/bin/env sh
set -eu

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5514}"

echo "Sending OPC UA-like RFC5424 syslog to ${HOST}:${PORT}/udp"
printf "%s\n" "<134>1 2026-05-06T10:15:33Z powergrid-opcua powergrid_opcua_server - - - [OPCUA] Server started on opc.tcp://192.168.1.62:4840" | nc -u -w1 "${HOST}" "${PORT}"
printf "%s\n" "<132>1 2026-05-06T10:16:10Z powergrid-opcua powergrid_opcua_server - - - [OPCUA] Client session created from 192.168.10.20" | nc -u -w1 "${HOST}" "${PORT}"
printf "%s\n" "<131>1 2026-05-06T10:17:00Z powergrid-opcua powergrid_opcua_server - - - [OPCUA] Rejected connection from 192.168.1.99" | nc -u -w1 "${HOST}" "${PORT}"
echo "Done."

