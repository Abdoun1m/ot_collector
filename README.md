# OT Collector (LabShock/DataProtect) - V1

Native Go OT security event collector for LabShock/DataProtect OT cyber-range environments.

This service passively receives syslog from OT assets, normalizes logs into structured events, stores them locally as JSONL, and optionally forwards them to a future DMZ collector.

## What This Service Does

- Receives syslog over UDP (`514`) and TCP (`1514`)
- Parses RFC5424-like, RFC3164-like, and raw syslog lines
- Normalizes into a unified OT event schema
- Appends events to `/data/events.jsonl`
- Exposes local HTTP API on `8088`
- Optionally forwards each event to a DMZ endpoint (best effort)

## Architecture

`PLC / FUXA / OPC UA -> OT Collector -> (future) DMZ Collector`

The collector is passive and parallel. It does not sit inline with the MES data path.

Existing MES/data pipeline remains unchanged:

`OPC UA Server -> OPC UA DMZ Gateway -> InfluxDB -> Node-RED -> MES frontend`

## Build

```bash
docker compose -f docker-compose.ot.yml build
```

## Run

```bash
docker compose -f docker-compose.ot.yml up -d
```

## Test

```bash
curl http://localhost:8088/health
./scripts/test_send_fuxa_syslog.sh
curl http://localhost:8088/events
```

Additional tests:

```bash
./scripts/test_send_openplc_syslog.sh
./scripts/test_send_opcua_syslog.sh
curl http://localhost:8088/stats
```

## FUXA Syslog Configuration

In FUXA UI:

- Settings -> Syslog Host: `192.168.1.70`
- Port: `514`

## LabShock Integration

- Keep existing `docker-compose.yml` unchanged.
- Add the collector using [deploy/docker-compose.addon.yml](/C:/Users/User/Documents/GitHub/ot_collector/deploy/docker-compose.addon.yml).
- Attach `ot_collector` container to `br-labshock` with `192.168.1.70/24` using your existing OVS attach script flow.
- See [deploy/attach_ot_collector_snippet.sh](/C:/Users/User/Documents/GitHub/ot_collector/deploy/attach_ot_collector_snippet.sh) for a safe snippet template.

## network_mode none + OVS

This container runs with `network_mode: none` and is expected to be manually attached to OVS (`br-labshock`) through your existing scripts. This matches current LabShock container networking behavior.

## MES Safety

This collector only observes, logs, and forwards events. It does not intercept or alter MES/OPC UA DMZ data flows.

## Future V2 Direction

- Dedicated DMZ collector service
- Frontend analytics/UI
- IDS ingestion
- OT firewall (`.254`) syslog ingestion
- SIEM forwarding integrations

