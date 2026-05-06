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

Open local observability UI:

```bash
http://localhost:8088/
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

## Web UI and Live Stream

The collector now serves a built-in local OT observability console from:

- `GET /` -> web UI
- `GET /events/stream` -> SSE event stream

UI sections:

- Dashboard
- Messages
- Sources
- Rule Matrix
- Forwarding
- Settings

UI features include:

- real-time event stream with pause/resume
- dense message table with badges and JSON expansion
- source CRUD with persistent config
- rule matrix CRUD with first-match evaluation and sampling/drop/forward decisions
- forwarding controls and connection test
- summary KPIs and charts

## Extended APIs

- `GET /events?limit=100&source_type=opcua&category=operator_action&search=...`
- `GET /events/stream`
- `GET /stats/summary`
- `GET /stats/timeline`
- `GET /sources` (known + observed source activity)
- `GET /filter/config`
- `POST /filter/config`
- `GET /config/sources`
- `POST /config/sources`
- `PUT /config/sources/{id}`
- `DELETE /config/sources/{id}`
- `GET /config/rules`
- `POST /config/rules`
- `PUT /config/rules/{id}`
- `DELETE /config/rules/{id}`
- `POST /config/rules/test`
- `GET /config/forwarding`
- `POST /config/forwarding`
- `POST /forwarding/test`

Example filter config payload:

```json
{
  "drop_opcua_reads": true,
  "drop_duplicates": true,
  "sample_rate": 0.2,
  "dedup_window_seconds": 5,
  "max_events_per_second": 500,
  "opcua_read_keep_every": 0
}
```

## Load Reduction

Load reduction is applied before storage and forwarding:

- rule-driven keep/drop/sample/store_only/forward_only decisions
- duplicate suppression in a short time window
- per-source event rate limiting
- decision tags added to stored events:
  - `tags["collector_decision"]`
  - `tags["matched_rule_id"]`

This keeps ingestion resilient and reduces DMZ forwarding noise without changing the public event schema.

## OPC UA Command-Level Enrichment

The normalizer includes OPC UA-specific enrichment for logs emitted by `powergrid_opcua_server`.

- `[OPCUA]` + `[CMD]` logs are classified as `event_category=operator_action`.
- OPC UA variants are handled: `[READ][CMD]`, `[WRITE][CMD]`, `[SESSION]`, `[SECURITY]`, `[ERROR]`, `[STARTUP]`, `[SHUTDOWN]`.
- OPC UA command/session/security fields are extracted into `tags` when present:
  - `opcua_operation`
  - `opcua_event_type`
  - `user`
  - `node_id`
  - `browse_name`
  - `display_name`
  - `mode`
  - `value`
- Sensitive control actions add `tags["sensitive_action"]="true"` when message content matches sensitive keywords (for example: `Reset`, `Emergency`, `Stop`, `Start`, `Vanne`, `Switch`, `DCY`).
- MITRE ATT&CK ICS hint tags are added:
  - command/control actions: `Impair Process Control` + `Manipulation of Control`
  - unauthorized/rejected/security actions: `Initial Access / Defense Evasion` + `Unauthorized Access Attempt`

This enrichment does not change the public event schema and does not alter existing non-OPCUA parsing behavior.

## Future V2 Direction

- Dedicated DMZ collector service
- Frontend analytics/UI
- IDS ingestion
- OT firewall (`.254`) syslog ingestion
- SIEM forwarding integrations
