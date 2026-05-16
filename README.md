# DataProtect OT Collector

Native Go OT event collector for LabShock/DataProtect lab environments. The service ingests syslog (UDP/TCP), normalizes and enriches events into a small OT event schema, persists events as JSONL, exposes a local HTTP API and Web UI, and can forward events to an external DMZ collector.

## Features

- Syslog ingestion over UDP and TCP (configurable addresses)
- Parsing of RFC5424, RFC3164 and raw syslog lines
- Structured-JSON telemetry ingestion when JSON is embedded in syslog messages
- Built-in normalizer that infers `source_type`, `event_category`, severity and OPC UA fields
- Per-event rule engine for keep/drop/sample/forward decisions
- JSONL storage with repair endpoint (`/storage/repair`)
- Optional DMZ forwarding (HTTP POST) with connection test
- HTTP API for events, stats, sources, rules and forwarding configuration
- Server-Sent Events (SSE) stream at `/events/stream` for live UI
- Simple single-page Web UI served from the binary

## Repository Structure

- `cmd/ot-collector/main.go` — main entry point; initializes components and runs syslog servers and API
- `internal/` — core packages
  - `api/` — HTTP API server, handlers and SSE stream hub
  - `config/` — on-disk stores for sources, rules and forwarding and runtime config loader
  - `event/` — event schema (`Event` struct)
  - `filter/` — rule engine and runtime rate/duplication controls
  - `forwarder/` — DMZ forwarding client
  - `normalizer/` — message normalization and enrichment logic
  - `sources/` — source resolution (IP->asset) and resolver backed by `SourceStore`
  - `storage/` — JSONL append/read/repair implementation
  - `syslog/` — UDP/TCP servers and syslog parsers
- `web/` — built frontend: `index.html`, `app.js`, `styles.css` (embedded via `web/assets.go`)
- `deploy/` — deployment snippets (addon compose, attach script snippet)
- `scripts/` — small helper scripts used for manual testing

## How It Works (high level)

- `main.go` loads configuration and persistent stores (`/data/*.json` and `/data/events.jsonl`), starts UDP and TCP syslog listeners and an HTTP API server.
- Incoming syslog lines are parsed by `internal/syslog.Parse` into a `ParsedMessage`.
- `internal/normalizer` converts parsed messages into `event.Event`, performing heuristics (structured JSON extraction, firewall filterlog parsing, OPC UA enrichment, etc.).
- The `filter.Engine` evaluates configured rule matrix and runtime controls (rate limiting, deduplication, sampling) to decide store/forward/drop.
- Events that are stored are appended to the JSONL file by `internal/storage.JSONLStore`.
- If forwarding is enabled (per-rule or via global forwarding config), `internal/forwarder` posts events to the configured DMZ collector.
- The HTTP API exposes endpoints to read events, query statistics, manage sources/rules/forwarding, run tests, repair storage, and the SSE stream for the UI.

## Installation

Prerequisites: Go toolchain (to build from source) or Docker (recommended for quick runs).

Build locally:

```bash
go build -o ot-collector ./cmd/ot-collector
```

Run with Docker Compose (recommended in lab deployments):

```bash
docker compose -f docker-compose.ot.yml build
docker compose -f docker-compose.ot.yml up -d
```

Run directly (dev):

```bash
# run the collector (creates/uses /data paths)
OT_COLLECTOR_ZONE=OT API_ADDR=0.0.0.0:8088 go run ./cmd/ot-collector
```

## Configuration

Runtime configuration is environment-variable driven (see `internal/config/config.go`):

- `OT_COLLECTOR_ZONE` — zone name used in events (default: `OT`)
- `UDP_SYSLOG_ADDR` — UDP listen address (default: `0.0.0.0:514`)
- `TCP_SYSLOG_ADDR` — TCP listen address (default: `0.0.0.0:1514`)
- `API_ADDR` — HTTP API listen address (default: `0.0.0.0:8088`)
- `EVENTS_FILE` — JSONL events file path (default: `/data/events.jsonl`)
- `DMZ_COLLECTOR_URL` — optional global DMZ collector URL (default: empty)
- `LOG_LEVEL` — `debug|info|warn|error` (default: `info`)

Persistent per-instance configuration is stored under `/data/` by default (the store files are created if missing):

- `/data/sources.json` — known sources (`config.SourceConfig`) (defaults provided)
- `/data/rules.json` — rule matrix (`config.RuleConfig`) with default sample/keep rules
- `/data/forwarding.json` — forwarding settings and status

Note: file paths may be overridden by setting `EVENTS_FILE` env var.

## Usage / API

Health:

```bash
curl http://localhost:8088/health
```

Get recent events (filtering supported):

```bash
curl 'http://localhost:8088/events?limit=200&source_type=opcua&category=operator_action&search=reset'
```

Stream live events (SSE): connect to `/events/stream` (the Web UI uses this).

Manage sources:

```
GET  /config/sources
POST /config/sources       # replace all
PUT  /config/sources/{id}  # update one
DELETE /config/sources/{id}
```

Manage rules:

```
GET  /config/rules
POST /config/rules        # replace all
PUT  /config/rules/{id}
DELETE /config/rules/{id}
POST /config/rules/test   # body: {"event": {...}}
```

Forwarding config:

```
GET  /config/forwarding
POST /config/forwarding   # body: ForwardingConfig JSON
POST /forwarding/test     # triggers a simple DMZ POST
```

Storage repair:

```
POST /storage/repair
```

Test injection endpoint (accepts raw syslog or JSON event):

```
POST /test-event
Body: {"raw": "<14>...", "source_ip": "192.168.1.20"}
or JSON event object
```

Web UI (single-page app): visit `/` after starting the server.

## Tests

There are unit tests in several packages (parser, normalizer, filter engine, storage). Run them with:

```bash
go test ./...
```

## Development Notes

- Entry point: [cmd/ot-collector/main.go](cmd/ot-collector/main.go)
- HTTP API server implemented in [internal/api/server.go](internal/api/server.go) and handlers in [internal/api/handlers.go](internal/api/handlers.go).
- Syslog parsing and servers: [internal/syslog/parser.go](internal/syslog/parser.go), [internal/syslog/udp.go](internal/syslog/udp.go), [internal/syslog/tcp.go](internal/syslog/tcp.go).
- Normalization and enrichment: [internal/normalizer/normalizer.go](internal/normalizer/normalizer.go).
- Storage: [internal/storage/jsonl.go](internal/storage/jsonl.go).
- Filtering rules: [internal/filter/engine.go](internal/filter/engine.go).
- Forwarding client: [internal/forwarder/forwarder.go](internal/forwarder/forwarder.go).

Patterns and behaviour to note:

- The filter engine applies rules in first-match order; rules may `drop`, `keep`, `sample`, `forward_only`, or `store_only`.
- Runtime deduplication (default 5s) and per-source rate limiting (default 800 eps) are enforced in `filter.Engine`.
- The Web UI calls the same API endpoints and connects to `/events/stream` for live updates.

## Troubleshooting

- Ports: binding to low numbered ports (UDP 514) may require elevated privileges. When running in Docker the container can listen on 514 without host privileges but mapping host ports may require root.
- File permissions: the process needs write access to the configured `EVENTS_FILE` directory (default `/data/`).
- If the UI shows offline, check `API_ADDR` and that the HTTP server is listening and accessible.
- If forwarding tests fail, verify connectivity from the collector container/machine to the configured DMZ URL.

## Contributing

- Fork and open a pull request. Keep changes focused and include tests where applicable.
- Run `go test ./...` before submitting.
- Update this README when adding visible behaviour (API, config, CLI).

## Notes & Open Items

- The `deploy/` folder contains compose snippets and an OVS attach script example used in lab setups. The exact network attachment steps for LabShock/OVS are environment-specific — marked as "Needs verification" for your deployment.

## Summary of changes made to docs

- Rewrote and expanded this repository `README.md` to match code: described components, configuration, API endpoints, storage files and run/build instructions; added troubleshooting, dev notes and testing guidance. Marked external-deployment network steps as "Needs verification".

