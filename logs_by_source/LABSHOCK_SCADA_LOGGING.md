# LabShock Logging & SIEM Source Reference — FUXA SCADA

## Overview

The FUXA SCADA service (`192.168.1.60`) produces two structured JSON syslog streams forwarded directly from inside the container to the OT Collector (`192.168.1.70:514/udp`). Neither stream depends on host-side `docker logs`.

```
FUXA Container (192.168.1.60)
├── FUXA Runtime
│   └── writes → /usr/src/app/FUXA/server/_logs/fuxa.log
│
├── scada_log_forwarder.py  (background thread)
│   └── tails fuxa.log
│   └── normalises → JSON events
│   └── UDP/TCP → OT Collector :514
│
└── fuxa-gds-client.sh  (optional, lifecycle-loop)
    └── emit_ot_event() → UDP → OT Collector :514
                                     │
                              OT Collector (192.168.1.70)
                                     │
                              DMZ Collector
                                     │
                              Splunk (index: ot_security)
```

---

## Data Sources

### 1. SCADA Runtime Logs

| Field | Value |
|---|---|
| `source_type` | `scada` |
| `sourcetype` (Splunk) | `labshock:ot:scada` |
| `asset_name` | `FUXA SCADA` |
| `asset_ip` | `192.168.1.60` |
| `zone` | `OT` |
| `protocol` | `scada_runtime` |
| Transport | UDP syslog → `192.168.1.70:514` |
| Splunk index | `ot_security` |

**Collection mechanism:** `scada_log_forwarder.py` tails the FUXA internal log file at `/usr/src/app/FUXA/server/_logs/fuxa.log` from inside the container, normalises each line against a regex ruleset, and emits RFC-5424-framed JSON to the OT Collector.

**Deduplication:** Noisy event types (`scada_api_heartbeat`, `scada_plc_read_memory_error`, `scada_polling_overload`, `scada_socket_client_connected`, `scada_api_request`) are suppressed within a rolling window (default 30 s, configurable via `SCADA_DEDUP_WINDOW`).

---

### 2. FUXA GDS Client Telemetry

| Field | Value |
|---|---|
| `source_type` | `scada_gds_client` |
| `sourcetype` (Splunk) | `labshock:ot:scada:gds` |
| `asset_name` | `FUXA SCADA GDS Client` |
| `asset_ip` | `192.168.1.60` |
| `zone` | `OT` |
| `protocol` | `gds_https_mtls` |
| Transport | UDP syslog → `192.168.1.70:514` |
| Splunk index | `ot_security` |

**Collection mechanism:** `emit_ot_event()` inside `fuxa-gds-client.sh` sends a JSON event directly to the OT Collector at each PKI lifecycle decision point. Telemetry failures are fully non-fatal — the GDS lifecycle continues regardless.

**Security constraints enforced:**
- Private key content is never included in any emitted event.
- Token values are never logged.
- Certificate PEM bodies are never emitted; only fingerprints (SHA-256 of DER).
- A guard pattern in `emit_ot_event()` blocks emission if `details` contains `PRIVATE KEY`, `CERTIFICATE`, or PEM markers.

---

## Event Categories

| Category | Description |
|---|---|
| `data_collection` | PLC/Modbus and OPC UA connectivity |
| `pki_validation` | OPC UA certificate and CRL issues |
| `pki_lifecycle` | GDS trust pull, renewal, apply operations |
| `system_health` | Component start/stop, forwarder heartbeat |
| `access_control` | User create/read, API authentication |
| `operator_action` | Settings/project changes |
| `project_activity` | Project load, restart, script errors |
| `scada_activity` | Socket connections, API requests |
| `error` | Script errors, general failures |

---

## Severity Mapping

| Severity | Risk Level | `collector_decision_hint` |
|---|---|---|
| `info` | LOW | `sample_or_drop` |
| `warning` | MEDIUM | `store_forward` |
| `high` | HIGH | `store_forward` |
| `error` | HIGH | `store_forward` |
| `critical` | CRITICAL | `store_forward` |

---

## Key Event Types

### SCADA Connectivity

| Event | Trigger |
|---|---|
| `scada_plc_connection_refused` | `ECONNREFUSED` on Modbus TCP |
| `scada_plc_connection_error` | Generic PLC connect error |
| `scada_plc_read_memory_error` | `_readMemory error!` |
| `scada_polling_overload` | Connection/polling overload warning |
| `scada_opcua_connection_lost` | OPC UA session dropped |
| `scada_opcua_session_closed` | OPC UA session warning closed |
| `scada_opcua_connection_break` | `connection_break opc.tcp://...` |
| `scada_opcua_session_keepalive_failure` | Keepalive timeout |
| `scada_connection_timeout` | `ping_server transaction timeout` |

### SCADA PKI

| Event | Trigger |
|---|---|
| `scada_opcua_certificate_san_mismatch` | `NODE-OPCUA-W06` |
| `scada_opcua_certificate_keyusage_warning` | `NODE-OPCUA-W16` |
| `scada_opcua_secure_channel_error` | Secure channel failure |

### SCADA Runtime

| Event | Trigger |
|---|---|
| `scada_runtime_restart` | `runtime.update-project: restart` |
| `scada_runtime_component_started/stopped/created` | Component lifecycle |
| `scada_project_loaded` | Project data loaded |
| `scada_settings_updated` | Server settings changed |
| `scada_script_load_error` | Script syntax/load failure |
| `scada_user_created` | New user provisioned via API |

### GDS Client PKI Lifecycle

| Event | Trigger |
|---|---|
| `fuxa_gds_lifecycle_check_started/completed` | Each lifecycle iteration |
| `fuxa_gds_pull_trust_started/completed/failed` | Trust material fetch |
| `fuxa_gds_trust_material_cached` | Trust written to cache |
| `fuxa_gds_renewal_threshold_reached` | Cert near expiry |
| `fuxa_gds_renewal_apply_completed` | Cert renewed successfully |
| `fuxa_gds_apply_trust_blocked` | Runtime write gate closed |
| `fuxa_gds_private_key_in_artifact` | **CRITICAL** — key in bundle |
| `fuxa_gds_private_key_changed` | **CRITICAL** — key hash changed |

---

## Environment Variables

### SCADA Log Forwarder

| Variable | Default | Description |
|---|---|---|
| `SCADA_ASSET_IP` | `192.168.1.60` | Source IP in events |
| `SCADA_OT_COLLECTOR_HOST` | `192.168.1.70` | OT Collector hostname |
| `SCADA_OT_COLLECTOR_PORT` | `514` | Syslog port |
| `SCADA_OT_COLLECTOR_PROTO` | `udp` | `udp` or `tcp` |
| `SCADA_LOG_PATHS` | `/usr/src/app/FUXA/server/_logs/fuxa.log` | Colon-separated log files to tail |
| `SCADA_FORWARDER_ENABLED` | `true` | Enable/disable forwarder |
| `SCADA_HEARTBEAT_INTERVAL` | `300` | Seconds between heartbeat events |
| `SCADA_DEDUP_WINDOW` | `30` | Seconds for noisy-event suppression |

### GDS Client Telemetry

| Variable | Default | Description |
|---|---|---|
| `FUXA_GDS_OT_TELEMETRY_ENABLED` | `true` | Enable OT telemetry emission |
| `FUXA_GDS_OT_COLLECTOR_HOST` | `192.168.1.70` | OT Collector hostname |
| `FUXA_GDS_OT_COLLECTOR_PORT` | `514` | Syslog port |
| `FUXA_GDS_OT_COLLECTOR_PROTO` | `udp` | `udp` or `tcp` |
| `FUXA_ASSET_IP` | `192.168.1.60` | Source IP in events |
| `FUXA_GDS_COMPONENT` | `fuxa_gds_client` | Component tag |

---

## Deployment Files

| File | Purpose |
|---|---|
| `Dockerfile` | Extends base FUXA image with forwarder + GDS client |
| `entrypoint.sh` | Starts FUXA, forwarder, and GDS loop |
| `scada_log_forwarder.py` | In-container SCADA log tailing + normalisation |
| `fuxa-gds-client.sh` | PKI lifecycle with `emit_ot_event()` telemetry |
| `docker-compose.yml` | Full environment block |
| `splunk_parsing_config.conf` | `props.conf` + `transforms.conf` |
| `splunk_validation.spl` | 20 validation SPL queries |
| `validation_commands.sh` | Build, test, and tcpdump commands |

---

## Architecture Notes

- **No `docker logs` dependency in production.** The forwarder tails files directly inside the container. Docker log commands are acceptable only for manual debugging.
- **Forwarder resilience.** If the OT Collector is unreachable, the forwarder logs locally to `/var/log/scada_forwarder.log` and retries. FUXA runtime is not affected.
- **GDS telemetry resilience.** `emit_ot_event()` wraps all network I/O in non-fatal error handling. A collector outage never interrupts the PKI lifecycle.
- **Log rotation.** The forwarder detects inode changes (log rotation) and re-opens the file automatically.
- **Secret safety.** No token, private key, or certificate PEM body is ever included in a forwarded event. The GDS helper enforces this with a PEM-content guard in `emit_ot_event()`.
