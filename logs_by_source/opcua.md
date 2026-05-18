# LabShock Logging & SIEM Source Reference — Initialisation OPC UA Server

Analyse effectuée sur les fichiers fournis :

* `Pasted text (2).txt` : code principal du serveur OPC UA PowerGrid.
* `Pasted code (3).c` : collecteurs Modbus / synchronisation PLC → OPC UA.
* `Pasted code (4).c` : module `ot_telemetry.c`.
* `Pasted code.c` : client/lifecycle GDS natif.

Le point clé : le serveur produit **deux familles de logs** :

1. **Logs locaux open62541/stdout** via `LOG_INFO`, `LOG_WARN`, `LOG_ERROR`, `fprintf`.
2. **Événements SIEM structurés** via `ot_telemetry_send_event()`, envoyés en JSON syslog vers l’OT Collector. Le module ajoute notamment `source_type=opcua`, `component=powergrid_opcua_server`, `zone=OT`, `event_category`, `severity`, `event_type`, `reason`, `opcua_operation` et des champs dynamiques. 

---

## 1. Current validated pipeline

### Architecture

```text
OPC UA Server / OT sources
        ↓ syslog / JSON events
OT Collector
        ↓
DMZ Collector
        ↓ Splunk HEC
Splunk index: ot_security
```

### Indexes

| Index         | Usage                                                     |
| ------------- | --------------------------------------------------------- |
| `ot_security` | Central Splunk index for OT security and operational logs |

### Validated sourcetypes

| Source               | Sourcetype              | Current status |
| -------------------- | ----------------------- | -------------- |
| OPNsense OT Firewall | `labshock:net:firewall` | observed       |
| OT GDS Agent         | `labshock:ot:gds`       | observed       |
| OPC UA Server        | `labshock:ot:opcua`     | observed       |
| OpenPLC / PLCs       | `labshock:ot:plc`       | observed       |

### Current OPC UA evidence

For OPC UA Server, two messages were already known from Splunk: `modbus_connection_failed` and `modbus_connection_recovered`. The uploaded code confirms both are implemented in `ot_telemetry.c`, with fields such as `plc_name`, `plc_ip`, `modbus_port`, and `error_code`. 

---

## 2. OT source inventory

| Source               |                 IP | Zone        | Sourcetype              | Index                  | Status                    | Event volume                              | Security value                                                              |
| -------------------- | -----------------: | ----------- | ----------------------- | ---------------------- | ------------------------- | ----------------------------------------- | --------------------------------------------------------------------------- |
| OPC UA Server        |     `192.168.1.62` | OT          | `labshock:ot:opcua`     | `ot_security`          | observed + implemented    | currently partial; Modbus events observed | High: sessions, commands, PKI, GDS lifecycle, Modbus health, access control |
| PLC1–PLC5 / OpenPLC  |  `192.168.1.20–24` | OT          | `labshock:ot:plc`       | `ot_security`          | observed from Splunk only | observed, not yet fully catalogued        | Medium/High: login, start/stop, operator actions                            |
| OPNsense OT Firewall | firewall interface | OT boundary | `labshock:net:firewall` | `ot_security`          | observed from Splunk only | observed, pass traffic                    | High once restrictive rules generate blocks                                 |
| OT GDS Agent         |            OT side | OT          | `labshock:ot:gds`       | `ot_security`          | observed from Splunk only | observed                                  | High: certificate trust, expiration, drift                                  |
| FUXA SCADA           |     `192.168.1.60` | OT          | not yet confirmed       | `ot_security` expected | configured only           | not confirmed                             | High if sessions/writes/errors are collected                                |
| EWS                  |     `192.168.1.50` | OT          | not yet confirmed       | `ot_security` expected | configured only           | not confirmed                             | High if project/config/programming actions are collected                    |

---

## 3. Per-source log catalog

## OPC UA Server

* **Role:** Secure OPC UA exposure layer for PowerGrid, Factory, RailAuto, RailManual, PLC1, PLC2, and MES telemetry nodes.
* **IP / zone:** `192.168.1.62`, OT.
* **Sourcetype:** `labshock:ot:opcua`.
* **Index:** `ot_security`.
* **Status:** observed + implemented.
* **Application URI:** `urn:dataprotect:opcua:ot-server`.
* **Component:** `powergrid_opcua_server`.
* **Syslog hostname:** `powergrid-opcua`.
* **Default OT Collector target:** `192.168.1.70`, UDP `514`, TCP `1514`. 

### Known event categories

Implemented categories in the telemetry layer include:

| Category                    | Meaning                                                                | Forwarding behavior                 |
| --------------------------- | ---------------------------------------------------------------------- | ----------------------------------- |
| `system_health`             | startup, readiness, recovery, GDS discovery success                    | high-value                          |
| `data_collection`           | Modbus/PLC collection failures                                         | high-value                          |
| `security`                  | PKI verification failure, artifact problems, trust anchor mismatch     | high-value                          |
| `pki_lifecycle`             | trust material loading, certificate verification, GDS trust pull/apply | high-value                          |
| `certificate_lifecycle`     | renewal, certificate application, certificate failure                  | high-value                          |
| `access_control`            | unauthorized write, anonymous/unexpected session                       | high-value                          |
| `session`                   | session activation/rejection/abnormal close                            | high-value                          |
| `sensitive_operator_action` | sensitive accepted OPC UA writes                                       | high-value                          |
| `error`                     | general server/GDS/Modbus/write/read errors                            | high-value                          |
| `debug_operation`           | reads and normal writes in debug/sampled modes                         | usually filtered unless mode allows |

The telemetry module filters events by mode. In default/security-oriented modes, `debug_operation` is excluded, while security, PKI, session, access control, system health, data collection, and error categories remain forwardable. 

---

# OPC UA Server — SIEM structured event catalog

## A. System health events

| Event type                     | Severity | Category        | Operation  | Status                           | Fields                                    |
| ------------------------------ | -------- | --------------- | ---------- | -------------------------------- | ----------------------------------------- |
| `server_startup`               | `info`   | `system_health` | `SECURITY` | implemented but not yet observed | none                                      |
| `server_ready`                 | `info`   | `system_health` | `SECURITY` | implemented but not yet observed | none                                      |
| `modbus_connection_recovered`  | `info`   | `system_health` | `MODBUS`   | observed + implemented           | `plc_name`, `plc_ip`, `modbus_port`       |
| `gds_discover_ok`              | `info`   | `system_health` | `GDS`      | implemented but not yet observed | `application_uri`, `target`, `error_code` |
| `gds_lifecycle_once_completed` | `info`   | `system_health` | `GDS`      | implemented but not yet observed | `application_uri`, `target`, `error_code` |

Evidence: `server_startup` and `server_ready` are emitted from the main server lifecycle through `ot_telemetry_send_event()`.  `modbus_connection_recovered` is implemented in the telemetry module and is only sent after a previous Modbus failure state was recorded. 

### Security meaning

* `server_startup` / `server_ready`: proves OPC UA service lifecycle visibility.
* `modbus_connection_recovered`: useful to close an incident window after PLC connectivity failure.
* GDS lifecycle success: proves PKI management plane is reachable and functioning.

### Operational meaning

* Confirms service uptime.
* Confirms successful Modbus reconnection.
* Confirms GDS lifecycle action completion.

### Dashboard value

Partial readiness. Useful for an “OPC UA / Modbus Health” panel and “Source Coverage / Collector Health”.

### Alert value

Low for startup/ready alone. Medium for frequent restarts. Informational for recovery.

---

## B. Data collection / Modbus events

| Event type                    | Severity | Category          | Operation | Status                           | Fields                                                       |
| ----------------------------- | -------- | ----------------- | --------- | -------------------------------- | ------------------------------------------------------------ |
| `modbus_connection_failed`    | `error`  | `data_collection` | `MODBUS`  | observed + implemented           | `plc_name`, `plc_ip`, `modbus_port`, `error_code`            |
| `modbus_connection_recovered` | `info`   | `system_health`   | `MODBUS`  | observed + implemented           | `plc_name`, `plc_ip`, `modbus_port`                          |
| `modbus_write_failed`         | `error`  | `error`           | `WRITE`   | implemented but not yet observed | `plc_name`, `plc_ip`, `modbus_port`, `node_id`, `error_code` |

The Modbus collector calls `ot_telemetry_modbus_connection_failed()` when `modbus_read_registers`, `modbus_new_tcp`, or `modbus_connect` fails, and calls `ot_telemetry_modbus_connection_recovered()` after a successful connection.  Modbus command write failure is emitted when `modbus_write_bit()` fails. 

### Known error codes from code

| Error code                     | Trigger                                         |
| ------------------------------ | ----------------------------------------------- |
| `modbus_read_registers_failed` | Holding register read returned unexpected count |
| `modbus_new_tcp_failed`        | Modbus TCP context creation failed              |
| `modbus_connect_failed`        | TCP connection to PLC failed                    |
| `modbus_write_bit_failed`      | Modbus coil write failed                        |

### Security meaning

* Repeated Modbus failures may indicate PLC outage, segmentation/routing issue, firewall block, PLC crash, or active disruption.
* Modbus write failure after an OPC UA command may indicate control path degradation.

### Operational meaning

* Direct health signal for PLC connectivity.
* Shows which PLC endpoint is failing: `PLC1`, `PLC2`, `Factory`, `Rail_Auto`, `Rail_Manual`.

### Dashboard value

Ready for:

* Modbus failures by PLC.
* Recovery timeline.
* Failed vs recovered ratio.
* Current unhealthy PLCs.

### Alert value

Ready for:

* `modbus_connection_failed`.
* `modbus_write_failed`.
* Repeated failure without recovery.

---

## C. Session events

| Event type                     | Severity | Category         | Operation | Status                           | Fields            |
| ------------------------------ | -------- | ---------------- | --------- | -------------------------------- | ----------------- |
| `session_rejected`             | `error`  | `session`        | `SESSION` | implemented but not yet observed | none              |
| `session_activated`            | `info`   | `session`        | `SESSION` | implemented but not yet observed | `user`, `node_id` |
| `unexpected_anonymous_session` | `warn`   | `access_control` | `SESSION` | implemented but not yet observed | `user`            |
| `abnormal_session_close`       | `warn`   | `session`        | `SESSION` | implemented but not yet observed | `user`            |

The server creates a session context from `UsernameIdentityToken`, maps the username to roles, emits `session_activated` for authenticated sessions, and emits `unexpected_anonymous_session` when the token is missing or invalid.  It emits `abnormal_session_close` when the session closes with no context or no role. 

### Role mapping from code

| Username        | Roles                         |
| --------------- | ----------------------------- |
| `admin`         | `ADMIN`, `SCADA`, `HISTORIAN` |
| `scada`         | `SCADA`                       |
| `historian`     | `HISTORIAN`                   |
| unknown / other | `ROLE_NONE`                   |

### Security meaning

* `unexpected_anonymous_session`: important because this server expects controlled identities.
* `abnormal_session_close`: may indicate failed/abnormal clients, broken sessions, or unauthorized clients.
* `session_activated`: gives user attribution for OPC UA activity.

### Operational meaning

* Helps understand legitimate client activity, for example SCADA, historian, or admin session patterns.

### Dashboard value

Partial readiness. Needs Splunk observation to confirm field extraction.

### Alert value

Ready in concept:

* anonymous session.
* roleless session close.
* unusual session volume.
* session from unexpected client, if client IP becomes available.

---

## D. OPC UA read events

| Event type          | Severity | Category          | Operation | Status                                        | Fields                                                               |
| ------------------- | -------- | ----------------- | --------- | --------------------------------------------- | -------------------------------------------------------------------- |
| `opcua_read_failed` | `error`  | `error`           | `READ`    | implemented but not yet observed              | none                                                                 |
| `opcua_read`        | `info`   | `debug_operation` | `READ`    | implemented but not yet observed; conditional | `user`, `node_id`, `browse_name`, `display_name`, `sensitive_action` |

`opcua_read_failed` is emitted when the command node context is missing. `opcua_read` is emitted only if read forwarding is enabled by telemetry mode; it may be filtered in normal security-only mode. 

### Security meaning

Low unless reads target sensitive nodes or come from unexpected users.

### Operational meaning

Useful for debugging SCADA/historian polling behavior.

### Dashboard value

Blocked/partial: only useful if read forwarding is intentionally enabled.

### Alert value

Not recommended by default. High-volume reads could be noisy.

---

## E. OPC UA write / command events

| Event type                 | Severity          | Category                    | Operation | Status                                        | Fields                                                                             |
| -------------------------- | ----------------- | --------------------------- | --------- | --------------------------------------------- | ---------------------------------------------------------------------------------- |
| `opcua_write_rejected`     | `error` or `warn` | `error` or `access_control` | `WRITE`   | implemented but not yet observed              | `user`, `node_id`, `browse_name`, `display_name`, `sensitive_action`, `error_code` |
| `unauthorized_write`       | `warn`            | `access_control`            | `WRITE`   | implemented but not yet observed              | same as above                                                                      |
| `sensitive_write_accepted` | `info`            | `sensitive_operator_action` | `WRITE`   | implemented but not yet observed              | same as above                                                                      |
| `opcua_write_accepted`     | `info`            | `debug_operation`           | `WRITE`   | implemented but not yet observed; conditional | same as above                                                                      |

The write callback validates node context, data presence, Boolean type, numeric NodeId, user authorization, and then performs either maintained or pulse command logic. Unauthorized writes emit `unauthorized_write` with `BadUserAccessDenied`. Invalid/malformed writes emit `opcua_write_rejected` with specific error codes. 

### Known write rejection reasons / error codes

| Reason                                 | Error code              |
| -------------------------------------- | ----------------------- |
| `missing_node_context`                 | internal error          |
| `bad_no_data_available`                | `BadNoDataAvailable`    |
| `bad_type_mismatch`                    | `BadTypeMismatch`       |
| `bad_node_id_invalid`                  | `BadNodeIdInvalid`      |
| `user_role_not_authorized_for_command` | `BadUserAccessDenied`   |
| `modbus_write_failed`                  | `BadCommunicationError` |
| `modbus_initial_pulse_write_failed`    | `BadCommunicationError` |
| `modbus_second_pulse_write_failed`     | `BadCommunicationError` |

### Sensitive action detection

The telemetry layer marks a write as sensitive if `browse_name` or `display_name` contains keywords such as `Reset`, `Emergency`, `Stop`, `Start`, `Manual`, `Auto`, `Switch`, `Vanne`, `Valve`, `DCY`, `AlarmAck`, `Safety`, `Bypass`, or `Override`. 

### Security meaning

Very high. These are the most important OPC UA security events because they represent command attempts, denied writes, or accepted sensitive control actions.

### Operational meaning

Shows who changed what, on which OPC UA node, and whether the command was maintained or pulse.

### Dashboard value

Partial readiness. Requires observed Splunk events and parser validation for fields:
`user`, `node_id`, `browse_name`, `display_name`, `sensitive_action`, `error_code`.

### Alert value

High:

* `unauthorized_write`.
* `sensitive_write_accepted` outside expected maintenance window.
* repeated `opcua_write_rejected`.
* `modbus_write_failed` after command.

---

## F. PKI / certificate verification events

| Event type                   | Severity   | Category        | Operation | Status                                                 | Fields                                                                                    |
| ---------------------------- | ---------- | --------------- | --------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| `certificate_verified`       | `info`     | `pki_lifecycle` | `PKI`     | implemented but not yet observed; sampled/rate-limited | `client_certificate_fingerprint_sha256`, `client_application_uri`, `status`               |
| dynamic `statusNameSafe(rc)` | `error`    | `security`      | `PKI`     | implemented but not yet observed                       | `client_certificate_fingerprint_sha256`, `client_application_uri`, `status`, `error_code` |
| `pki_load_failed`            | `critical` | `pki_lifecycle` | `PKI`     | implemented but not yet observed                       | none                                                                                      |

The diagnostic certificate verifier logs certificate details, forwards successful certificate verification only when rate-limited conditions allow, and sends a security event on certificate verification failure.  PKI load failure is emitted for explicit trust material loading failure or empty trust list. 

### Security meaning

Very high:

* certificate failure may indicate untrusted client, wrong trust list, expired/missing certificate, or misconfigured PKI.
* empty trust list is critical because it would weaken validation.

### Operational meaning

Useful during GDS/Vault/PKI rollout and certificate rotation tests.

### Dashboard value

Ready once observed:

* certificate verification failures.
* trusted/issuer/CRL inventory.
* PKI load errors.

### Alert value

High:

* any certificate verification failure.
* `pki_load_failed`.
* repeated unknown client certificate.

---

## G. Native GDS lifecycle events

| Event type                            | Severity | Category                | Operation | Status                           |
| ------------------------------------- | -------- | ----------------------- | --------- | -------------------------------- |
| `gds_discover_ok`                     | `info`   | `system_health`         | `GDS`     | implemented but not yet observed |
| `gds_discover_failed`                 | `error`  | `error`                 | `GDS`     | implemented but not yet observed |
| `gds_pull_trust_completed`            | `info`   | `pki_lifecycle`         | `GDS`     | implemented but not yet observed |
| `private_key_included_true`           | `error`  | `security`              | `GDS`     | implemented but not yet observed |
| `signed_artifact_verification_failed` | `error`  | `security`              | `GDS`     | implemented but not yet observed |
| `trust_anchor_mismatch`               | `error`  | `security`              | `GDS`     | implemented but not yet observed |
| `crl_freshness_failed`                | `error`  | `pki_lifecycle`         | `GDS`     | implemented but not yet observed |
| `gds_apply_trust_completed`           | `info`   | `pki_lifecycle`         | `GDS`     | implemented but not yet observed |
| `gds_apply_certificate_completed`     | `info`   | `certificate_lifecycle` | `GDS`     | implemented but not yet observed |
| `gds_apply_trust_failed`              | `error`  | `pki_lifecycle`         | `GDS`     | implemented but not yet observed |
| `gds_apply_certificate_failed`        | `error`  | `certificate_lifecycle` | `GDS`     | implemented but not yet observed |
| `renewal_required`                    | `warn`   | `certificate_lifecycle` | `GDS`     | implemented but not yet observed |
| `renewal_apply_completed`             | `info`   | `certificate_lifecycle` | `GDS`     | implemented but not yet observed |
| `renewal_failed`                      | `error`  | `certificate_lifecycle` | `GDS`     | implemented but not yet observed |
| `gds_renew_failed`                    | `error`  | `certificate_lifecycle` | `GDS`     | implemented but not yet observed |
| `gds_lifecycle_loop_error`            | `error`  | `error`                 | `GDS`     | implemented but not yet observed |
| `gds_lifecycle_once_completed`        | `info`   | `system_health`         | `GDS`     | implemented but not yet observed |

The GDS client wraps lifecycle telemetry through `gds_emit()`, which adds `application_uri`, `target`, and `error_code`, then sends the event with OPC UA operation `GDS`.  The code includes specific GDS security events for private key inclusion, signed artifact verification failure, trust anchor mismatch, and CRL freshness failure. 

### Security meaning

Very high:

* `private_key_included_true`: serious violation, because private keys should not be distributed by GDS artifacts.
* `signed_artifact_verification_failed`: integrity failure.
* `trust_anchor_mismatch`: possible trust anchor drift or tampering.
* `crl_freshness_failed`: revocation validation weakness.
* renewal/apply failures: certificate lifecycle risk.

### Operational meaning

Tracks trust pull, trust apply, certificate apply, and renewal lifecycle.

### Dashboard value

High, but current readiness is partial because Splunk observation is not yet confirmed for these GDS lifecycle events from the OPC UA server itself.

### Alert value

High:

* `private_key_included_true`
* `signed_artifact_verification_failed`
* `trust_anchor_mismatch`
* `crl_freshness_failed`
* `gds_apply_certificate_failed`
* `renewal_failed`
* `gds_renew_failed`

---

## H. Local stdout/open62541 logs — not necessarily structured SIEM events

The code also emits many local logs through `LOG_INFO`, `LOG_WARN`, `LOG_ERROR`, `LOG_FATAL`, and `fprintf`. These are useful if container stdout is collected, but they are not automatically equivalent to structured SIEM events unless the collector captures and parses them.

Examples:

| Local log family       | Example pattern                                | Security/SIEM value        |
| ---------------------- | ---------------------------------------------- | -------------------------- |
| `[BOOT]`               | server startup, PKI init, AccessControl config | useful for lifecycle       |
| `[PKI][PATH]`          | PKI paths                                      | useful for troubleshooting |
| `[PKI][EXPLICIT]`      | trust/issuer/CRL loading                       | useful for PKI inventory   |
| `[PKI][VERIFY]`        | certificate verify diagnostics                 | high security value        |
| `[SESSION][ACTIVATE]`  | user and roles                                 | high security value        |
| `[SESSION][CLOSE]`     | user and roles                                 | medium/high                |
| `[READ][CMD]`          | read of command node                           | noisy unless sampled       |
| `[WRITE][CMD]`         | command write start/request/accept/deny        | very high                  |
| `[AUDIT][ACCEPT/DENY]` | write audit                                    | very high                  |
| `[MODBUS][WRITE]`      | write-through to PLC coil                      | high                       |
| `[BUILD][...]`         | node model construction                        | mostly boot/debug          |
| `[SYNC][CMD]`          | command state sync from Modbus                 | operational/debug          |

---

## 4. Field dictionary — current OPC UA additions

| Field                                   | Source(s)              | Meaning                 | Example                                            | Dashboard use              | Alert use                 |
| --------------------------------------- | ---------------------- | ----------------------- | -------------------------------------------------- | -------------------------- | ------------------------- |
| `source_type`                           | OPC UA telemetry       | Logical source type     | `opcua`                                            | source filtering           | source validation         |
| `component`                             | OPC UA telemetry       | Runtime component       | `powergrid_opcua_server`                           | component health           | missing component         |
| `zone`                                  | OPC UA telemetry       | Network/security zone   | `OT`                                               | zone filtering             | unexpected zone           |
| `event_category`                        | OPC UA telemetry       | Event family            | `access_control`                                   | panel grouping             | alert routing             |
| `severity`                              | OPC UA telemetry       | Event severity          | `info`, `warn`, `error`, `critical`                | severity charts            | thresholding              |
| `event_type`                            | OPC UA telemetry       | Normalized event name   | `unauthorized_write`                               | core dashboard dimension   | alert trigger             |
| `timestamp`                             | OPC UA telemetry       | Event timestamp         | ISO UTC                                            | timeline                   | correlation               |
| `collector_decision`                    | OPC UA telemetry       | Collector decision tag  | `forward`                                          | collector behavior         | drop/forward audit        |
| `reason`                                | OPC UA telemetry       | Human-readable reason   | `user_role_not_authorized_for_command`             | drilldown                  | false positive review     |
| `opcua_operation`                       | OPC UA telemetry       | Operation family        | `WRITE`, `READ`, `PKI`, `GDS`, `MODBUS`, `SESSION` | operation panels           | operation-specific alerts |
| `user`                                  | OPC UA sessions/writes | OPC UA username         | `admin`, `scada`, `historian`                      | user activity              | unexpected user           |
| `node_id`                               | OPC UA reads/writes    | OPC UA node identifier  | `ns=2;i=...`                                       | node activity              | sensitive node alert      |
| `browse_name`                           | OPC UA writes/reads    | OPC UA browse name      | `Switch`, `ResetFes`, `DCY`                        | command classification     | sensitive command         |
| `display_name`                          | OPC UA writes/reads    | Human display name      | `Vanne1`                                           | command context            | sensitive command         |
| `sensitive_action`                      | OPC UA writes          | Sensitive action flag   | `true`                                             | sensitive operations panel | alert trigger             |
| `error_code`                            | OPC UA/Modbus/GDS      | Error code/status       | `BadUserAccessDenied`                              | failure breakdown          | alert condition           |
| `plc_name`                              | Modbus telemetry       | PLC endpoint name       | `PLC1`, `Factory`, `Rail_Auto`                     | PLC health                 | repeated failures         |
| `plc_ip`                                | Modbus telemetry       | PLC IP address          | `192.168.1.20`                                     | endpoint panel             | endpoint-specific alert   |
| `modbus_port`                           | Modbus telemetry       | Modbus TCP port         | `502`                                              | protocol panel             | abnormal port             |
| `client_certificate_fingerprint_sha256` | PKI verify             | Client cert fingerprint | SHA-256 hex                                        | certificate inventory      | unknown cert alert        |
| `client_application_uri`                | PKI verify             | OPC UA client URI       | URI SAN                                            | client identity            | unauthorized app URI      |
| `application_uri`                       | GDS lifecycle          | GDS target app URI      | `urn:dataprotect:opcua:ot-server`                  | certificate lifecycle      | wrong target              |
| `target`                                | GDS lifecycle          | GDS target name         | `ot-server`                                        | target grouping            | failed target             |

---

## 5. Parser improvement backlog

| Issue                                                     | Affected source       | Current behavior                                                           | Desired normalization                                                 | Priority | Example                                         | Suggested implementation                     |
| --------------------------------------------------------- | --------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------- | -------- | ----------------------------------------------- | -------------------------------------------- |
| Distinguish structured telemetry vs stdout logs           | OPC UA Server         | Both may arrive as logs if stdout is collected                             | Mark structured JSON as canonical SIEM event; parse stdout separately | High     | `ot_telemetry_send_event` JSON vs `[BOOT]` logs | Use sourcetype or JSON detection             |
| Normalize `severity=warn` vs `warning`                    | OPC UA / GDS          | Code emits `warn`; other sources may emit `warning`                        | Normalize to `warning` or keep `warn` consistently                    | Medium   | `OT_TEL_WARN → warn`                            | Splunk eval normalization                    |
| Extract `event_type` from JSON                            | OPC UA                | Already present in telemetry JSON                                          | Ensure indexed/extracted field                                        | High     | `event_type=unauthorized_write`                 | props/transforms or `spath`                  |
| Extract `opcua_operation`                                 | OPC UA                | Already present                                                            | Ensure searchable as `tags.opcua_operation` or `opcua_operation`      | High     | `WRITE`, `MODBUS`, `GDS`                        | normalize field name                         |
| Normalize fields under `tags.*`                           | OPC UA / all OT       | Some existing Splunk fields may be under `tags.*`                          | Decide canonical: raw JSON fields or `tags.*`                         | High     | `tags.plc_ip` vs `plc_ip`                       | field aliasing                               |
| Parse local `[AUDIT][ACCEPT/DENY]` if stdout is collected | OPC UA                | Local audit lines are rich but unstructured                                | Extract phase, user, node, result                                     | Medium   | `[AUDIT][DENY] User=scada ...`                  | regex transform                              |
| Parse local `[WRITE][CMD]` if stdout is collected         | OPC UA                | High-value command logs may appear as text                                 | Extract user, node, requested value, mode                             | Medium   | `[WRITE][CMD][AUTHZ-DENY]`                      | regex transform                              |
| Confirm GDS event separation                              | OPC UA / OT GDS Agent | GDS lifecycle can come from OPC UA native client and separate OT GDS Agent | Keep source identity distinct                                         | High     | `source_type=opcua` vs `gds_agent`              | use `component`, `asset_name`, `source_type` |
| Dedup awareness                                           | OPC UA telemetry      | Telemetry suppresses duplicate events within configured window             | Dashboard may undercount repeated identical errors                    | Medium   | Modbus fail repeated                            | document dedup window in dashboard notes     |
| Sensitive action keyword reliance                         | OPC UA writes         | Sensitivity is keyword-based                                               | Review command inventory and add explicit criticality later           | Medium   | `Switch`, `Reset`, `Vanne`                      | enrich lookup table                          |

---

## 6. Dashboard blueprint — readiness only, no final dashboards yet

| Dashboard                          | Current readiness       | Reason                                                                                  |
| ---------------------------------- | ----------------------- | --------------------------------------------------------------------------------------- |
| OT Security Overview               | partial                 | sources exist, but full source catalogs not complete                                    |
| OPC UA / Modbus Health             | ready for first version | `modbus_connection_failed` and `modbus_connection_recovered` are observed + implemented |
| OPC UA Sessions                    | partial                 | events implemented, not yet observed in Splunk                                          |
| OPC UA Command / Write Activity    | partial                 | events implemented, not yet observed in Splunk                                          |
| PKI / GDS Certificate Health       | partial                 | events implemented; OT GDS Agent already observed separately                            |
| Source Coverage / Collector Health | partial                 | needs DMZ/collector heartbeat logs                                                      |
| SCADA / EWS Activity               | blocked                 | logs not yet provided/observed                                                          |

---

## 7. Alert blueprint — current OPC UA candidates

| Alert name                                 | SPL readiness | Severity    | Threshold                                         | Explanation                                  | False positive notes                              |
| ------------------------------------------ | ------------- | ----------- | ------------------------------------------------- | -------------------------------------------- | ------------------------------------------------- |
| OPC UA Modbus connection failed            | ready         | high        | `count > 0`, or repeated by PLC                   | PLC/Modbus connectivity broken               | can occur during lab reboot                       |
| OPC UA Modbus failure without recovery     | partial       | high        | failure exists, no recovery after N minutes       | persistent PLC outage                        | needs correlation window                          |
| OPC UA Modbus write failed                 | partial       | high        | `event_type=modbus_write_failed`                  | command could not reach PLC                  | may happen if PLC intentionally stopped           |
| OPC UA unauthorized write                  | partial       | critical    | `event_type=unauthorized_write`                   | user attempted command without required role | test clients may trigger during validation        |
| OPC UA sensitive write accepted            | partial       | medium/high | sensitive write outside maintenance window        | legitimate command but security-relevant     | needs maintenance window context                  |
| OPC UA anonymous session                   | partial       | high        | `event_type=unexpected_anonymous_session`         | session without valid username token         | may happen during client misconfiguration         |
| OPC UA certificate verification failed     | partial       | critical    | `event_category=security AND opcua_operation=PKI` | untrusted/invalid certificate                | expected during PKI tests                         |
| OPC UA PKI load failed                     | partial       | critical    | `event_type=pki_load_failed`                      | trust material invalid or empty              | likely startup-blocking                           |
| OPC UA GDS trust anchor mismatch           | partial       | critical    | `event_type=trust_anchor_mismatch`                | trust anchor mismatch/tampering risk         | verify configured pin                             |
| OPC UA signed artifact verification failed | partial       | critical    | `event_type=signed_artifact_verification_failed`  | GDS artifact integrity issue                 | may occur during dev if signature metadata absent |
| OPC UA renewal failed                      | partial       | high        | `event_type IN (renewal_failed,gds_renew_failed)` | certificate renewal failed                   | may be due to GDS service down                    |

---

## 8. DMZ onboarding template

| Source name        |                                             IP | Zone   | Protocol      | Expected index         | Expected sourcetype                   | Logs to collect                                      | Parser fields                   | Dashboard panels      | Alert rules                 | Validation SPL                                        |
| ------------------ | ---------------------------------------------: | ------ | ------------- | ---------------------- | ------------------------------------- | ---------------------------------------------------- | ------------------------------- | --------------------- | --------------------------- | ----------------------------------------------------- |
| DMZ Collector      |                                            TBD | DMZ    | syslog/HEC    | `ot_security`          | `labshock:dmz:collector` expected     | queue, forward success/failure, HEC errors           | source, status, error_code      | Source Coverage       | collector forwarding failed | `index=ot_security sourcetype=labshock:dmz:collector` |
| OPC UA DMZ Gateway |                                `192.168.10.20` | DMZ    | OPC UA/syslog | `ot_security`          | `labshock:dmz:opcua_gateway` expected | southbound/northbound sessions, cache, Influx writes | event_type, direction, endpoint | OPC UA Gateway Health | gateway disconnected        | TBD                                                   |
| InfluxDB           |                                `192.168.10.15` | DMZ    | HTTP/logs     | `ot_security` expected | `labshock:dmz:influxdb` expected      | write/query failures, auth errors                    | method, status, bucket          | Data Pipeline         | write failures              | TBD                                                   |
| Vault              |                                `192.168.10.10` | DMZ    | audit logs    | `ot_security` expected | `labshock:dmz:vault` expected         | PKI issue/renew/revoke, auth                         | path, operation, status         | PKI/Vault             | unauthorized Vault access   | TBD                                                   |
| GDS                |                                            TBD | DMZ    | API/logs      | `ot_security` expected | `labshock:dmz:gds` expected           | enrollment, renewal, trust packages                  | app_uri, package_id, status     | GDS Lifecycle         | enrollment failure          | TBD                                                   |
| Jump Host          |                                            TBD | DMZ    | auth/syslog   | `ot_security` expected | `labshock:dmz:jump` expected          | SSH/RDP/login/sudo                                   | user, src_ip, action            | Admin Access          | failed login burst          | TBD                                                   |
| Node-RED / MES API | `192.168.20.10` or DMZ/IT depending deployment | IT/DMZ | HTTP/logs     | `ot_security` expected | `labshock:mes:nodered` expected       | API errors, auth, flow failures                      | endpoint, status, method        | MES API Health        | API down/errors             | TBD                                                   |

---

# Added to the reference

* Initial master reference structure created.
* OPC UA Server added as the first deeply analyzed source.
* Confirmed structured telemetry JSON format and core fields.
* Confirmed `modbus_connection_failed` and `modbus_connection_recovered` are both **observed + implemented**.
* Extracted implemented-but-not-yet-observed events for:

  * system health
  * Modbus health
  * sessions
  * reads
  * writes / authorization
  * sensitive operator actions
  * PKI verification
  * native GDS lifecycle
* Added OPC UA fields to the field dictionary.
* Added parser backlog items specific to OPC UA telemetry and stdout logs.
* Added dashboard readiness status without building dashboards yet.
* Added first alert candidates based only on implemented/observed evidence.

# Still missing

* Splunk export for `labshock:ot:opcua` to confirm which implemented events are actually arriving.
* Raw examples of structured OPC UA events after parser extraction.
* Confirmation whether container stdout/open62541 logs are also collected into Splunk.
* Parser output showing whether fields are extracted as `event_type`, `plc_ip`, etc., or nested under `tags.*`.
* PLC logs/code analysis.
* FUXA SCADA logging output.
* EWS logging service/output.
* DMZ Collector and DMZ Gateway logs.

# Next source to provide

Send one of these next:

1. **Splunk export for `sourcetype=labshock:ot:opcua`** — best next step to compare implemented vs observed.
2. **PLC raw logs / Splunk export for `labshock:ot:plc`** — best if you want to complete OpenPLC classification.
3. **SCADA FUXA logs or logging code** — best if you want to validate configured vs observed.
4. **EWS logging service/code** — best if you want to define engineering workstation monitoring.
