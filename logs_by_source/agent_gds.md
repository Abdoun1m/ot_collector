# LabShock Logging & SIEM Source Reference — Ajout OT GDS Agent

J’ai intégré le **GDS Agent** comme deuxième source OT analysée. Ici, on distingue clairement :

1. **Le GDS Agent Python** — source `labshock:ot:gds`, `source_type=gds_agent`, `asset_name=OT GDS Agent`.
2. **Le client GDS natif intégré au serveur OPC UA** — déjà documenté sous `labshock:ot:opcua`, car il émet avec `source_type=opcua`.

Cette section concerne principalement le **GDS Agent Python** que tu viens d’envoyer.

---

## 2. OT source inventory — mise à jour

| Source       |                    IP | Zone | Sourcetype        | Index         | Status                 | Event volume                                                                                                                                              | Security value                                                                                                     |
| ------------ | --------------------: | ---- | ----------------- | ------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| OT GDS Agent | OT side / à confirmer | OT   | `labshock:ot:gds` | `ot_security` | observed + implemented | observed: `certificate_expiry_critical`, `certificate_inventory_drift_detected`, `gds_cert_missing_runtime`, `gds_telemetry_pulled`, `sync_cycle_success` | High: PKI trust sync, certificate lifecycle, drift detection, activation gates, revocation dry-run, runtime safety |

---

# 3. Per-source log catalog

## OT GDS Agent

* **Role:** OT-side GDS synchronization and PKI lifecycle agent. It pulls trust material, validates signed artifacts, checks certificate inventory drift, monitors expiration, manages dry-run activation gates, renewal workflows, revocation dry-runs, quarantine plans, and forwards selected security/health events to the OT Collector.
* **Zone:** OT.
* **Sourcetype:** `labshock:ot:gds`.
* **Index:** `ot_security`.
* **Source type:** `gds_agent`.
* **Asset name:** `OT GDS Agent`.
* **Status:** observed + implemented.
* **Evidence type:** code + previously observed Splunk messages.

The code normalizes events before forwarding them to the OT Collector. The normalized payload includes fields such as `zone`, `source_type`, `asset_name`, `asset_ip`, `severity`, `protocol`, `event_category`, `message`, `raw`, and `tags`. The default `source_type` is `gds-agent` in the normalization function, while forwarded tags set `source_type` to `gds_agent`, so parser normalization is needed. 

---

## Known event categories

| Category                      | Status                                                        | Meaning                                                                           |
| ----------------------------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `pki_trust_sync`              | observed + implemented                                        | Normal trust sync, cache write, successful sync cycle, package runtime activation |
| `pki_validation`              | observed + implemented                                        | Drift detection, certificate expiration, CA/CRL change, activation gate denial    |
| `gds_agent_error`             | implemented but not yet confirmed in Splunk                   | Sync failures, cache write failure, preview failure, critical diff                |
| `trustlist_diff`              | implemented but not yet confirmed in Splunk                   | Trustlist added/removed/changed certificates                                      |
| `pki_lifecycle`               | implemented but not yet confirmed in Splunk                   | Component CRL freshness, renewal/apply failures, private key policy violations    |
| `certificate_lifecycle`       | implemented in related renewal/package flows                  | Certificate package activation/renewal lifecycle                                  |
| `security`                    | implemented in policy decisions / artifact verification paths | Trust anchor mismatch, signed artifact validation, private key policy             |
| `policy_audit`                | policy-related, partially inferred from constants             | Maintenance/approval/blackout decisions                                           |
| `system_health` / `lifecycle` | implemented in policy constants                               | Agent lifecycle and health-style events                                           |

The telemetry forwarding policy treats `security`, `policy_audit`, `access_control`, `error`, `sensitive_operator_action`, `pki_lifecycle`, and `certificate_lifecycle` as security categories. It also treats `system_health`, `lifecycle`, and `pki_trust_sync` as health categories. 

---

## Known severity levels

| Severity   | Status                                   | Meaning                                                                                            |
| ---------- | ---------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `info`     | observed + implemented                   | Successful sync, telemetry pull, cache write success, package runtime activation                   |
| `warning`  | observed + implemented                   | Drift, CA/CRL change, gate denied, sync failure, renewal/apply issues                              |
| `critical` | observed + implemented                   | Critical certificate expiration, critical trustlist diff, private key policy violation             |
| `error`    | implemented in local logs and some paths | Activation/package/renewal failure paths; may be normalized differently depending collector/parser |

Important parser note: the Python GDS Agent emits severities as strings like `info`, `warning`, `critical`, while the native OPC UA telemetry module uses `warn` instead of `warning`. This requires severity normalization across sources.

---

# OT GDS Agent — SIEM structured event catalog

## A. Agent / telemetry forwarding policy events

| Message / event        | Severity  | Category          | Status                           | Fields / tags                                                                                            |
| ---------------------- | --------- | ----------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `sync_cycle_success`   | `info`    | `pki_trust_sync`  | observed + implemented           | `agent_id`, `elapsed_seconds`, `sync_cycle_id`, `control_plane_scheme`, `mtls_enabled`, `correlation_id` |
| `sync_cycle_failure`   | `warning` | `gds_agent_error` | implemented but not yet observed | `agent_id`, `failure_code`, `error`, `sync_cycle_id`                                                     |
| `preview_once_success` | `info`    | `pki_trust_sync`  | implemented but not yet observed | `agent_id`, `elapsed_seconds`, `sync_cycle_id`                                                           |
| `preview_once_failure` | `warning` | `gds_agent_error` | implemented but not yet observed | `agent_id`, `failure_code`, `error`, `sync_cycle_id`                                                     |

The code forwards `sync_cycle_success` at a minimum interval controlled by a success-event rate limit, and forwards `sync_cycle_failure` when the sync cycle throws an exception. 

### Security meaning

* `sync_cycle_success` confirms that the OT-side GDS trust synchronization loop is alive.
* `sync_cycle_failure` indicates a broken control-plane connection, invalid artifact, HTTP failure, parsing issue, or local runtime problem.

### Operational meaning

Useful for checking whether the GDS agent is healthy and whether the GDS control plane is reachable.

### Noise assessment

* `sync_cycle_success` can be noisy if emitted every cycle, but the code rate-limits it.
* `sync_cycle_failure` should stay high-value.

---

## B. PKI cache write events

| Message                            | Severity  | Category          | Status                           | Raw fields                        |
| ---------------------------------- | --------- | ----------------- | -------------------------------- | --------------------------------- |
| `cache_write_success ca-chain.pem` | `info`    | `pki_trust_sync`  | implemented but not yet observed | `path`                            |
| `cache_write_failure ca-chain.pem` | `warning` | `gds_agent_error` | implemented but not yet observed | `path`, `error`                   |
| `cache_write_success crl.der`      | `info`    | `pki_trust_sync`  | implemented but not yet observed | `path`                            |
| `cache_write_failure crl.der`      | `warning` | `gds_agent_error` | implemented but not yet observed | `path`, `error`                   |
| `cache_write_success trustlist`    | `info`    | `pki_trust_sync`  | implemented but not yet observed | `path`, `zone`, `role`, `version` |
| `cache_write_failure trustlist`    | `warning` | `gds_agent_error` | implemented but not yet observed | `path`, `zone`, `role`, `error`   |

The code writes CA chain, CRL, and trustlist artifacts locally and forwards success/failure events to the OT Collector.  

### Security meaning

* Cache write failures can break trust distribution to runtime components.
* Repeated CRL cache failure weakens revocation visibility.

### Operational meaning

Confirms whether the local GDS cache was updated correctly.

### Noise assessment

* Success events are operational, not security-critical.
* Failure events should alert if repeated.

---

## C. CA / CRL change events

| Message            | Severity  | Category         | Status                           | Fields / tags                              |
| ------------------ | --------- | ---------------- | -------------------------------- | ------------------------------------------ |
| `ca_chain_changed` | `warning` | `pki_validation` | implemented but not yet observed | `ca_chain_changed=true`, `risk_level=HIGH` |
| `crl_changed`      | `warning` | `pki_validation` | implemented but not yet observed | `crl_changed=true`, `risk_level=HIGH`      |

The code compares old cached CA chain and CRL with newly pulled material and forwards `ca_chain_changed` or `crl_changed` when differences are detected. 

### Security meaning

High. CA chain changes are sensitive because they affect trust anchors/intermediates. CRL changes are expected during revocation updates but still security-relevant.

### Operational meaning

Shows that PKI material was refreshed.

### Noise assessment

* `crl_changed` may be expected after certificate revocation or CRL rotation.
* `ca_chain_changed` should be rare and reviewed.

---

## D. Trustlist diff events

| Message                   | Severity                               | Category          | Status                           | Fields / tags                                                                                                                                                  |
| ------------------------- | -------------------------------------- | ----------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `trustlist_diff_detected` | dynamic: `info`, `warning`, `critical` | `trustlist_diff`  | implemented but not yet observed | `zone`, `role`, `previous_version`, `new_version`, `added_count`, `removed_count`, `changed_count`, `ca_chain_changed`, `crl_changed`, `risk_level`, `diff_id` |
| `critical_diff_detected`  | `critical`                             | `gds_agent_error` | implemented but not yet observed | `zone`, `role`, `critical_reasons`, `risk_level`, `diff_id`                                                                                                    |

The diff report classifies risk as `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. The severity is derived from this risk: `LOW → info`, `MEDIUM/HIGH → warning`, `CRITICAL → critical`. 

### Security meaning

Very high when:

* trust list becomes empty,
* CA chain is missing,
* certificates are removed,
* fingerprints change,
* application URI changes,
* expiry is reduced,
* parsing errors occur.

### Operational meaning

Shows exactly how trust material changed between sync cycles.

### Noise assessment

* `LOW` diffs may be mostly informational.
* `MEDIUM/HIGH/CRITICAL` diffs require review.
* `critical_diff_detected` should be an alert.

---

## E. Certificate inventory drift events

| Message                                | Severity                      | Category         | Status                           | Fields / tags                                                                                                                         |
| -------------------------------------- | ----------------------------- | ---------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `certificate_inventory_drift_detected` | `warning`                     | `pki_validation` | observed + implemented           | `sync_cycle_id`, `drift_count`, `items`, `risk_level=MEDIUM`                                                                          |
| `gds_cert_missing_runtime`             | `warning`                     | `pki_validation` | observed + implemented           | `target`, `zone`, `role`, `application_uri`, `common_name`, `fingerprint_sha256`, `artifact_revision`, `diff_id`, `risk_level=MEDIUM` |
| `runtime_cert_unknown`                 | `warning`                     | `pki_validation` | implemented but not yet observed | `target`, `zone`, `role`, `relative_path`, `fingerprint_sha256`, `subject`, `risk_level=MEDIUM`                                       |
| `gds_artifact_missing_cache`           | warning by parent drift event | `pki_validation` | implemented but not yet observed | `target`, `zone`, `role`                                                                                                              |

The code builds a drift report by comparing certificates in the GDS artifact cache with certificates found in runtime directories. If a GDS certificate is missing from runtime, it emits `gds_cert_missing_runtime`; if a runtime certificate is unknown to the GDS artifact, it emits `runtime_cert_unknown`.  The drift summary event `certificate_inventory_drift_detected` is sent when `drift_count > 0`. 

### Security meaning

High:

* `gds_cert_missing_runtime`: expected trust material is not installed in the runtime.
* `runtime_cert_unknown`: runtime contains a certificate not present in GDS-managed trust material.
* Persistent drift can mean incomplete sync, manual runtime changes, stale PKI state, or unauthorized trust modification.

### Operational meaning

Shows mismatch between intended GDS state and actual runtime state.

### Noise assessment

This is likely one of your repeated/noisy warnings. It is security-relevant, but may stay noisy while runtime mounts or trust application are incomplete. Classify as **medium risk until runtime enforcement is finalized**.

---

## F. Certificate expiration events

| Message                                                    | Severity                      | Category         | Status                                            | Expected fields                                              |
| ---------------------------------------------------------- | ----------------------------- | ---------------- | ------------------------------------------------- | ------------------------------------------------------------ |
| `certificate_expiry_critical`                              | `critical`                    | `pki_validation` | observed + implemented                            | certificate identity, target/application URI, days remaining |
| certificate warning events from `_telemetry_cert_events()` | likely `warning` / `critical` | `pki_validation` | implemented but not fully enumerated from snippet | certificate metadata                                         |

The source code contains a telemetry certificate event loop using `_telemetry_cert_events(certificate_telemetry)` and forwards each returned event to the collector. The exact helper body was not visible in the retrieved snippets, but the observed Splunk message confirms `certificate_expiry_critical` exists.  

### Security meaning

Critical if a runtime certificate is near expiry or expired, because OPC UA/FUXA trust may break or operators may be tempted to weaken security.

### Operational meaning

Certificate rotation planning.

### Noise assessment

Not noise. Should be visible until fixed.

---

## G. GDS telemetry summary events

| Message                | Severity | Category                              | Status                 | Fields / tags                                                                   |
| ---------------------- | -------- | ------------------------------------- | ---------------------- | ------------------------------------------------------------------------------- |
| `gds_telemetry_pulled` | `info`   | `pki_trust_sync` or telemetry-related | observed + implemented | likely sync/correlation IDs, metrics path, certificate drift count, mTLS counts |

The code forwards a telemetry summary with metrics including `mtls_success_count`, `mtls_failure_count`, `certificate_drift_count`, `component_status_count`, and `telemetry_path`.  The observed source list confirms `gds_telemetry_pulled` is currently visible in Splunk. 

### Security meaning

Medium. Useful to know whether GDS control-plane telemetry is being pulled and whether there are mTLS failures or drift.

### Operational meaning

Strong source coverage/health indicator.

### Noise assessment

Mostly operational. Keep as health event, not alert unless missing for a long time.

---

## H. Component lifecycle / component status events

| Message                                           | Severity   | Category        | Status                           | Fields                                                                                                             |
| ------------------------------------------------- | ---------- | --------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `component_private_key_policy_violation_reported` | `critical` | `pki_lifecycle` | implemented but not yet observed | `sync_cycle_id`, `application_uri`, `target`, `private_key_exported`, `private_key_touched`, `risk_level=CRITICAL` |
| `component_crl_freshness_not_verified`            | `warning`  | `pki_lifecycle` | implemented but not yet observed | `sync_cycle_id`, `application_uri`, `target`, `risk_level=MEDIUM`                                                  |
| `component_renewal_failed`                        | `warning`  | `pki_lifecycle` | implemented but not yet observed | `sync_cycle_id`, `application_uri`, `target`, `risk_level=MEDIUM`                                                  |
| `component_trust_apply_failed`                    | `warning`  | `pki_lifecycle` | implemented but not yet observed | `sync_cycle_id`, `application_uri`, `target`, `risk_level=MEDIUM`                                                  |

These are emitted when component lifecycle status indicates private-key violations, CRL freshness failure, renewal failure, or trust apply failure. 

### Security meaning

Very high for private key violations; medium/high for CRL and lifecycle failures.

### Operational meaning

Shows per-component PKI health.

### Noise assessment

* Private key policy violations: never noise.
* CRL freshness and renewal failures may repeat until fixed.

---

## I. Activation gate events

| Message                   | Severity  | Category         | Status                           | Fields                                                                                                                                                        |
| ------------------------- | --------- | ---------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `activation_gate_ready`   | `info`    | `pki_trust_sync` | implemented but not yet observed | `target`, `status`, `blocked_reason`, `approval_status`, `within_window`, `within_blackout`, `artifact_version`, `artifact_revision`, `risk_level`, `diff_id` |
| `activation_gate_denied`  | `warning` | `pki_validation` | implemented but not yet observed | same fields                                                                                                                                                   |
| `emergency_override_used` | `warning` | `pki_validation` | implemented but not yet observed | same fields                                                                                                                                                   |

The code evaluates activation gates and forwards `activation_gate_ready`, `activation_gate_denied`, or `emergency_override_used` depending on gate status. 

### Security meaning

High. This is the control layer that prevents unsafe runtime mutation outside approval/window/blackout policy.

### Operational meaning

Shows why activation was allowed or blocked.

### Noise assessment

Low-to-medium. Gate denials may repeat if the system is intentionally outside a maintenance window.

---

## J. Package activation / runtime mutation events

| Message                            | Severity                     | Category                                                       | Status                                                                         | Fields                                                                                                                                                                                                                                                              |
| ---------------------------------- | ---------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `package_runtime_activated`        | `info`                       | `pki_trust_sync`                                               | implemented but not yet observed                                               | `target`, `package_id`, `generation`, `plan_id`, `receipt_id`, `changed_files_count`, `rollback_snapshot_created`, `runtime_write_enabled`, `runtime_restart_automatic`, `private_key_overwritten`, `sync_cycle_id`, `application_uri`, `diff_id`, `risk_level=LOW` |
| `package_activation_failed`        | local log + lifecycle report | implemented but not confirmed as OT Collector event in snippet | `target`, `package_id`, `plan_id`, `failure_code`, `error`, `mutation_started` |                                                                                                                                                                                                                                                                     |
| `renew_runtime_certificate_failed` | local log                    | implemented but not confirmed as OT Collector event in snippet | `target`, `failure_code`, `error`                                              |                                                                                                                                                                                                                                                                     |

The code forwards `package_runtime_activated` to the OT Collector after successful runtime activation. On activation failure, the code logs `package_activation_failed` and writes a failure receipt; it also reports package lifecycle back to the GDS control plane.  

### Security meaning

High, because it confirms that runtime trust/certificate material was actually mutated.

### Operational meaning

Proof of controlled activation and rollback snapshot creation.

### Noise assessment

Low. Runtime mutation events should be rare and important.

---

## K. Revocation / quarantine events

| Message                      | Severity            | Category         | Status                           | Fields                                                                                                                                                                                           |
| ---------------------------- | ------------------- | ---------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `revocation_dry_run_created` | `info` or `warning` | `pki_validation` | implemented but not yet observed | `sync_cycle_id`, `crl_changed`, `revoked_certificates_count`, `affected_runtime_entries_count`, `deletion_candidates_count`, `files_to_remove_count`, `runtime_mutation_performed`, `risk_level` |

The code creates revocation dry-run reports and forwards `revocation_dry_run_created`; severity is `info` if no affected runtime entries are found, otherwise `warning`. 

### Security meaning

High when affected runtime trust entries exist.

### Operational meaning

Supports safe revocation reconciliation without direct runtime deletion.

### Noise assessment

Low. Useful during revocation testing.

---

## Important fields / tags for GDS Agent

| Field                    | Meaning                     | Example / expected value                         | Use                     |
| ------------------------ | --------------------------- | ------------------------------------------------ | ----------------------- |
| `message`                | Main event name             | `sync_cycle_success`, `gds_cert_missing_runtime` | primary classification  |
| `event_category`         | Event family                | `pki_validation`, `pki_trust_sync`               | dashboard grouping      |
| `severity`               | Severity                    | `info`, `warning`, `critical`                    | alert severity          |
| `source_type`            | Source type                 | `gds_agent` / `gds-agent`                        | needs normalization     |
| `asset_name`             | Asset label                 | `OT GDS Agent`                                   | source coverage         |
| `asset_ip`               | Agent IP                    | configured env value                             | source attribution      |
| `tags.component`         | Component name              | `labshock_ot_gds_agent`                          | component filtering     |
| `tags.gds_control_plane` | GDS base/control plane host | host/IP                                          | GDS reachability        |
| `tags.trustlist_zone`    | Trustlist zone              | `OT`, `DMZ`                                      | trustlist dashboards    |
| `tags.trustlist_role`    | Trustlist role              | `server`, `scada-client`                         | trustlist dashboards    |
| `tags.risk_level`        | Risk classification         | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`              | alert tuning            |
| `tags.diff_id`           | Diff/report/preview ID      | UUID                                             | drilldown               |
| `tags.sync_cycle_id`     | Sync correlation ID         | UUID                                             | correlation             |
| `tags.correlation_id`    | Correlation ID              | usually same as sync cycle                       | cross-event correlation |
| `raw.drift_count`        | Drift item count            | `1`, `2`, etc.                                   | drift panels            |
| `raw.items`              | Drift details               | list                                             | investigation           |
| `raw.path`               | Local cache/report path     | `/.../crl.der`                                   | troubleshooting         |
| `raw.error`              | Error message               | exception string                                 | failure analysis        |
| `raw.target`             | Runtime target              | `opcua-server`, `fuxa`                           | per-target panels       |
| `raw.application_uri`    | Application URI             | `urn:dataprotect:opcua:ot-server`                | certificate identity    |
| `raw.fingerprint_sha256` | Certificate fingerprint     | SHA-256                                          | cert identity           |
| `raw.days_remaining`     | Certificate expiry          | integer                                          | expiry alerting         |

---

# 5. Parser improvement backlog — GDS additions

| Issue                           | Affected source | Current behavior                                                             | Desired normalization                                                                 | Priority | Suggested implementation                                                                      |
| ------------------------------- | --------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------- |
| `gds-agent` vs `gds_agent`      | OT GDS Agent    | `normalize_for_ot_collector()` defaults to `gds-agent`, tags use `gds_agent` | canonicalize to `gds_agent`                                                           | High     | Splunk eval/field alias                                                                       |
| Message vs event_type           | OT GDS Agent    | Main event name is stored as `message`, not always `event_type`              | create canonical `event_type=message` for GDS                                         | High     | `eval event_type=coalesce(event_type,message)`                                                |
| Category name `gds_agent_error` | OT GDS Agent    | Used as category but not in original category list                           | classify as `error` or keep as subcategory                                            | Medium   | field alias `normalized_category=if(event_category="gds_agent_error","error",event_category)` |
| Severity consistency            | GDS + OPC UA    | GDS uses `warning`; OPC UA native uses `warn`                                | normalize both to `warning`                                                           | High     | `eval severity=case(severity="warn","warning",true(),severity)`                               |
| Raw JSON nested as string       | OT GDS Agent    | `raw` may be JSON string after normalization                                 | ensure `spath input=raw` works or parse into `raw.*`                                  | High     | Splunk props/transforms                                                                       |
| Tags enrichment                 | OT GDS Agent    | key data in `tags`                                                           | expose `risk_level`, `sync_cycle_id`, `trustlist_zone`, `target` as searchable fields | High     | `spath path=tags.risk_level output=risk_level`                                                |
| Drift item expansion            | OT GDS Agent    | `raw.items` may contain list                                                 | create optional drilldown search with `mvexpand`                                      | Medium   | dashboard drilldown                                                                           |
| Rate-limited health events      | OT GDS Agent    | success/health events are intentionally limited                              | document to avoid false “missing event” assumptions                                   | Medium   | dashboard note                                                                                |
| Collector truncation            | OT GDS Agent    | payload may set `payload_truncated=true`                                     | track truncation count                                                                | Medium   | alert if repeated truncation                                                                  |

---

# 6. Dashboard blueprint — GDS readiness

| Dashboard                          | Current readiness       | Why                                                                                                                                                      |
| ---------------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PKI/GDS Certificate Health         | ready for first version | Observed `certificate_expiry_critical`, `certificate_inventory_drift_detected`, `gds_cert_missing_runtime`, `gds_telemetry_pulled`, `sync_cycle_success` |
| GDS Trust Sync Timeline            | ready for first version | `sync_cycle_success`, `sync_cycle_failure`, cache writes, trustlist diff events implemented                                                              |
| Certificate Inventory Drift        | ready                   | Drift events observed + implemented                                                                                                                      |
| Certificate Expiration             | ready                   | `certificate_expiry_critical` observed                                                                                                                   |
| Activation Gate / Runtime Mutation | partial                 | implemented, not yet observed                                                                                                                            |
| Revocation / Quarantine Safety     | partial                 | implemented, not yet observed                                                                                                                            |
| GDS Control Plane Health           | partial                 | needs consistent `gds_telemetry_pulled`, mTLS success/failure fields                                                                                     |

---

# 7. Alert blueprint — GDS additions

| Alert name                           | SPL readiness | Severity     | Threshold                                                                       | Explanation                                             | False positive notes                      |
| ------------------------------------ | ------------- | ------------ | ------------------------------------------------------------------------------- | ------------------------------------------------------- | ----------------------------------------- |
| Certificate expiry critical          | ready         | critical     | `message="certificate_expiry_critical"`                                         | Runtime certificate near expiry/expired                 | valid during test certificates            |
| GDS certificate missing from runtime | ready         | warning/high | `message="gds_cert_missing_runtime"`                                            | GDS-managed certificate absent from runtime trust store | expected before trust apply is finished   |
| Certificate inventory drift detected | ready         | warning      | `message="certificate_inventory_drift_detected" AND raw.drift_count>0`          | Runtime and GDS inventory mismatch                      | can be noisy during rollout               |
| GDS sync cycle failure               | partial       | warning/high | `message="sync_cycle_failure"`                                                  | Agent failed sync loop                                  | expected if GDS is down                   |
| Critical trustlist diff              | partial       | critical     | `message="critical_diff_detected"`                                              | Trustlist integrity or parsing issue                    | may occur with malformed test artifacts   |
| CA chain changed                     | partial       | high         | `message="ca_chain_changed"`                                                    | CA chain changed                                        | expected only during CA rotation          |
| CRL changed                          | partial       | medium       | `message="crl_changed"`                                                         | Revocation material changed                             | expected during revocation tests          |
| Private key policy violation         | partial       | critical     | `message="component_private_key_policy_violation_reported"`                     | Private key exported/touched                            | should never happen normally              |
| CRL freshness not verified           | partial       | high         | `message="component_crl_freshness_not_verified"`                                | Revocation freshness not guaranteed                     | may occur if GDS lacks freshness metadata |
| Activation gate denied               | partial       | medium       | `message="activation_gate_denied"`                                              | Runtime activation blocked by policy                    | expected outside maintenance window       |
| Emergency override used              | partial       | high         | `message="emergency_override_used"`                                             | Emergency override path used                            | requires manual review                    |
| Package runtime activated            | partial       | medium/high  | `message="package_runtime_activated"`                                           | Runtime trust/cert material was changed                 | expected during approved activation       |
| Revocation dry-run affected runtime  | partial       | high         | `message="revocation_dry_run_created" AND raw.affected_runtime_entries_count>0` | Revoked cert still present in runtime trust             | expected during revocation lab phase      |

---

# Added to the reference

* Added **OT GDS Agent** as a full per-source catalog entry.
* Classified observed GDS messages:

  * `certificate_expiry_critical`
  * `certificate_inventory_drift_detected`
  * `gds_cert_missing_runtime`
  * `gds_telemetry_pulled`
  * `sync_cycle_success`
* Extracted implemented-but-not-yet-observed event families:

  * sync cycle failure
  * cache write success/failure
  * CA/CRL changes
  * trustlist diff
  * critical diff
  * runtime certificate drift details
  * component lifecycle failures
  * activation gate events
  * package runtime activation
  * revocation dry-run
* Added GDS-specific field dictionary entries.
* Added GDS parser backlog.
* Added GDS dashboard readiness.
* Added GDS alert candidates.

# Still missing

* Actual Splunk export for `sourcetype=labshock:ot:gds` with extracted fields.
* Full raw examples for each observed message.
* Confirmation of the exact canonical Splunk field names:

  * `message` vs `event_type`
  * `tags.risk_level` vs `risk_level`
  * `raw.drift_count` vs `drift_count`
* Confirmation whether `source_type` appears as `gds-agent`, `gds_agent`, or both.
* Confirmation of the GDS Agent IP / container name.
* Full body of helper `_telemetry_cert_events()` to enumerate all certificate expiry warning levels precisely.

# Next source to provide

Best next input: **Splunk export for `sourcetype=labshock:ot:gds`** with columns:

```spl
index=ot_security sourcetype=labshock:ot:gds
| table _time asset_name source_type severity event_category message tags.* raw
```

After that, send **PLC logs** so we can cleanly classify `Attempting to login`, `Login success`, `User logout`, `PLC started`, and `PLC stopped/stoped`.
