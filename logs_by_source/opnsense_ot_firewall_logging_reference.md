# LabShock Logging & SIEM Source Reference — OPNsense OT Firewall

## 1. Source identity

| Field | Value |
|---|---|
| Source name | OPNsense OT Firewall |
| Zone | OT boundary / firewall |
| Expected Splunk index | `ot_security` |
| Sourcetype | `labshock:net:firewall` |
| Source type | `firewall` |
| Asset name | `OPNsense OT Firewall` |
| Current status | `observed from Splunk only` |
| Current observed message | `firewall_pass` |
| Current block visibility | No `firewall_block` confirmed yet |
| Security value | High, especially after restrictive rules are enabled |
| Operational value | Traffic visibility, rule validation, segmentation evidence |

---

## 2. Current syslog destination configuration

Based on the current OPNsense remote logging destination screen:

| Parameter | Current value |
|---|---|
| Enabled | Yes |
| Transport | `UDP(4)` |
| Applications | `filter (filterlog)`, `firewall (firewall)`, `routing (routed)` |
| Levels | `info`, `notice`, `warn`, `error`, `critical`, `alert`, `emergency` |
| Facility | `local0` |
| Destination hostname | `192.168.1.70` |
| Destination port | `514` |
| RFC5424 | Enabled |
| Description | `OT Collector` |

### Interpretation

The firewall is configured to forward logs by UDP syslog to the OT Collector at `192.168.1.70:514`.

The selected applications are relevant for the SIEM chain:

- `filterlog`: packet filtering decisions, pass/block traffic, rules, interfaces, IPs, ports, protocols.
- `firewall`: firewall service/system messages.
- `routed`: routing daemon messages, useful for routing-state visibility if used.

The destination uses RFC5424 formatting, which is preferred because it provides a more structured syslog envelope than classic RFC3164.

---

## 3. Current validated pipeline

```text
OPNsense OT Firewall
        ↓ UDP/514 RFC5424 syslog
OT Collector — 192.168.1.70
        ↓
DMZ Collector
        ↓ Splunk HEC
Splunk index: ot_security
Sourcetype: labshock:net:firewall
```

---

## 4. Per-source log catalog

## OPNsense OT Firewall

- **Role:** OT boundary firewall and traffic control point.
- **Zone:** OT boundary.
- **Sourcetype:** `labshock:net:firewall`.
- **Index:** `ot_security`.
- **Status:** observed from Splunk only.
- **Known observed message:** `firewall_pass`.
- **Known missing message:** `firewall_block` not yet confirmed.
- **Transport to collector:** UDP syslog to `192.168.1.70:514`.
- **Format:** RFC5424 enabled.
- **Facility:** `local0`.

### Known event categories

| Event category | Status | Meaning |
|---|---|---|
| `network_traffic` | observed from Splunk only | Firewall traffic events, currently mostly pass events |
| `firewall_policy` | expected | Rule action, interface, rule number, policy tracking |
| `routing` | configured but not yet catalogued | Routing daemon events if `routed` emits logs |
| `system_health` | configured but not yet catalogued | Firewall service/system messages |
| `security` | expected when blocks are generated | Denied traffic, policy violations, unexpected flows |

---

## 5. Observed and expected firewall events

| Event / message | Status | Expected severity | Meaning |
|---|---|---|---|
| `firewall_pass` | observed from Splunk only | `info` / `notice` | A packet or flow was allowed by firewall policy |
| `firewall_block` | not yet observed | `warning` or higher depending parser policy | A packet or flow was blocked |
| `firewall_reject` | not yet observed | `warning` | Traffic was explicitly rejected |
| `routed_event` | configured but not yet observed | depends on routing daemon | Routing service event |
| `firewall_system_event` | configured but not yet observed | depends on OPNsense log level | Firewall system/service event |

### Current interpretation

The firewall currently provides evidence of allowed traffic. This is useful for proving connectivity and mapping actual flows, but it is not yet sufficient for a security dashboard focused on blocked traffic because no block event has been confirmed.

---

## 6. Important fields / tags

The following fields are expected or already known from the current parser design and previous Splunk observations.

| Field | Meaning | Example | Dashboard use | Alert use |
|---|---|---|---|---|
| `asset_name` | Human-readable source name | `OPNsense OT Firewall` | Source filtering | Source coverage |
| `source_type` | Logical source type | `firewall` | Source grouping | Parser validation |
| `severity` | Event severity | `info`, `warning` | Severity panels | Thresholding |
| `event_category` | Event family | `network_traffic`, `firewall_policy` | Dashboard grouping | Alert routing |
| `message` | Normalized event name | `firewall_pass` | Main panel dimension | Alert trigger |
| `raw` | Original or normalized raw payload | firewall log line / JSON | Drilldown | Investigation |
| `tags.action` | Firewall decision | `pass`, `block`, `reject` | Pass/block ratio | Block alerts |
| `tags.src_ip` | Source IP address | `192.168.1.x` | Top sources | Suspicious source |
| `tags.src_port` | Source port | `502`, ephemeral | Flow analysis | Abnormal service |
| `tags.dst_ip` | Destination IP address | `192.168.1.70` | Top destinations | Protected asset targeting |
| `tags.dst_port` | Destination port | `502`, `4840`, `514` | Service panels | Unexpected port |
| `tags.protocol_name` | Protocol | `tcp`, `udp`, `icmp` | Protocol breakdown | Unexpected protocol |
| `tags.interface` | Firewall interface | `OT`, `DMZ`, `LAN`, etc. | Interface activity | Wrong-zone activity |
| `tags.rule_number` | Matched firewall rule | numeric/string | Rule analysis | Risky rule |
| `tags.tracker` | OPNsense/pf rule tracker | tracker ID | Rule correlation | Rule-specific alert |

---

## 7. Security meaning

The OPNsense firewall logs are critical because they prove whether the segmentation model is actually enforced.

Main security uses:

1. **Validate OT/DMZ/IT segmentation**
   - Confirm which flows cross firewall boundaries.
   - Detect direct MES/IT access to PLCs if it appears.
   - Prove that traffic is routed through the intended chokepoint.

2. **Detect policy violations**
   - Blocked or rejected traffic should become high-value events.
   - Unexpected traffic to PLC Modbus `502` or OPC UA `4840` should be reviewed.

3. **Support incident investigation**
   - Correlate firewall events with OPC UA, PLC, SCADA, EWS, GDS, and collector logs.
   - Example: `modbus_connection_failed` from OPC UA server can be correlated with firewall block/pass logs.

4. **Build visibility of allowed flows**
   - Even `firewall_pass` is useful during lab validation.
   - Pass logs help build an allowlist baseline before tightening firewall rules.

---

## 8. Operational meaning

Firewall logs also help troubleshoot:

- wrong routes,
- missing OVS attachment,
- blocked collector/syslog traffic,
- unreachable PLCs,
- wrong firewall interface,
- rule ordering issues,
- OT Collector reachability,
- DMZ forwarding problems.

Examples:

| Symptom | Firewall logs can show |
|---|---|
| OPC UA cannot reach PLC | pass/block for `192.168.1.62 → PLC:502` |
| EWS logger not visible in Splunk | pass/block for `192.168.1.50 → 192.168.1.70:514` |
| GDS Agent cannot reach control plane | pass/block for GDS control-plane destination |
| SCADA cannot reach OPC UA | pass/block for `FUXA → OPC UA:4840` |
| Nozomi sees traffic but Splunk does not | firewall/collector forwarding gap |

---

## 9. Dashboard value

### Current readiness

| Dashboard panel | Readiness | Reason |
|---|---|---|
| Firewall event volume | ready | `firewall_pass` observed |
| Pass traffic by source/destination | ready if fields are extracted | depends on parser field quality |
| Top services / destination ports | ready if `dst_port` is extracted | useful for OT flow baseline |
| Pass/block ratio | partial | block events not yet observed |
| Blocked traffic timeline | blocked | no `firewall_block` confirmed |
| Rule hit count | partial | requires `tags.rule_number` or `tags.tracker` |
| Interface activity | partial | requires `tags.interface` extraction |
| OT collector syslog traffic | ready if firewall logs include destination `192.168.1.70:514` | useful after EWS/GDS/OPC logs |

### Suggested future panels

| Panel | Purpose | Required fields |
|---|---|---|
| Firewall Events Over Time | Show traffic/log volume | `_time`, `message`, `severity` |
| Pass vs Block | Show enforcement state | `tags.action` |
| Top Source IPs | Identify active sources | `tags.src_ip` |
| Top Destination IPs | Identify targeted assets | `tags.dst_ip` |
| Top Destination Ports | Identify protocols/services | `tags.dst_port`, `tags.protocol_name` |
| Rule Hit Count | Validate firewall rules | `tags.rule_number`, `tags.tracker` |
| OT Collector Traffic | Confirm syslog forwarding | `tags.dst_ip=192.168.1.70`, `tags.dst_port=514` |
| Unexpected Direct PLC Access | Detect direct access to PLCs | `tags.dst_ip=192.168.1.20-24`, `tags.dst_port=502` |

---

## 10. Alert value

### Alert candidates

| Alert name | Readiness | Severity | Condition | Notes |
|---|---|---|---|---|
| Firewall block detected | partial | medium/high | `message="firewall_block"` or `tags.action="block"` | Needs block events confirmed |
| Direct access to PLC Modbus | partial | high | destination PLC IP + `dst_port=502` from unauthorized source | Requires allowlist |
| Direct IT/MES to PLC | partial | critical | IT/MES source subnet to PLC destination | Requires source zone extraction |
| OT Collector syslog blocked | partial | high | block traffic to `192.168.1.70:514` | Important for SIEM visibility |
| Unexpected OPC UA access | partial | high | access to `192.168.1.62:4840` from unauthorized source | Needs allowlist |
| Firewall logging stopped | partial | high | no firewall events over N minutes | Requires source coverage baseline |
| Routing daemon warning | configured only | medium | `routed` warning/error logs | Need observed routed events |

---

## 11. Recommended validation SPL

### Raw firewall events

```spl
index=ot_security sourcetype=labshock:net:firewall
| table _time host source sourcetype asset_name source_type severity event_category message tags.* raw
| sort - _time
```

### Event types by count

```spl
index=ot_security sourcetype=labshock:net:firewall
| stats count earliest(_time) as first_seen latest(_time) as last_seen
  by asset_name source_type severity event_category message
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

### Check pass/block visibility

```spl
index=ot_security sourcetype=labshock:net:firewall
| eval action=coalesce('tags.action', action)
| stats count by action message severity
| sort - count
```

### Top source/destination flows

```spl
index=ot_security sourcetype=labshock:net:firewall
| eval src_ip=coalesce('tags.src_ip', src_ip)
| eval dst_ip=coalesce('tags.dst_ip', dst_ip)
| eval dst_port=coalesce('tags.dst_port', dst_port)
| eval protocol=coalesce('tags.protocol_name', protocol)
| stats count by src_ip dst_ip dst_port protocol message
| sort - count
```

### Traffic to OT Collector

```spl
index=ot_security sourcetype=labshock:net:firewall
| eval dst_ip=coalesce('tags.dst_ip', dst_ip)
| eval dst_port=coalesce('tags.dst_port', dst_port)
| search dst_ip="192.168.1.70" dst_port="514"
| table _time src_ip dst_ip dst_port protocol message tags.* raw
| sort - _time
```

### Detect direct Modbus access to PLCs

```spl
index=ot_security sourcetype=labshock:net:firewall
| eval src_ip=coalesce('tags.src_ip', src_ip)
| eval dst_ip=coalesce('tags.dst_ip', dst_ip)
| eval dst_port=coalesce('tags.dst_port', dst_port)
| where dst_port="502" AND match(dst_ip, "^192\.168\.1\.2[0-4]$")
| stats count by src_ip dst_ip dst_port message
| sort - count
```

### Firewall source coverage

```spl
index=ot_security sourcetype=labshock:net:firewall
| stats count latest(_time) as last_seen by host source asset_name source_type
| convert ctime(last_seen)
| sort - last_seen
```

---

## 12. Parser improvement backlog

| Issue | Current behavior | Desired behavior | Priority |
|---|---|---|---|
| Confirm `firewall_block` mapping | Only `firewall_pass` known | Normalize block/reject events | High |
| Normalize action field | May appear under `tags.action` or raw | canonical `action` and `tags.action` | High |
| Extract source/destination fields | Needed for flow dashboards | `src_ip`, `src_port`, `dst_ip`, `dst_port` | High |
| Extract protocol | Needed for protocol dashboards | `protocol_name` | High |
| Extract interface | Needed for zone/interface dashboards | `interface` | Medium |
| Extract rule number/tracker | Needed for rule hit panels | `rule_number`, `tracker` | Medium |
| Map severity consistently | OPNsense levels may vary | `info`, `warning`, `error`, etc. | Medium |
| Add zone enrichment | Raw logs may not contain zone | add src_zone/dst_zone by subnet lookup | High |
| Add asset enrichment | IPs should map to assets | PLC1, PLC2, OPC UA Server, EWS, SCADA, OT Collector | High |

---

## 13. Asset/IP enrichment suggestions

| IP / Range | Suggested asset |
|---|---|
| `192.168.1.20` | PLC1 |
| `192.168.1.21` | PLC2 |
| `192.168.1.22` | PLC3 / Analog PLC depending current topology |
| `192.168.1.23` | PLC4 |
| `192.168.1.24` | PLC5 |
| `192.168.1.25` | Simulated Data Sender |
| `192.168.1.50` | EWS / Engineering Workstation |
| `192.168.1.60` | SCADA FUXA |
| `192.168.1.62` | OPC UA Server |
| `192.168.1.70` | OT Collector |
| `192.168.1.254` | OT firewall/router interface |
| `192.168.10.0/24` | DMZ zone |
| `192.168.20.0/24` | IT/MES zone |

---

## 14. Test plan

### A. Confirm firewall forwarding to OT Collector

On OT Collector or host:

```bash
sudo tcpdump -ni any host <OPNSENSE_IP_OR_INTERFACE> and host 192.168.1.70 and port 514
```

### B. Generate allowed traffic

Examples:

```bash
ping 192.168.1.70
curl http://192.168.1.70:8088/health
```

Expected in Splunk:

```text
firewall_pass
```

### C. Generate blocked traffic later

After restrictive rules are enabled, attempt a denied flow, for example unauthorized direct access to a PLC service.

Expected in Splunk:

```text
firewall_block
```

### D. Validate fields

Use:

```spl
index=ot_security sourcetype=labshock:net:firewall
| table _time message tags.action tags.src_ip tags.dst_ip tags.dst_port tags.interface tags.rule_number tags.tracker raw
| sort - _time
```

---

## 15. Documentation status

```text
Source: OPNsense OT Firewall
Zone: OT boundary
Sourcetype: labshock:net:firewall
Index: ot_security
Status: observed from Splunk only

Confirmed configuration:
- Remote syslog enabled
- UDP(4)
- Destination: 192.168.1.70
- Port: 514
- RFC5424 enabled
- Facility: local0
- Applications: filterlog, firewall, routed
- Levels: info, notice, warn, error, critical, alert, emergency

Observed event:
- firewall_pass

Not yet observed:
- firewall_block
- firewall_reject
- routed events
- firewall system health events

Current readiness:
- Firewall pass traffic dashboard: ready/partial
- Block dashboard: blocked until block events are observed
- Rule hit dashboard: partial, depends on parser fields
- Flow baseline: ready if src/dst fields are extracted
```
