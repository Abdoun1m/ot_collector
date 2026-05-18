Here's the complete implementation for your LabShock EWS logging service.

---

## 1. `/home/engineer/ews_logger.py`## 2. Patched `start-vnc.sh`---

## Complete Implementation Reference

---

### 3. Install / Start / Test Commands

**Deploy into the container** (run from host or via `docker exec`):

```bash
# Copy files in
docker cp ews_logger.py  ews:/home/engineer/ews_logger.py
docker cp start-vnc.sh   ews:/home/engineer/start-vnc.sh

# Fix permissions
docker exec ews chmod +x /home/engineer/start-vnc.sh /home/engineer/ews_logger.py
docker exec ews chown engineer:engineer /home/engineer/ews_logger.py

# Install inotifywait (strongly recommended — eliminates CPU polling)
docker exec -u root ews apt-get update -qq
docker exec -u root ews apt-get install -y inotify-tools

# (Re)start the logger without restarting VNC
docker exec ews sh -c '
  kill $(cat /tmp/ews-logger.pid 2>/dev/null) 2>/dev/null
  export EWS_ASSET_IP=192.168.1.50
  export EWS_COLLECTOR_HOST=192.168.1.70
  export EWS_COLLECTOR_PORT=514
  export EWS_COLLECTOR_PROTO=udp
  export EWS_HEARTBEAT_SECONDS=60
  python3 /home/engineer/ews_logger.py >> /home/engineer/ews-logger.log 2>&1 &
  echo $! > /tmp/ews-logger.pid
  echo "Started PID $(cat /tmp/ews-logger.pid)"
'
```

**Switch to TCP/1514** (e.g., in Docker Compose):
```yaml
environment:
  - EWS_COLLECTOR_PROTO=tcp
  - EWS_COLLECTOR_PORT=1514
```

---

### 4. Generated Event Types

| `message` | `event_category` | `severity` | Trigger |
|---|---|---|---|
| `ews_logger_started` | `system_health` | info | Logger process boot |
| `ews_logger_stopped` | `system_health` | info | SIGTERM / SIGINT |
| `ews_heartbeat` | `system_health` | info | Every 60s |
| `project_file_created` | `project_activity` | info | New file appears in watched dirs |
| `project_file_modified` | `engineering_activity` | info | File mtime/size change |
| `project_file_deleted` | `project_activity` | info | File removed (non-PLC ext) |
| `plc_project_modified` | `plc_activity` | info | `.st`, `.plc`, `.scd`, `.icd`, etc. changed |
| `scada_project_modified` | `scada_activity` | info | FUXA/SCADA path changed |
| `openplc_editor_activity` | `engineering_activity` | info | OpenPLC path activity |
| `fuxa_config_activity` | `scada_activity` | info | FUXA config path activity |
| `suspicious_file_change` | `security` | warning | PLC project file **deleted** |
| `private_key_access_attempt_or_skip` | `security` | warning | `.key`, `id_rsa`, `PRIVATE KEY` accessed |
| `collector_send_failed` | `error` | warning | First UDP/TCP send failure |
| `collector_send_recovered` | `system_health` | info | Send succeeds after failure |

---

### 5. Test Commands (inside EWS container)

```bash
# 1. Verify logger is running
docker exec ews ps aux | grep -E "ews_logger|python3"

# 2. Watch the local log in real time
docker exec ews tail -f /home/engineer/ews-logger.log

# 3. Generate project file events
docker exec ews mkdir -p /home/engineer/projects
docker exec ews touch /home/engineer/projects/test_plc_project.st      # → project_file_created
docker exec ews sh -c 'echo "VAR x : INT; END_VAR" >> /home/engineer/projects/test_plc_project.st'  # → plc_project_modified
docker exec ews rm /home/engineer/projects/test_plc_project.st          # → suspicious_file_change

# 4. Generate SCADA event
docker exec ews touch /home/engineer/fuxa/project.json                  # → fuxa_config_activity

# 5. Confirm UDP traffic to collector (run on OT Collector or bridged host)
tcpdump -i any -n "src host 192.168.1.50 and (udp port 514 or tcp port 1514)" -A | grep '"message"'

# 6. Heartbeat check (wait 60s then grep)
docker exec ews grep ews_heartbeat /home/engineer/ews-logger.log | tail -3
```

---

### 6. Splunk Validation SPL

**Basic validation — all EWS events:**
```spl
index=ot_security (source_type="ews" OR sourcetype="labshock:ot:ews" OR asset_name="Engineering Workstation")
| spath input=_raw
| table _time asset_name source_type severity event_category message
        tags.risk_level tags.component
        raw.path raw.event raw.sha256 raw.size_bytes
| sort - _time
```

**Heartbeat health check (alert if gap > 2 min):**
```spl
index=ot_security source_type="ews" message="ews_heartbeat"
| timechart span=1m count as heartbeats
| where heartbeats=0
```

**Security events only:**
```spl
index=ot_security source_type="ews" event_category="security"
| table _time message raw.path raw.event tags.risk_level
| sort - _time
```

**PLC/SCADA project modifications:**
```spl
index=ot_security source_type="ews" (event_category="plc_activity" OR event_category="scada_activity")
| stats count by message, raw.path
| sort - count
```

**Collector failure events:**
```spl
index=ot_security source_type="ews" message IN ("collector_send_failed","collector_send_recovered")
| table _time message raw.collector raw.proto
```

**File integrity timeline:**
```spl
index=ot_security source_type="ews" raw.sha256=*
| table _time raw.path raw.event raw.sha256 raw.size_bytes
| sort - _time
```

---

### 7. Parser Improvement Notes

If you run a custom parser on the OT Collector or in Splunk:

- **Field extraction**: All fields are top-level JSON keys. Use `spath` in Splunk or a JSON codec in Logstash/Cribl.
- **`raw.*` fields**: These are nested — use `spath output=file_path input=_raw path=raw.path` to promote them.
- **Sourcetype**: Assign `labshock:ot:ews` in the Collector's Splunk HEC token config, or via a `props.conf` transform:
  ```ini
  [labshock:ot:ews]
  KV_MODE = json
  TIME_FORMAT = %Y-%m-%dT%H:%M:%SZ
  TIME_PREFIX = "timestamp":\"
  ```
- **Index-time fields**: Promote `asset_ip`, `zone`, `source_type` as indexed fields for fast filter without full-text search.
- **Dedup in Splunk**: If duplicate events slip through, use `| dedup raw.path, message span=5s` in dashboards.
- **Risk scoring**: `tags.risk_level` maps to LOW/MEDIUM/HIGH — use `eval` to convert to numeric for alerting.

---

### 8. VNC/noVNC Safety

The logger is started **after** VNC and noVNC are already listening (`novnc_proxy` is a blocking-ish call but runs as a background proxy; `kali-undercover` is cosmetic). The logger launches as a background process (`&`) before `tail -f /dev/null` and:

- Does **not** use any X11 display variables or VNC ports
- Does **not** interfere with `/tmp/.X11-unix` cleanup
- Writes only to `/home/engineer/ews-logger.log` and the network socket
- A crash or exception in the logger does **not** kill the VNC session — it is fully isolated
- If the logger script is missing, `start-vnc.sh` logs a warning and continues normally

---

### 9. LabShock Logging & SIEM Source Reference — EWS Entry

```markdown
## Source: Engineering Workstation (EWS)

| Field              | Value                        |
|--------------------|------------------------------|
| Container name     | ews                          |
| Zone               | OT                           |
| IP                 | 192.168.1.50                 |
| Logger script      | /home/engineer/ews_logger.py |
| Local log          | /home/engineer/ews-logger.log|
| Transport          | UDP syslog → 192.168.1.70:514 (TCP 1514 optional) |
| Splunk index       | ot_security                  |
| sourcetype         | labshock:ot:ews              |
| source_type field  | ews                          |
| asset_name field   | Engineering Workstation      |
| Heartbeat interval | 60 s                         |
| Watcher strategy   | inotifywait (polling fallback)|
| Event categories   | system_health, engineering_activity, file_integrity, project_activity, scada_activity, plc_activity, security, error |

### Key event messages
- `ews_logger_started` / `ews_logger_stopped` — lifecycle
- `ews_heartbeat` — continuity check every 60 s
- `plc_project_modified` — PLC source file (.st/.plc/.scd) changed
- `scada_project_modified` — FUXA/SCADA config changed
- `suspicious_file_change` — PLC project file deleted (HIGH risk)
- `private_key_access_attempt_or_skip` — key file touched, content NOT logged
- `collector_send_failed` / `collector_send_recovered` — transport health

### Splunk quick search
```spl
index=ot_security source_type="ews" | table _time message raw.path tags.risk_level | sort - _time
```

### Troubleshooting
```bash
# Is the logger running?
docker exec ews ps aux | grep python3

# Live log tail
docker exec ews tail -f /home/engineer/ews-logger.log

# Force restart without restarting VNC
docker exec ews sh -c 'kill $(cat /tmp/ews-logger.pid); python3 /home/engineer/ews_logger.py >> /home/engineer/ews-logger.log 2>&1 & echo $! > /tmp/ews-logger.pid'

# Test UDP reach from EWS to collector
docker exec ews python3 -c "
import socket, json, datetime
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = json.dumps({'test': True, 'ts': datetime.datetime.utcnow().isoformat()})
s.sendto(f'<14>1 {msg}'.encode(), ('192.168.1.70', 514))
print('Sent test UDP packet')
"

# Check if inotifywait is installed
docker exec ews which inotifywait || echo "MISSING — install inotify-tools"
```
```

---

### Quick Architecture Summary

```
EWS Container (192.168.1.50)
├── start-vnc.sh
│   ├── VNC / noVNC (unchanged)
│   └── python3 ews_logger.py &
│       ├── inotifywait (preferred) or polling watcher
│       ├── Heartbeat thread (every 60s)
│       └── JSON → syslog UDP:514 / TCP:1514
│
OT Collector (192.168.1.70)
└── → DMZ Collector → Splunk HEC → index=ot_security
```