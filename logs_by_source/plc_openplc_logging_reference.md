# LabShock Logging & SIEM Source Reference — PLC / OpenPLC

## 1. Source identity

| Field | Value |
|---|---|
| Source name | PLCs / OpenPLC |
| Assets observed | PLC1, PLC3, PLC4, PLC5 |
| Expected assets | PLC1, PLC2, PLC3, PLC4, PLC5 |
| Zone | OT |
| Expected IP range | 192.168.1.20–192.168.1.24 |
| Splunk index | `ot_security` |
| Sourcetype | `labshock:ot:plc` |
| Source type | `plc` / OpenPLC runtime logs |
| Status | Observed and normalized in Splunk |
| Main security value | PLC authentication and lifecycle monitoring |

This source represents OpenPLC runtime and web/session activity collected from the PLC containers. The first validated log families are authentication events and PLC lifecycle events.

---

## 2. Evidence summary

The PLC source has been validated in Splunk using:

```spl
index=ot_security sourcetype=labshock:ot:plc
```

Confirmed normalized events:

- `plc_login_attempt`
- `plc_login_success`
- `plc_user_logout`
- `plc_started`
- `plc_stopped`

Confirmed extracted field:

- `plc_user=openplc` from successful login logs.

Confirmed raw examples:

```text
<14>May 17 00:00:49 INFO: [*] Attempting to login
<14>May 17 00:00:49 INFO: [+] Login success for user: 'openplc'
<14>May 17 00:00:48 INFO: [+] User logout
<14>May 17 00:00:56 INFO: [+] PLC started
<14>May 17 00:00:53 INFO: [+] PLC stoped
```

Important parser correction:

```text
PLC stoped → PLC stopped
```

---

## 3. Observed event statistics

Latest validated Splunk summary showed **776 PLC events** over the selected 24-hour range.

| Asset | Event type | Count | User |
|---|---:|---:|---|
| PLC1 | `plc_login_attempt` | 3 | — |
| PLC1 | `plc_login_success` | 1 | `openplc` |
| PLC1 | `plc_started` | 1 | — |
| PLC1 | `plc_stopped` | 1 | — |
| PLC1 | `plc_user_logout` | 1 | — |
| PLC3 | `plc_login_attempt` | 639 | — |
| PLC4 | `plc_login_attempt` | 65 | — |
| PLC5 | `plc_login_attempt` | 65 | — |

### Security interpretation

`PLC3` generated a high number of login attempts. This should be investigated before final alert tuning. Possible explanations:

1. Real repeated login attempts against PLC3.
2. A browser, service, or script repeatedly trying to authenticate.
3. OpenPLC runtime behavior producing repeated login attempt logs.
4. Parser overmatching, although raw messages currently support the login-attempt classification.

The `PLC1` login success confirms that OpenPLC successful authentication events are visible and can be used for engineering access auditing.

---

## 4. Per-event catalog

### 4.1 `plc_login_attempt`

| Field | Value |
|---|---|
| Raw pattern | `Attempting to login` |
| Category | `access_control` |
| Severity | `info` initially; alert severity becomes high when repeated |
| Status | Observed in Splunk |
| Example asset | PLC1, PLC3, PLC4, PLC5 |

**Meaning:** an authentication attempt was made against the PLC/OpenPLC interface.

**Security value:** useful for brute-force detection, unauthorized access monitoring, and engineering workstation activity correlation.

**Operational value:** shows when users or tools are interacting with the OpenPLC interface.

**Alert value:** high when repeated above baseline.

---

### 4.2 `plc_login_success`

| Field | Value |
|---|---|
| Raw pattern | `Login success for user: 'openplc'` |
| Category | `access_control` |
| Severity | `info` / medium alert event |
| Status | Observed in Splunk |
| Extracted user | `openplc` |

**Meaning:** a successful login occurred on the PLC/OpenPLC interface.

**Security value:** confirms granted access to the PLC interface. Should be correlated with expected maintenance or engineering activity.

**Operational value:** provides traceability of engineering access.

**Alert value:** medium by default; high if outside maintenance window or after repeated failed/attempt events.

---

### 4.3 `plc_user_logout`

| Field | Value |
|---|---|
| Raw pattern | `User logout` |
| Category | `operator_action` |
| Severity | `info` |
| Status | Observed in Splunk |

**Meaning:** the OpenPLC user session was closed.

**Security value:** session traceability.

**Operational value:** helps reconstruct an engineering session timeline.

**Alert value:** low by itself; useful in correlation.

---

### 4.4 `plc_started`

| Field | Value |
|---|---|
| Raw pattern | `PLC started` |
| Category | `system` |
| Severity | `info` |
| Status | Observed in Splunk |

**Meaning:** the PLC runtime started.

**Security value:** important when correlated with login or stop events.

**Operational value:** confirms PLC runtime availability.

**Alert value:** medium if unexpected restart occurs.

---

### 4.5 `plc_stopped`

| Field | Value |
|---|---|
| Raw pattern | `PLC stoped` or `PLC stopped` |
| Category | `system` |
| Severity | `warning` recommended |
| Status | Observed in Splunk |

**Meaning:** the PLC runtime stopped.

**Security value:** high, because stopping a PLC runtime can affect process continuity and may indicate operator action, fault, or malicious interference.

**Operational value:** critical for availability monitoring.

**Alert value:** high. Any unexpected PLC stop should be investigated.

---

## 5. Normalization logic

Recommended SPL normalization:

```spl
index=ot_security sourcetype=labshock:ot:plc
| eval clean_raw=coalesce(raw,message,_raw)
| eval clean_raw=replace(clean_raw,"^<\\d+>[A-Z][a-z]{2}\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2}\\s+","")
| eval clean_raw=replace(clean_raw,"stoped","stopped")
| eval event_type=case(
    like(lower(clean_raw), "%attempting to login%"), "plc_login_attempt",
    like(lower(clean_raw), "%login success%"), "plc_login_success",
    like(lower(clean_raw), "%user logout%"), "plc_user_logout",
    like(lower(clean_raw), "%plc started%"), "plc_started",
    like(lower(clean_raw), "%plc stopped%"), "plc_stopped",
    true(), "other"
)
| rex field=clean_raw "Login success for user:\\s*'(?<plc_user>[^']+)'"
| eval normalized_category=case(
    event_type IN ("plc_login_attempt","plc_login_success"), "access_control",
    event_type="plc_user_logout", "operator_action",
    event_type IN ("plc_started","plc_stopped"), "system",
    true(), event_category
)
| table _time asset_name event_type normalized_category severity plc_user clean_raw raw
| sort - _time
```

---

## 6. Final PLC summary SPL

```spl
index=ot_security sourcetype=labshock:ot:plc
| eval clean_raw=coalesce(raw,message,_raw)
| eval clean_raw=replace(clean_raw,"^<\\d+>[A-Z][a-z]{2}\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2}\\s+","")
| eval clean_raw=replace(clean_raw,"stoped","stopped")
| eval event_type=case(
    like(lower(clean_raw), "%attempting to login%"), "plc_login_attempt",
    like(lower(clean_raw), "%login success%"), "plc_login_success",
    like(lower(clean_raw), "%user logout%"), "plc_user_logout",
    like(lower(clean_raw), "%plc started%"), "plc_started",
    like(lower(clean_raw), "%plc stopped%"), "plc_stopped",
    true(), "other"
)
| rex field=clean_raw "Login success for user:\\s*'(?<plc_user>[^']+)'"
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(plc_user) as users by asset_name event_type
| convert ctime(first_seen) ctime(last_seen)
| sort asset_name event_type
```

---

## 7. Field dictionary

| Field | Meaning | Example | Dashboard use | Alert use |
|---|---|---|---|---|
| `_time` | Splunk event timestamp | `2026-05-17 00:00:49` | timeline | correlation |
| `asset_name` | PLC asset name | `PLC1`, `PLC3` | per-PLC panels | per-PLC thresholds |
| `sourcetype` | Splunk sourcetype | `labshock:ot:plc` | source filtering | source filtering |
| `message` | Parsed message field | `Attempting to login` | event table | event matching |
| `raw` | Original raw payload | `<14>May 17 ...` | drilldown | parser validation |
| `clean_raw` | Normalized raw message | `INFO: [+] PLC started` | event readability | normalized matching |
| `event_type` | Normalized event name | `plc_login_success` | core dashboard dimension | alert trigger |
| `plc_user` | Extracted PLC user | `openplc` | user/session table | login auditing |
| `normalized_category` | Corrected event category | `access_control` | dashboard grouping | alert routing |
| `severity` | Event severity | `info` | severity panel | alert priority |

---

## 8. Parser improvement backlog

| Issue | Current behavior | Desired behavior | Priority |
|---|---|---|---|
| Raw syslog prefix | Raw contains `<14>May 17 ...` | Remove prefix into `clean_raw` | High |
| Typo in OpenPLC log | `PLC stoped` | Normalize to `PLC stopped` / `plc_stopped` | High |
| Login success user | User embedded in raw string | Extract `plc_user=openplc` | High |
| Login category | Login events currently appear as `system` | Reclassify to `access_control` | High |
| Logout category | Logout appears as `operator_action` or `other` | Normalize as `plc_user_logout` | High |
| PLC lifecycle | Start/stop previously appeared as `other` | Normalize as `plc_started`, `plc_stopped` | High |
| PLC2 missing | PLC2 not observed in latest summary | Confirm whether PLC2 logging is enabled | Medium |
| Source IP/user attribution | No source client IP visible yet | Extract if present in raw logs or improve logger | Medium |

---

## 9. Dashboard blueprint

### 9.1 PLC Authentication Activity

| Panel | Purpose | Readiness |
|---|---|---|
| Login attempts by PLC | Identify high-authentication activity per PLC | Ready |
| Login success timeline | Audit successful OpenPLC access | Ready |
| Top PLCs by login attempts | Highlight abnormal assets, especially PLC3 | Ready |
| Login attempts over time | Detect bursts | Ready |
| Login success user table | Show users such as `openplc` | Ready |

Example SPL:

```spl
index=ot_security sourcetype=labshock:ot:plc
| eval clean_raw=coalesce(raw,message,_raw)
| eval event_type=case(
    like(lower(clean_raw), "%attempting to login%"), "plc_login_attempt",
    like(lower(clean_raw), "%login success%"), "plc_login_success",
    true(), "other"
)
| search event_type IN ("plc_login_attempt","plc_login_success")
| timechart span=10m count by asset_name
```

### 9.2 PLC Lifecycle Events

| Panel | Purpose | Readiness |
|---|---|---|
| PLC start/stop events | Monitor runtime availability | Ready |
| PLC stopped table | Investigate stop events quickly | Ready |
| PLC lifecycle timeline | Correlate start/stop with login sessions | Ready |

Example SPL:

```spl
index=ot_security sourcetype=labshock:ot:plc
| eval clean_raw=coalesce(raw,message,_raw)
| eval clean_raw=replace(clean_raw,"stoped","stopped")
| eval event_type=case(
    like(lower(clean_raw), "%plc started%"), "plc_started",
    like(lower(clean_raw), "%plc stopped%"), "plc_stopped",
    true(), "other"
)
| search event_type IN ("plc_started","plc_stopped")
| table _time asset_name event_type severity clean_raw
| sort - _time
```

---

## 10. Alert candidates

### 10.1 Repeated PLC login attempts

| Field | Value |
|---|---|
| Severity | High |
| Readiness | Ready |
| Logic | More than 20 login attempts in 10 minutes by PLC |

```spl
index=ot_security sourcetype=labshock:ot:plc
| eval clean_raw=coalesce(raw,message,_raw)
| eval event_type=case(
    like(lower(clean_raw), "%attempting to login%"), "plc_login_attempt",
    true(), "other"
)
| search event_type="plc_login_attempt"
| bin _time span=10m
| stats count by _time asset_name
| where count > 20
```

### 10.2 PLC login success

| Field | Value |
|---|---|
| Severity | Medium |
| Readiness | Ready |
| Logic | Any successful PLC login |

```spl
index=ot_security sourcetype=labshock:ot:plc
| eval clean_raw=coalesce(raw,message,_raw)
| search clean_raw="*Login success*"
| rex field=clean_raw "Login success for user:\\s*'(?<plc_user>[^']+)'"
| table _time asset_name plc_user clean_raw
| sort - _time
```

### 10.3 PLC stopped

| Field | Value |
|---|---|
| Severity | High |
| Readiness | Ready |
| Logic | Any PLC stop event |

```spl
index=ot_security sourcetype=labshock:ot:plc
| eval clean_raw=coalesce(raw,message,_raw)
| eval clean_raw=replace(clean_raw,"stoped","stopped")
| search clean_raw="*PLC stopped*"
| table _time asset_name severity event_category message raw clean_raw
| sort - _time
```

### 10.4 PLC stopped after successful login

| Field | Value |
|---|---|
| Severity | Critical |
| Readiness | Partial |
| Logic | Successful login followed by PLC stop within short time window |
| Need | Better session/source attribution |

Conceptual SPL:

```spl
index=ot_security sourcetype=labshock:ot:plc
| eval clean_raw=coalesce(raw,message,_raw)
| eval clean_raw=replace(clean_raw,"stoped","stopped")
| eval event_type=case(
    like(lower(clean_raw), "%login success%"), "plc_login_success",
    like(lower(clean_raw), "%plc stopped%"), "plc_stopped",
    true(), "other"
)
| search event_type IN ("plc_login_success","plc_stopped")
| transaction asset_name startswith=event_type="plc_login_success" endswith=event_type="plc_stopped" maxspan=10m
| table _time asset_name duration eventcount clean_raw
```

---

## 11. Security and operational conclusions

The PLC/OpenPLC source is now mature enough for a first SIEM dashboard and first alert rules. The most valuable confirmed use cases are:

- detecting repeated PLC login attempts;
- auditing successful OpenPLC logins;
- identifying PLC runtime start/stop events;
- correlating PLC stop events with recent successful login activity;
- comparing authentication activity across PLC1–PLC5.

The highest current investigation point is the abnormal number of login attempts on PLC3. This should be analyzed with a `timechart` and, if possible, with source-client attribution.

Recommended next check:

```spl
index=ot_security sourcetype=labshock:ot:plc
| eval clean_raw=coalesce(raw,message,_raw)
| search clean_raw="*Attempting to login*"
| timechart span=1m count by asset_name
```

If PLC3 shows continuous periodic attempts, this may be automated OpenPLC noise or a service behavior. If it appears as a burst, it is more suitable for a brute-force-style alert.

---

## 12. Final status

| Item | Status |
|---|---|
| Source observed in Splunk | Yes |
| Sourcetype confirmed | Yes — `labshock:ot:plc` |
| Login attempt parsing | Validated |
| Login success parsing | Validated |
| User extraction | Validated for `openplc` |
| Logout parsing | Validated |
| Start/stop parsing | Validated |
| Alert readiness | Ready for basic alerts |
| Dashboard readiness | Ready for first version |
| Remaining work | PLC2 validation, source IP extraction, baseline tuning for PLC3 |
