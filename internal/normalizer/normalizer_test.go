package normalizer

import (
	"strings"
	"testing"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/syslog"
	"github.com/Abdoun1m/ot_collector/internal/sources"
)

func TestOPCUAReadCommandEnrichment(t *testing.T) {
	msg := `[OPCUA] [READ][CMD] User=admin NodeId=ns=2;i=1214 Browse=Vanne4 Display=Vanne4 Mode=MAINTAINED Value=false`
	parsed := syslog.ParsedMessage{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hostname:  "powergrid-opcua",
		AppName:   "powergrid_opcua_server",
		Message:   msg,
		Raw:       msg,
		Format:    "raw",
	}

	evt := FromParsed("OT", parsed, "192.168.1.62")
	if evt.EventCategory != "operator_read" {
		t.Fatalf("expected operator_read, got %s", evt.EventCategory)
	}
	if evt.Tags["opcua_operation"] != "READ" {
		t.Fatalf("expected opcua_operation=READ, got %q", evt.Tags["opcua_operation"])
	}
	if evt.Tags["opcua_event_type"] != "CMD" {
		t.Fatalf("expected opcua_event_type=CMD, got %q", evt.Tags["opcua_event_type"])
	}
	if evt.Tags["user"] != "admin" {
		t.Fatalf("expected user=admin, got %q", evt.Tags["user"])
	}
	if evt.Tags["node_id"] != "ns=2;i=1214" {
		t.Fatalf("expected node_id=ns=2;i=1214, got %q", evt.Tags["node_id"])
	}
	if evt.Tags["browse_name"] != "Vanne4" {
		t.Fatalf("expected browse_name=Vanne4, got %q", evt.Tags["browse_name"])
	}
	if evt.Tags["display_name"] != "Vanne4" {
		t.Fatalf("expected display_name=Vanne4, got %q", evt.Tags["display_name"])
	}
	if evt.Tags["mode"] != "MAINTAINED" {
		t.Fatalf("expected mode=MAINTAINED, got %q", evt.Tags["mode"])
	}
	if evt.Tags["value"] != "false" {
		t.Fatalf("expected value=false, got %q", evt.Tags["value"])
	}
	if evt.Tags["sensitive_action"] != "true" {
		t.Fatalf("expected sensitive_action=true, got %q", evt.Tags["sensitive_action"])
	}
}

func TestOPCUAWriteCommandCategory(t *testing.T) {
	msg := `[OPCUA] [WRITE][CMD] User=admin NodeId=ns=2;i=1214 Browse=Vanne4 Display=Vanne4 Mode=MAINTAINED Value=true`
	parsed := syslog.ParsedMessage{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Message:   msg,
		Raw:       msg,
		Format:    "raw",
	}
	evt := FromParsed("OT", parsed, "192.168.1.62")
	if evt.EventCategory != "operator_write" {
		t.Fatalf("expected operator_write, got %s", evt.EventCategory)
	}
}

func TestOPCUAStartupClassification(t *testing.T) {
	msg := `[OPCUA] [STARTUP] Server started on opc.tcp://192.168.1.62:4840`
	parsed := syslog.ParsedMessage{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Message:        msg,
		Raw:            msg,
		Format:         "raw",
		SeverityNumber: intPtr(4),
	}
	evt := FromParsed("OT", parsed, "192.168.1.62")
	if evt.EventCategory != "runtime" {
		t.Fatalf("expected runtime, got %s", evt.EventCategory)
	}
	if evt.Severity != "info" {
		t.Fatalf("expected info, got %s", evt.Severity)
	}
}

func TestOPCUASessionClassification(t *testing.T) {
	msg := `[OPCUA] [SESSION] Client session created from 192.168.10.20`
	parsed := syslog.ParsedMessage{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Message:   msg,
		Raw:       msg,
		Format:    "raw",
	}
	evt := FromParsed("OT", parsed, "192.168.1.62")
	if evt.EventCategory != "network" {
		t.Fatalf("expected network, got %s", evt.EventCategory)
	}
}

func TestOPCUARejectedSecurityClassification(t *testing.T) {
	msg := `[OPCUA] [SECURITY] Rejected connection from 192.168.1.99 invalid certificate`
	parsed := syslog.ParsedMessage{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Message:   msg,
		Raw:       msg,
		Format:    "raw",
	}
	evt := FromParsed("OT", parsed, "192.168.1.62")
	if evt.EventCategory != "security" {
		t.Fatalf("expected security, got %s", evt.EventCategory)
	}
	if evt.Severity != "warning" && evt.Severity != "error" {
		t.Fatalf("expected warning or error, got %s", evt.Severity)
	}
	if evt.Tags["mitre_ics_tactic"] == "" {
		t.Fatal("expected mitre_ics_tactic tag to exist")
	}
}

func TestNonOPCUAFUXAUnchanged(t *testing.T) {
	msg := `[INFO] FUXA init successful`
	parsed := syslog.ParsedMessage{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Message:   msg,
		Raw:       msg,
		Format:    "raw",
	}
	evt := FromParsed("OT", parsed, "192.168.1.60")
	if evt.SourceType != "scada" {
		t.Fatalf("expected scada source type, got %s", evt.SourceType)
	}
	if evt.Tags["opcua_event_type"] != "" {
		t.Fatalf("unexpected opcua_event_type tag for non-opcua message: %q", evt.Tags["opcua_event_type"])
	}
}

func TestStructuredTelemetryNormalization(t *testing.T) {
	fixedTimestamp := "2026-05-15T10:42:25Z"
	tests := []struct {
		name              string
		raw               string
		priority          *int
		format            string
		hostname          string
		appName           string
		sourceIP          string
		parsedTimestamp    string
		wantSourceType     string
		wantEventCategory  string
		wantSeverity       string
		wantMessage        string
		wantZone           string
		wantSyslogFormat   string
		wantTimestamp      string
		wantTags           map[string]string
		wantAbsentTags     []string
		wantExtractNil     bool
		wantLegacyNodeID   string
	}{
		{
			name: "opcua_certificate_verified",
			raw: `<134>2026-05-15T10:42:25Z powergrid-opcua powergrid_opcua_server: {"source_type":"opcua","component":"powergrid_opcua_server","zone":"OT","event_category":"pki_lifecycle","severity":"info","event_type":"certificate_verified","timestamp":"2026-05-15T10:42:25Z","collector_decision":"forward","reason":"new_certificate","opcua_operation":"PKI","status":"Good"}`,
			priority: intPtr(134),
			format: "raw",
			hostname: "powergrid-opcua",
			appName: "powergrid_opcua_server",
			sourceIP: "192.168.1.62",
			parsedTimestamp: fixedTimestamp,
			wantSourceType: "opcua",
			wantEventCategory: "pki_lifecycle",
			wantSeverity: "info",
			wantMessage: "certificate_verified",
			wantZone: "OT",
			wantSyslogFormat: "iso_syslog",
			wantTags: map[string]string{
				"structured_json": "true",
				"status": "Good",
			},
		},
		{
			name: "opcua_session_activated",
			raw: `<134>2026-05-15T10:42:25Z powergrid-opcua powergrid_opcua_server: {"source_type":"opcua","event_category":"session","severity":"info","event_type":"session_activated","component":"powergrid_opcua_server","zone":"OT","timestamp":"2026-05-15T10:42:25Z","collector_decision":"forward","reason":"new_session","user":"historian"}`,
			priority: intPtr(134),
			format: "raw",
			hostname: "powergrid-opcua",
			appName: "powergrid_opcua_server",
			sourceIP: "192.168.1.62",
			parsedTimestamp: fixedTimestamp,
			wantSourceType: "opcua",
			wantEventCategory: "session",
			wantSeverity: "info",
			wantMessage: "session_activated",
			wantZone: "OT",
			wantSyslogFormat: "iso_syslog",
			wantTags: map[string]string{
				"structured_json": "true",
				"user": "historian",
			},
		},
		{
			name: "plc_modbus_connection_failed",
			raw: `<131>2026-05-15T10:42:25Z powergrid-opcua powergrid_opcua_server: {"source_type":"plc","component":"powergrid_opcua_server","event_category":"data_collection","severity":"error","event_type":"modbus_connection_failed","plc_name":"PLC1","plc_ip":"192.168.1.20","modbus_port":"502","error_code":"modbus_connect_failed","timestamp":"2026-05-15T10:42:25Z"}`,
			priority: intPtr(131),
			format: "raw",
			hostname: "powergrid-opcua",
			appName: "powergrid_opcua_server",
			sourceIP: "192.168.1.62",
			parsedTimestamp: fixedTimestamp,
			wantSourceType: "plc",
			wantEventCategory: "data_collection",
			wantSeverity: "error",
			wantMessage: "modbus_connection_failed",
			wantZone: "OT",
			wantSyslogFormat: "iso_syslog",
			wantTags: map[string]string{
				"structured_json": "true",
				"plc_name": "PLC1",
				"error_code": "modbus_connect_failed",
			},
		},
		{
			name: "gds_agent_runtime_write_deprecated_use_native_client",
			raw: `<132>2026-05-15T11:00:00Z ot-agent labshock_ot_gds_agent: {"source_type":"gds-agent","component":"labshock_ot_gds_agent","zone":"OT","event_category":"policy_audit","severity":"warn","event_type":"runtime_write_deprecated_use_native_client","target":"opcua-server","collector_decision":"forward","reason":"runtime write blocked","timestamp":"2026-05-15T11:00:00Z"}`,
			priority: intPtr(132),
			format: "raw",
			hostname: "ot-agent",
			appName: "labshock_ot_gds_agent",
			sourceIP: "192.168.1.60",
			parsedTimestamp: fixedTimestamp,
			wantSourceType: "gds-agent",
			wantEventCategory: "policy_audit",
			wantSeverity: "warn",
			wantMessage: "runtime_write_deprecated_use_native_client",
			wantZone: "OT",
			wantSyslogFormat: "iso_syslog",
			wantTags: map[string]string{
				"structured_json": "true",
				"target": "opcua-server",
			},
		},
		{
			name: "opnsense_firewall_block",
			raw: `<132>2026-05-15T11:00:00Z opnsense opnsense: {"source_type":"firewall","component":"opnsense","zone":"OT","event_category":"network","severity":"warn","event_type":"firewall_block","src_ip":"192.168.20.10","dst_ip":"192.168.1.62","dst_port":"4840","action":"block","rule":"deny_it_to_ot_opcua","timestamp":"2026-05-15T11:00:00Z"}`,
			priority: intPtr(132),
			format: "raw",
			hostname: "opnsense",
			appName: "opnsense",
			sourceIP: "192.168.1.254",
			parsedTimestamp: fixedTimestamp,
			wantSourceType: "firewall",
			wantEventCategory: "network",
			wantSeverity: "warn",
			wantMessage: "firewall_block",
			wantZone: "OT",
			wantSyslogFormat: "iso_syslog",
			wantTags: map[string]string{
				"structured_json": "true",
				"src_ip": "192.168.20.10",
				"action": "block",
			},
		},
		{
			name: "rfc5424_nilvalue_legacy_compatibility",
			raw: `<134>1 2026-05-15T10:42:25Z powergrid-opcua powergrid_opcua_server - - - {"source_type":"opcua","event_type":"server_startup","severity":"info","event_category":"system_health","component":"powergrid_opcua_server","zone":"OT","timestamp":"2026-05-15T10:42:25Z"}`,
			priority: intPtr(134),
			format: "rfc5424",
			hostname: "powergrid-opcua",
			appName: "powergrid_opcua_server",
			sourceIP: "192.168.1.62",
			parsedTimestamp: fixedTimestamp,
			wantSourceType: "opcua",
			wantEventCategory: "system_health",
			wantSeverity: "info",
			wantMessage: "server_startup",
			wantZone: "OT",
			wantSyslogFormat: "rfc5424",
			wantTags: map[string]string{
				"structured_json": "true",
			},
		},
		{
			name: "fuxa_trust_apply_failed",
			raw: `<131>2026-05-15T10:42:25Z fuxa-host labshock_scada: {"source_type":"scada","component":"labshock_scada","zone":"OT","event_category":"pki_lifecycle","severity":"error","event_type":"trust_apply_failed","reason":"cert not in trust list","timestamp":"2026-05-15T10:42:25Z"}`,
			priority: intPtr(131),
			format: "raw",
			hostname: "fuxa-host",
			appName: "labshock_scada",
			sourceIP: "192.168.1.60",
			parsedTimestamp: fixedTimestamp,
			wantSourceType: "scada",
			wantEventCategory: "pki_lifecycle",
			wantSeverity: "error",
			wantMessage: "trust_apply_failed",
			wantZone: "OT",
			wantSyslogFormat: "iso_syslog",
			wantTags: map[string]string{
				"structured_json": "true",
				"reason": "cert not in trust list",
			},
		},
		{
			name: "sensitive_key_filtering",
			raw: `<132>2026-05-15T11:00:00Z ot-agent labshock_ot_gds_agent: {"source_type":"gds-agent","event_type":"secret_test","severity":"warn","event_category":"security","token":"abc123","secret_id":"def456","private_key":"rsakey","access_token":"bearer_xyz","safe_field":"visible_value","timestamp":"2026-05-15T11:00:00Z"}`,
			priority: intPtr(132),
			format: "raw",
			hostname: "ot-agent",
			appName: "labshock_ot_gds_agent",
			sourceIP: "192.168.1.60",
			parsedTimestamp: fixedTimestamp,
			wantSourceType: "gds-agent",
			wantEventCategory: "security",
			wantSeverity: "warn",
			wantMessage: "secret_test",
			wantZone: "OT",
			wantSyslogFormat: "iso_syslog",
			wantTags: map[string]string{
				"structured_json": "true",
				"safe_field": "visible_value",
			},
			wantAbsentTags: []string{"token", "secret_id", "private_key", "access_token"},
		},
		{
			name: "missing_event_category_inferred",
			raw: `{"source_type":"opcua","event_type":"certificate_renewal_completed","severity":"info","component":"powergrid_opcua_server","zone":"OT","timestamp":"2026-05-15T10:42:25Z"}`,
			format: "raw",
			hostname: "powergrid-opcua",
			appName: "powergrid_opcua_server",
			sourceIP: "192.168.1.62",
			parsedTimestamp: fixedTimestamp,
			wantSourceType: "opcua",
			wantEventCategory: "certificate_lifecycle",
			wantSeverity: "info",
			wantMessage: "certificate_renewal_completed",
			wantZone: "OT",
			wantSyslogFormat: "raw_json",
			wantTags: map[string]string{
				"structured_json": "true",
			},
		},
		{
			name: "missing_timestamp_falls_back_to_parsed_syslog_timestamp",
			raw: `{"source_type":"opcua","event_type":"certificate_verified","severity":"info","event_category":"pki_lifecycle","component":"powergrid_opcua_server","zone":"OT"}`,
			format: "raw",
			hostname: "powergrid-opcua",
			appName: "powergrid_opcua_server",
			sourceIP: "192.168.1.62",
			parsedTimestamp: fixedTimestamp,
			wantSourceType: "opcua",
			wantEventCategory: "pki_lifecycle",
			wantSeverity: "info",
			wantMessage: "certificate_verified",
			wantZone: "OT",
			wantSyslogFormat: "raw_json",
			wantTimestamp: fixedTimestamp,
			wantTags: map[string]string{
				"structured_json": "true",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed := syslog.ParsedMessage{
				Priority:  tc.priority,
				Timestamp: tc.parsedTimestamp,
				Hostname:  tc.hostname,
				AppName:   tc.appName,
				Message:   tc.raw,
				Raw:       tc.raw,
				Format:    tc.format,
			}

			payload := extractStructuredTelemetryJSON(tc.raw)
			if tc.wantExtractNil {
				if payload != nil {
					t.Fatalf("expected no structured payload, got %#v", payload)
				}
			} else if payload == nil {
				t.Fatalf("expected structured payload")
			}

			didPanic := false
			func() {
				defer func() {
					if r := recover(); r != nil {
						didPanic = true
					}
				}()
				_ = FromParsed("OT", parsed, tc.sourceIP)
			}()
			if didPanic {
				t.Fatalf("FromParsed panicked for %s", tc.name)
			}

			evt := FromParsed("OT", parsed, tc.sourceIP)
			if tc.wantExtractNil {
				if evt.Tags["structured_json"] != "" {
					t.Fatalf("expected legacy path, got structured_json tag %q", evt.Tags["structured_json"])
				}
				if tc.wantLegacyNodeID != "" {
					if evt.Tags["node_id"] != tc.wantLegacyNodeID {
						t.Fatalf("expected node_id=%q, got %q", tc.wantLegacyNodeID, evt.Tags["node_id"])
					}
				}
				return
			}

			if evt.SourceType != tc.wantSourceType {
				t.Fatalf("expected source_type=%s, got %s", tc.wantSourceType, evt.SourceType)
			}
			if evt.EventCategory != tc.wantEventCategory {
				t.Fatalf("expected event_category=%s, got %s", tc.wantEventCategory, evt.EventCategory)
			}
			if evt.Severity != tc.wantSeverity {
				t.Fatalf("expected severity=%s, got %s", tc.wantSeverity, evt.Severity)
			}
			if evt.Message != tc.wantMessage {
				t.Fatalf("expected message=%s, got %s", tc.wantMessage, evt.Message)
			}
			if evt.Zone != tc.wantZone {
				t.Fatalf("expected zone=%s, got %s", tc.wantZone, evt.Zone)
			}
			if tc.wantSyslogFormat != "" && evt.Tags["syslog_format"] != tc.wantSyslogFormat {
				t.Fatalf("expected syslog_format=%s, got %s", tc.wantSyslogFormat, evt.Tags["syslog_format"])
			}
			if tc.wantTimestamp != "" && evt.Timestamp != tc.wantTimestamp {
				t.Fatalf("expected timestamp=%s, got %s", tc.wantTimestamp, evt.Timestamp)
			}
			for key, want := range tc.wantTags {
				if got := evt.Tags[key]; got != want {
					t.Fatalf("expected tag %s=%q, got %q", key, want, got)
				}
			}
			for _, key := range tc.wantAbsentTags {
				if _, ok := evt.Tags[key]; ok {
					t.Fatalf("expected tag %s to be filtered out", key)
				}
			}
			if tc.name == "rfc5424_nilvalue_legacy_compatibility" {
				for key, value := range evt.Tags {
					if strings.HasPrefix(value, "- {") {
						t.Fatalf("unexpected prefixed JSON in tag %s: %q", key, value)
					}
				}
			}
		})
	}
}

func TestStructuredTelemetryFallbacks(t *testing.T) {
	tests := []struct {
		name            string
		raw             string
		format          string
		wantExtractNil   bool
		wantNodeID      string
	}{
		{
			name: "legacy_sync_cmd",
			raw:   `<134>May 15 10:42:25 powergrid-opcua powergrid_opcua_server: [OPCUA] [SYNC][CMD] NodeId=ns=2;i=1159 BrowseName=DCY Value=1`,
			format: "rfc3164",
			wantExtractNil: true,
			wantNodeID: "ns=2;i=1159",
		},
		{
			name: "malformed_json_falls_back",
			raw:   `<134>2026-05-15T10:42:25Z powergrid-opcua powergrid_opcua_server: {not valid json at all`,
			format: "raw",
			wantExtractNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed := syslog.ParsedMessage{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Hostname:  "powergrid-opcua",
				AppName:   "powergrid_opcua_server",
				Message:   tc.raw,
				Raw:       tc.raw,
				Format:    tc.format,
			}

			if payload := extractStructuredTelemetryJSON(tc.raw); payload != nil {
				t.Fatalf("expected nil structured payload, got %#v", payload)
			}

			didPanic := false
			func() {
				defer func() {
					if r := recover(); r != nil {
						didPanic = true
					}
				}()
				_ = FromParsed("OT", parsed, "192.168.1.62")
			}()
			if didPanic {
				t.Fatalf("FromParsed panicked for %s", tc.name)
			}

			evt := FromParsed("OT", parsed, "192.168.1.62")
			if tc.wantNodeID != "" && evt.Tags["node_id"] != tc.wantNodeID {
				t.Fatalf("expected node_id=%q, got %q", tc.wantNodeID, evt.Tags["node_id"])
			}
			if evt.Tags["structured_json"] != "" {
				t.Fatalf("expected legacy path, got structured_json tag %q", evt.Tags["structured_json"])
			}
		})
	}
}

func TestOPNsenseFilterlogNormalization(t *testing.T) {
	tests := []struct {
		name                 string
		raw                  string
		format               string
		hostname             string
		appName              string
		sourceIP             string
		wantSourceType       string
		wantEventCategory    string
		wantSeverity         string
		wantMessage          string
		wantContainsTags     map[string]string
		wantAbsentTags       []string
		wantSyslogFormatPart string
	}{
		{
			name:   "bsd_udp_pass_dns",
			raw:    `<134>Jul 16 06:36:52 firewall.local filterlog[40156]: 85,,,9f96d956119c2514,bridge0,match,pass,out,4,0x0,,64,63281,0,DF,17,udp,52,10.0.0.5,8.8.8.8,36444,53,32`,
			format: "rfc3164",
			hostname: "firewall.local",
			appName: "filterlog",
			wantSourceType: "firewall",
			wantEventCategory: "network",
			wantSeverity: "info",
			wantMessage: "firewall_pass",
			wantContainsTags: map[string]string{
				"rule_number": "85",
				"tracker": "9f96d956119c2514",
				"interface": "bridge0",
				"action": "pass",
				"direction": "out",
				"ip_version": "4",
				"protocol_name": "udp",
				"src_ip": "10.0.0.5",
				"dst_ip": "8.8.8.8",
				"src_port": "36444",
				"dst_port": "53",
				"data_length": "32",
				"firewall_vendor": "opnsense",
			},
		},
		{
			name:   "bsd_tcp_block_syn",
			raw:    `<134>Jul 16 06:36:52 firewall.local filterlog[40156]: 101,,,1000000103,igb1,match,block,in,4,0x0,,63,26567,0,DF,6,tcp,60,192.168.1.100,10.0.0.10,40234,443,0,S,3917296601,,64240,,mss`,
			format: "rfc3164",
			hostname: "firewall.local",
			appName: "filterlog",
			wantSourceType: "firewall",
			wantEventCategory: "security",
			wantSeverity: "warn",
			wantMessage: "firewall_block",
			wantContainsTags: map[string]string{
				"rule_number": "101",
				"action": "block",
				"direction": "in",
				"protocol_name": "tcp",
				"src_ip": "192.168.1.100",
				"dst_ip": "10.0.0.10",
				"src_port": "40234",
				"dst_port": "443",
				"tcp_flags": "S",
				"tcp_sequence": "3917296601",
				"tcp_window": "64240",
				"tcp_options": "mss",
				"protocol_hint": "https",
				"high_value_firewall_event": "true",
				"mitre_ics_tactic": "Initial Access",
			},
		},
		{
			name:   "rfc5424_structured_data_block",
			raw:    `<134>1 2024-08-05T12:05:54+00:00 firewall.local filterlog 54802 - [meta sequenceId="2763892"] 101,,,1000000103,igb1,match,block,in,4,0x0,,63,26567,0,DF,6,tcp,60,192.168.1.100,10.0.0.10,40234,443,0,S,3917296601,,64240,,mss`,
			format: "rfc5424",
			hostname: "firewall.local",
			appName: "filterlog",
			wantSourceType: "firewall",
			wantEventCategory: "security",
			wantSeverity: "warn",
			wantMessage: "firewall_block",
			wantContainsTags: map[string]string{
				"rule_number": "101",
				"action": "block",
				"direction": "in",
				"dst_port": "443",
				"protocol_hint": "https",
				"high_value_firewall_event": "true",
			},
			wantSyslogFormatPart: "rfc5424",
		},
		{
			name:   "ipv4_opcua_block",
			raw:    `<134>Jul 16 06:36:52 firewall.local filterlog[40156]: 202,,,deadbeef,igb1,match,block,in,4,0x0,,64,1234,0,DF,6,tcp,60,10.20.0.5,192.168.1.62,54321,4840,0,S,111111111,,65535,,mss`,
			format: "rfc3164",
			hostname: "firewall.local",
			appName: "filterlog",
			wantSourceType: "firewall",
			wantEventCategory: "security",
			wantSeverity: "warn",
			wantMessage: "firewall_block",
			wantContainsTags: map[string]string{
				"dst_port": "4840",
				"protocol_hint": "opcua",
				"high_value_firewall_event": "true",
				"mitre_ics_tactic": "Initial Access",
			},
		},
		{
			name:   "ipv6_udp_pass",
			raw:    `<134>Jul 16 06:36:52 firewall.local filterlog[40156]: 85,,,abcdef1234,em0,match,pass,out,6,0x00,0x00000,64,udp,17,52,2001:db8::1,2001:db8::2,5353,5353,32`,
			format: "rfc3164",
			hostname: "firewall.local",
			appName: "filterlog",
			wantSourceType: "firewall",
			wantEventCategory: "network",
			wantSeverity: "info",
			wantMessage: "firewall_pass",
			wantContainsTags: map[string]string{
				"ip_version": "6",
				"protocol_name": "udp",
				"src_ip": "2001:db8::1",
				"dst_ip": "2001:db8::2",
				"src_port": "5353",
				"dst_port": "5353",
			},
		},
		{
			name:   "short_filterlog_csv",
			raw:    `<134>Jul 16 06:36:52 firewall.local filterlog[40156]: 85,,,tracker,bridge0,match,block`,
			format: "rfc3164",
			hostname: "firewall.local",
			appName: "filterlog",
			wantSourceType: "firewall",
			wantEventCategory: "error",
			wantSeverity: "error",
			wantMessage: "firewall_event",
			wantContainsTags: map[string]string{
				"parse_warning": "short filterlog csv",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed := syslog.ParsedMessage{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Hostname:  tc.hostname,
				AppName:   tc.appName,
				Message:   tc.raw,
				Raw:       tc.raw,
				Format:    tc.format,
			}

			evt := FromParsed("OT", parsed, tc.sourceIP)
			if evt.SourceType != tc.wantSourceType {
				t.Fatalf("expected source_type=%s, got %s", tc.wantSourceType, evt.SourceType)
			}
			if evt.EventCategory != tc.wantEventCategory {
				t.Fatalf("expected event_category=%s, got %s", tc.wantEventCategory, evt.EventCategory)
			}
			if evt.Severity != tc.wantSeverity {
				t.Fatalf("expected severity=%s, got %s", tc.wantSeverity, evt.Severity)
			}
			if evt.Message != tc.wantMessage {
				t.Fatalf("expected message=%s, got %s", tc.wantMessage, evt.Message)
			}
			for key, want := range tc.wantContainsTags {
				if got := evt.Tags[key]; got != want {
					t.Fatalf("expected tag %s=%q, got %q", key, want, got)
				}
			}
			for _, key := range tc.wantAbsentTags {
				if _, ok := evt.Tags[key]; ok {
					t.Fatalf("expected tag %s to be absent", key)
				}
			}
			if tc.wantSyslogFormatPart != "" && !strings.Contains(evt.Tags["syslog_format"], tc.wantSyslogFormatPart) {
				t.Fatalf("expected syslog_format to contain %q, got %q", tc.wantSyslogFormatPart, evt.Tags["syslog_format"])
			}
			if tc.name == "rfc5424_structured_data_block" {
				for key, value := range evt.Tags {
					if strings.Contains(value, "[meta") || strings.Contains(value, "sequenceId") {
						t.Fatalf("unexpected structured-data artifact in tag %s=%q", key, value)
					}
				}
			}
		})
	}
}

func TestLegacyRoutingAndHelperGuards(t *testing.T) {
	raw := `[OPCUA] [SYNC][CMD] NodeId=ns=2;i=1159 BrowseName=DCY Value=1`
	parsed := syslog.ParsedMessage{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hostname:  "powergrid-opcua",
		AppName:   "powergrid_opcua_server",
		Message:   raw,
		Raw:       raw,
		Format:    "raw",
	}
	if payload := extractStructuredTelemetryJSON(raw); payload != nil {
		t.Fatalf("expected nil structured payload, got %#v", payload)
	}
	if evt, ok := parseOPNsenseFilterlog("OT", parsed, "192.168.1.62", sources.Resolve("192.168.1.62", parsed.Hostname, parsed.AppName, parsed.Message)); ok {
		t.Fatalf("expected filterlog parser to reject legacy OPC UA text, got %#v", evt)
	}
	evt := FromParsed("OT", parsed, "192.168.1.62")
	if evt.Tags["browse_name"] != "DCY" {
		t.Fatalf("expected browse_name=DCY, got %q", evt.Tags["browse_name"])
	}
	if evt.Tags["sensitive_action"] != "true" {
		t.Fatalf("expected sensitive_action=true, got %q", evt.Tags["sensitive_action"])
	}
}

func intPtr(v int) *int {
	return &v
}
