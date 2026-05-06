package normalizer

import (
	"testing"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/syslog"
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

func intPtr(v int) *int {
	return &v
}
