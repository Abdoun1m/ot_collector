package normalizers

import (
	"strings"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

func applyOPCUA(evt *event.Event, _ Context) {
	if evt.SourceType != "opcua" {
		return
	}
	if evt.AssetName == "" || strings.EqualFold(evt.AssetName, "unknown") || evt.AssetName == "powergrid_opcua_server" {
		evt.AssetName = "OPC UA Server"
	}

	msg := strings.ToLower(cleanMessagePrefix(evt.Message))
	if evt.Tags["event_type"] != "" {
		rewriteMessage(evt, evt.Tags["event_type"])
	}

	switch {
	case containsAny(msg, "server startup", "server_startup"):
		rewriteMessage(evt, "server_startup")
		evt.EventCategory = "system_health"
	case containsAny(msg, "server ready", "server_ready"):
		rewriteMessage(evt, "server_ready")
		evt.EventCategory = "system_health"
	case containsAny(msg, "modbus connection failed", "modbus_connection_failed"):
		rewriteMessage(evt, "modbus_connection_failed")
		evt.EventCategory = "data_collection"
		evt.Severity = "error"
	case containsAny(msg, "modbus connection recovered", "modbus_connection_recovered"):
		rewriteMessage(evt, "modbus_connection_recovered")
		evt.EventCategory = "system_health"
	case containsAny(msg, "modbus_write_failed"):
		rewriteMessage(evt, "modbus_write_failed")
		evt.EventCategory = "error"
		evt.Severity = "error"
	case containsAny(msg, "unauthorized_write"):
		rewriteMessage(evt, "unauthorized_write")
		evt.EventCategory = "access_control"
		evt.Severity = "warning"
	case containsAny(msg, "sensitive_write_accepted"):
		rewriteMessage(evt, "sensitive_write_accepted")
		evt.EventCategory = "sensitive_operator_action"
	case containsAny(msg, "opcua_write_rejected"):
		rewriteMessage(evt, "opcua_write_rejected")
		evt.EventCategory = "error"
		evt.Severity = "error"
	case containsAny(msg, "session_activated"):
		rewriteMessage(evt, "session_activated")
		evt.EventCategory = "session"
	case containsAny(msg, "unexpected_anonymous_session"):
		rewriteMessage(evt, "unexpected_anonymous_session")
		evt.EventCategory = "access_control"
		evt.Severity = "warning"
	case containsAny(msg, "abnormal_session_close"):
		rewriteMessage(evt, "abnormal_session_close")
		evt.EventCategory = "session"
		evt.Severity = "warning"
	case containsAny(msg, "certificate_verified"):
		rewriteMessage(evt, "certificate_verified")
		evt.EventCategory = "pki_lifecycle"
	case containsAny(msg, "pki_load_failed"):
		rewriteMessage(evt, "pki_load_failed")
		evt.EventCategory = "pki_lifecycle"
		evt.Severity = "critical"
	}
}
