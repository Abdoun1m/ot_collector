package normalizers

import (
	"strings"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

func applySCADA(evt *event.Event, _ Context) {
	if evt.SourceType != "scada" {
		return
	}
	if evt.AssetName == "" || strings.EqualFold(evt.AssetName, "unknown") {
		evt.AssetName = "FUXA SCADA"
	}
	if evt.AssetIP == "" {
		evt.AssetIP = "192.168.1.60"
	}

	l := strings.ToLower(cleanMessagePrefix(evt.Message))
	switch {
	case containsAny(l, "fuxa started"):
		rewriteMessage(evt, "scada_runtime_started")
		evt.EventCategory = "system_health"
	case strings.Contains(l, "'plc1' connected"):
		rewriteMessage(evt, "scada_plc_connected")
		evt.EventCategory = "data_collection"
	case strings.Contains(l, "'opcua' connected"):
		rewriteMessage(evt, "scada_opcua_connected")
		evt.EventCategory = "data_collection"
	case strings.Contains(l, "'opcua' subscription created"):
		rewriteMessage(evt, "scada_opcua_subscription_created")
		evt.EventCategory = "data_collection"
	case containsAny(l, "load.script", "script load error"):
		rewriteMessage(evt, "scada_script_load_error")
		evt.EventCategory = "error"
		evt.Severity = "error"
	case containsAny(l, "connection_break", "opcua connection break"):
		rewriteMessage(evt, "scada_opcua_connection_break")
		evt.EventCategory = "pki_validation"
		evt.Severity = "warning"
	case containsAny(l, "san mismatch", "node-opcua-w06"):
		rewriteMessage(evt, "scada_opcua_certificate_san_mismatch")
		evt.EventCategory = "pki_validation"
		evt.Severity = "warning"
	case containsAny(l, "runtime.update-project: restart", "runtime restart"):
		rewriteMessage(evt, "scada_runtime_restart")
		evt.EventCategory = "project_activity"
	case containsAny(l, "settings updated", "server settings changed"):
		rewriteMessage(evt, "scada_settings_updated")
		evt.EventCategory = "operator_action"
	case containsAny(l, "user created"):
		rewriteMessage(evt, "scada_user_created")
		evt.EventCategory = "access_control"
	case containsAny(l, "connection timeout", "transaction timeout"):
		rewriteMessage(evt, "scada_connection_timeout")
		evt.EventCategory = "data_collection"
		evt.Severity = "warning"
	case containsAny(l, "validation ping"):
		evt.Tags["test_event"] = "true"
		evt.Tags["noise_hint"] = "drop_candidate"
	}

	if containsAny(evt.Message,
		"scada_api_heartbeat",
		"scada_forwarder_heartbeat",
		"daqstorage",
		"plugin-installed",
		"scada_socket_client_connected") {
		evt.Tags["noise_hint"] = "sample_candidate"
	}
}
