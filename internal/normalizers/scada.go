package normalizers

import (
	"regexp"
	"strings"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

var (
	scadaLinePrefixRE       = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\S+\s+\[(\w+)\]\s+`)
	scadaQuotedConnectRE    = regexp.MustCompile(`(?i)'([^']+)'\s+try to connect\s+([0-9.]+)`)
	scadaQuotedConnectedRE  = regexp.MustCompile(`(?i)'([^']+)'\s+connected!`)
	scadaReadMemoryErrRE    = regexp.MustCompile(`(?i)'([^']+)'\s+_readmemory\s+error!`)
	scadaECONNRefusedRE     = regexp.MustCompile(`(?i)connect\s+econnrefused\s+([0-9.]+):(\d+)`)
	scadaOPCUASessionRE     = regexp.MustCompile(`(?i)'opcua'\s+warning\s*=>\s*session\s+closed`)
	scadaOPCUASubscribeRE   = regexp.MustCompile(`(?i)'opcua'\s+subscription\s+created!`)
	scadaOPCUAConnLostRE    = regexp.MustCompile(`(?i)'opcua'\s+connection\s+lost!`)
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

	rawClean := cleanMessagePrefix(evt.Message)
	rawNoPrefix := rawClean
	l := strings.ToLower(rawClean)
	if m := scadaLinePrefixRE.FindStringSubmatch(l); len(m) > 1 {
		l = scadaLinePrefixRE.ReplaceAllString(l, "")
		rawNoPrefix = scadaLinePrefixRE.ReplaceAllString(rawNoPrefix, "")
		// Preserve parsed severity unless it's generic info and line prefix gives better context.
		if evt.Severity == "info" {
			switch strings.ToLower(m[1]) {
			case "error", "err":
				evt.Severity = "error"
			case "warn", "warning":
				evt.Severity = "warning"
			}
		}
	}

	switch {
	case containsAny(l, "fuxa started"):
		rewriteMessage(evt, "scada_runtime_started")
		evt.EventCategory = "system_health"
	case scadaReadMemoryErrRE.MatchString(l):
		rewriteMessage(evt, "scada_plc_read_memory_error")
		evt.EventCategory = "data_collection"
		if evt.Severity == "info" || evt.Severity == "" {
			evt.Severity = "error"
		}
		match := scadaReadMemoryErrRE.FindStringSubmatch(rawNoPrefix)
		if len(match) > 1 {
			evt.Tags["target"] = strings.TrimSpace(match[1])
		}
	case scadaQuotedConnectRE.MatchString(l):
		rewriteMessage(evt, "scada_plc_connection_attempt")
		evt.EventCategory = "data_collection"
		match := scadaQuotedConnectRE.FindStringSubmatch(rawNoPrefix)
		if len(match) > 2 {
			evt.Tags["target"] = strings.TrimSpace(match[1])
			evt.Tags["target_ip"] = strings.TrimSpace(match[2])
		}
	case scadaQuotedConnectedRE.MatchString(l):
		match := scadaQuotedConnectedRE.FindStringSubmatch(rawNoPrefix)
		target := ""
		if len(match) > 1 {
			target = strings.TrimSpace(match[1])
			evt.Tags["target"] = target
		}
		if strings.EqualFold(target, "opcua") {
			rewriteMessage(evt, "scada_opcua_connected")
		} else {
			rewriteMessage(evt, "scada_plc_connected")
		}
		evt.EventCategory = "data_collection"
	case strings.Contains(l, "'plc1' connected"):
		rewriteMessage(evt, "scada_plc_connected")
		evt.EventCategory = "data_collection"
		evt.Tags["target"] = "PLC1"
	case scadaOPCUASubscribeRE.MatchString(l) || strings.Contains(l, "'opcua' subscription created"):
		rewriteMessage(evt, "scada_opcua_subscription_created")
		evt.EventCategory = "data_collection"
		evt.Tags["target"] = "opcua"
	case scadaOPCUAConnLostRE.MatchString(l):
		rewriteMessage(evt, "scada_opcua_connection_lost")
		evt.EventCategory = "data_collection"
		evt.Severity = "error"
		evt.Tags["target"] = "opcua"
		evt.Tags["alert_candidate"] = "true"
	case scadaOPCUASessionRE.MatchString(l):
		rewriteMessage(evt, "scada_opcua_session_closed")
		evt.EventCategory = "data_collection"
		evt.Severity = "warning"
		evt.Tags["target"] = "opcua"
	case scadaECONNRefusedRE.MatchString(l):
		rewriteMessage(evt, "scada_plc_connection_refused")
		evt.EventCategory = "data_collection"
		evt.Severity = "error"
		match := scadaECONNRefusedRE.FindStringSubmatch(rawNoPrefix)
		if len(match) > 2 {
			evt.Tags["target_ip"] = strings.TrimSpace(match[1])
			evt.Tags["target_port"] = strings.TrimSpace(match[2])
		}
	case containsAny(l, "working (connection || polling) overload", "polling overload"):
		rewriteMessage(evt, "scada_polling_overload")
		evt.EventCategory = "data_collection"
		evt.Severity = "warning"
		evt.Tags["noise_hint"] = "sample_candidate"
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
