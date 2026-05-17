package normalizers

import (
	"regexp"
	"strings"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

const parserVersion = "v2.logs_by_sources_md"

var syslogPrefixRE = regexp.MustCompile(`^<\d+>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d\s+`)

func ensureBaseTags(evt *event.Event) {
	if evt.Tags == nil {
		evt.Tags = map[string]string{}
	}
	evt.Tags["parser_version"] = parserVersion
	evt.Tags["normalized"] = "true"
	evt.Tags["normalization_source"] = "logs_by_sources_md"
	evt.Tags["siem_index_hint"] = "ot_security"
}

func canonicalizeSourceIdentity(evt *event.Event, ctx Context) {
	evt.SourceType = strings.TrimSpace(strings.ToLower(evt.SourceType))
	switch evt.SourceType {
	case "gds-agent":
		evt.SourceType = "gds_agent"
	case "gds":
		evt.SourceType = "gds_agent"
	}

	if evt.SourceType == "unknown" || evt.SourceType == "" {
		h := strings.ToLower(ctx.Parsed.Hostname + " " + ctx.Parsed.AppName + " " + evt.Message)
		switch {
		case strings.Contains(h, "opnsense") || strings.Contains(h, "filterlog"):
			evt.SourceType = "firewall"
		case strings.Contains(h, "openplc") || strings.Contains(h, "plc"):
			evt.SourceType = "plc"
		case strings.Contains(h, "fuxa"):
			evt.SourceType = "scada"
		case strings.Contains(h, "engineering") || strings.Contains(h, "ews"):
			evt.SourceType = "ews"
		case strings.Contains(h, "opcua"):
			evt.SourceType = "opcua"
		case strings.Contains(h, "gds"):
			evt.SourceType = "gds_agent"
		}
	}

	if evt.AssetIP == "" {
		evt.AssetIP = ctx.SourceIP
	}
}

func normalizeSeverity(evt *event.Event) {
	original := strings.TrimSpace(evt.Severity)
	l := strings.ToLower(original)
	norm := l
	switch l {
	case "warn", "warning", "war":
		norm = "warning"
	case "err", "error":
		norm = "error"
	case "inf", "info":
		norm = "info"
	case "critical":
		norm = "critical"
	case "":
		norm = "info"
	}
	evt.Severity = norm
	if original != "" && !strings.EqualFold(original, norm) {
		evt.Tags["original_severity"] = original
	}
}

func setSourcetype(evt *event.Event) {
	sourcetype := ""
	switch evt.SourceType {
	case "firewall":
		sourcetype = "labshock:net:firewall"
	case "plc":
		sourcetype = "labshock:ot:plc"
	case "scada":
		sourcetype = "labshock:ot:scada"
	case "ews":
		sourcetype = "labshock:ot:ews"
	case "opcua":
		sourcetype = "labshock:ot:opcua"
	case "gds_agent":
		sourcetype = "labshock:ot:gds"
	case "scada_gds_client":
		sourcetype = "labshock:ot:scada:gds"
	}
	if sourcetype != "" {
		evt.Tags["splunk_sourcetype"] = sourcetype
	}
}

func setDecisionHint(evt *event.Event) {
	if evt.Tags["collector_decision_hint"] != "" {
		return
	}
	switch evt.Severity {
	case "critical", "error", "warning":
		evt.Tags["collector_decision_hint"] = "store_forward"
	default:
		evt.Tags["collector_decision_hint"] = "sample_or_drop"
	}
}

func markAlertCandidate(evt *event.Event) {
	switch evt.Message {
	case "firewall_block",
		"plc_login_success",
		"plc_login_attempt",
		"plc_stopped",
		"scada_opcua_connection_break",
		"scada_script_load_error",
		"scada_user_created",
		"scada_settings_updated",
		"scada_runtime_restart",
		"scada_opcua_certificate_san_mismatch",
		"ews_suspicious_file_change",
		"private_key_access_attempt_or_skip",
		"unauthorized_write",
		"sensitive_write_accepted",
		"modbus_connection_failed",
		"certificate_expiry_critical",
		"gds_cert_missing_runtime",
		"trust_signature_invalid",
		"crl_freshness_failed",
		"private_key_changed":
		evt.Tags["alert_candidate"] = "true"
	}
}

func cleanMessagePrefix(s string) string {
	trimmed := strings.TrimSpace(s)
	trimmed = syslogPrefixRE.ReplaceAllString(trimmed, "")
	return strings.TrimSpace(trimmed)
}

func rewriteMessage(evt *event.Event, message string) {
	message = strings.TrimSpace(message)
	if message == "" || evt.Message == message {
		return
	}
	evt.Tags["original_message"] = evt.Message
	evt.Message = message
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
