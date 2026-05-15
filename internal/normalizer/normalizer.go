package normalizer

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/sources"
	"github.com/Abdoun1m/ot_collector/internal/syslog"
)

func FromParsed(zone string, p syslog.ParsedMessage, sourceIP string) event.Event {
	if payload := extractStructuredTelemetryJSON(p.Message); payload != nil {
		return fromStructuredTelemetryJSON(sourceIP, zone, p, payload)
	}

	src := sources.Resolve(sourceIP, p.Hostname, p.AppName, p.Message)
	if src.AssetIP == "" {
		src.AssetIP = sourceIP
	}

	tags := map[string]string{
		"syslog_format": p.Format,
		"hostname":      p.Hostname,
		"app_name":      p.AppName,
	}
	enrichOPCUATags(p.Message, tags)

	return event.Event{
		ID:            newID(),
		Timestamp:     p.Timestamp,
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Zone:          zone,
		SourceType:    src.SourceType,
		AssetName:     src.AssetName,
		AssetIP:       src.AssetIP,
		Severity:      classifySeverity(p.Message, p.SeverityNumber),
		Protocol:      "syslog",
		EventCategory: classifyCategory(p.Message),
		Message:       p.Message,
		Raw:           p.Raw,
		Tags:          tags,
	}
}

func extractStructuredTelemetryJSON(message string) map[string]interface{} {
	idx := strings.Index(message, "{")
	if idx < 0 {
		return nil
	}

	candidate := message[idx:]

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(candidate), &payload); err != nil {
		return nil
	}

	if len(payload) == 0 {
		return nil
	}

	for _, key := range []string{"source_type", "component", "event_type", "event_category"} {
		if _, ok := payload[key]; ok {
			return payload
		}
	}

	return nil
}

func fromStructuredTelemetryJSON(sourceIP, zone string, p syslog.ParsedMessage, payload map[string]interface{}) event.Event {
	resolved := sources.Resolve(sourceIP, p.Hostname, p.AppName, p.Message)

	component, _ := scalarToString(payload["component"])
	payloadSourceType, _ := scalarToString(payload["source_type"])
	payloadZone, _ := scalarToString(payload["zone"])
	payloadSeverity, _ := scalarToString(payload["severity"])
	payloadEventCategory, _ := scalarToString(payload["event_category"])
	payloadEventType, _ := scalarToString(payload["event_type"])
	payloadMessage, _ := scalarToString(payload["message"])
	payloadCollectorDecision, _ := scalarToString(payload["collector_decision"])
	payloadAssetIP, _ := scalarToString(payload["asset_ip"])

	sourceType := ""
	if payloadSourceType != "" {
		sourceType = payloadSourceType
	} else if inferredSourceType := inferSourceTypeFromComponent(component); inferredSourceType != "unknown" {
		sourceType = inferredSourceType
	} else if resolved.SourceType != "" {
		sourceType = resolved.SourceType
	}
	if sourceType == "" {
		sourceType = "unknown"
	}

	assetName := resolved.AssetName
	if assetName == "" {
		assetName = inferAssetNameFromComponent(component)
	}

	assetIP := resolved.AssetIP
	if assetIP == "" && sourceIP != "" {
		assetIP = sourceIP
	}
	if assetIP == "" && sourceIP == "" && payloadAssetIP != "" {
		assetIP = payloadAssetIP
	}

	eventZone := payloadZone
	if eventZone == "" {
		eventZone = zone
	}
	if eventZone == "" {
		eventZone = "OT"
	}

	severity := ""
	if payloadSeverity != "" {
		severity = normalizeSeverityText(payloadSeverity)
	}
	if severity == "" && p.Priority != nil {
		severity = normalizeSyslogSeverity(*p.Priority)
	}
	if severity == "" {
		severity = classifySeverity(p.Message, p.SeverityNumber)
	}
	if severity == "" {
		severity = "info"
	}

	eventType := payloadEventType
	if eventType == "" {
		if payloadMessage != "" {
			eventType = payloadMessage
		} else {
			eventType = "structured_telemetry"
		}
	}

	eventCategory := payloadEventCategory
	if eventCategory == "" {
		eventCategory = inferEventCategory(eventType, payload)
	}
	if eventCategory == "" {
		eventCategory = "system_health"
	}

	timestamp := p.Timestamp
	if payloadTimestamp, ok := scalarToString(payload["timestamp"]); ok && payloadTimestamp != "" {
		if parsedTimestamp, ok := parseTelemetryTimestamp(payloadTimestamp); ok {
			timestamp = parsedTimestamp
		}
	}
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	tags := map[string]string{
		"structured_json": "true",
		"syslog_format":   normalizedSyslogFormat(p, p.Message),
	}
	if p.Hostname != "" {
		tags["hostname"] = p.Hostname
	}
	if p.AppName != "" {
		tags["app_name"] = p.AppName
	}
	if component != "" {
		tags["component"] = component
	}
	if eventType != "" {
		tags["event_type"] = eventType
	}
	if payloadCollectorDecision != "" {
		tags["collector_decision_hint"] = payloadCollectorDecision
	}

	copySafeJSONFieldsToTags(tags, payload)

	return event.Event{
		ID:            newID(),
		Timestamp:     timestamp,
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Zone:          eventZone,
		SourceType:    sourceType,
		AssetName:     assetName,
		AssetIP:       assetIP,
		Severity:      severity,
		Protocol:      "syslog",
		EventCategory: eventCategory,
		Message:       eventType,
		Raw:           p.Raw,
		Tags:          tags,
	}
}

func normalizedSyslogFormat(p syslog.ParsedMessage, message string) string {
	switch p.Format {
	case "rfc5424", "rfc3164":
		return p.Format
	case "raw":
		trimmed := strings.TrimSpace(message)
		if trimmed == "" {
			return "unknown"
		}
		if strings.HasPrefix(trimmed, "{") {
			return "raw_json"
		}
		if strings.HasPrefix(trimmed, "<") {
			if end := strings.Index(trimmed, ">"); end > 0 {
				rest := strings.TrimSpace(trimmed[end+1:])
				if isRFC3164Envelope(rest) {
					return "rfc3164"
				}
				if isISOEnvelope(rest) {
					return "iso_syslog"
				}
			}
		}
	}
	return "unknown"
}

func isRFC3164Envelope(message string) bool {
	if len(message) < 3 {
		return false
	}
	switch message[:3] {
	case "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec":
		return true
	default:
		return false
	}
}

func isISOEnvelope(message string) bool {
	if len(message) < 19 {
		return false
	}
	return len(message) >= 11 && message[4] == '-' && message[7] == '-' && message[10] == 'T'
}

func parseTelemetryTimestamp(value string) (string, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC().Format(time.RFC3339Nano), true
		}
	}
	return "", false
}

func normalizeSeverityText(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "trace":
		return "debug"
	case "info", "notice", "":
		return "info"
	case "warn", "warning":
		return "warn"
	case "error", "err":
		return "error"
	case "critical", "crit", "alert", "emergency", "fatal":
		return "critical"
	default:
		return "info"
	}
}

func normalizeSyslogSeverity(priority int) string {
	if priority < 0 {
		return "info"
	}
	switch priority & 0x07 {
	case 0, 1, 2:
		return "critical"
	case 3:
		return "error"
	case 4:
		return "warn"
	case 5, 6:
		return "info"
	case 7:
		return "debug"
	default:
		return "info"
	}
}

func inferSourceTypeFromComponent(component string) string {
	lower := strings.ToLower(component)
	switch {
	case strings.Contains(lower, "opcua"):
		return "opcua"
	case strings.Contains(lower, "gds_agent"), strings.Contains(lower, "gds-agent"):
		return "gds-agent"
	case strings.Contains(lower, "gds"):
		return "gds"
	case strings.Contains(lower, "fuxa"), strings.Contains(lower, "scada"):
		return "scada"
	case strings.Contains(lower, "opnsense"), strings.Contains(lower, "firewall"):
		return "firewall"
	case strings.Contains(lower, "openplc"), strings.Contains(lower, "plc"):
		return "plc"
	case strings.Contains(lower, "ews"):
		return "ews"
	case strings.Contains(lower, "ids"), strings.Contains(lower, "nozomi"):
		return "ids"
	case strings.Contains(lower, "vault"):
		return "vault"
	default:
		return "unknown"
	}
}

func inferAssetNameFromComponent(component string) string {
	lower := strings.ToLower(component)
	switch {
	case component == "powergrid_opcua_server":
		return "OPC UA Server"
	case component == "labshock_ot_gds_agent":
		return "OT GDS Agent"
	case strings.Contains(lower, "fuxa"), strings.Contains(lower, "scada"):
		return "FUXA SCADA"
	case strings.Contains(lower, "opnsense"):
		return "OPNsense OT Firewall"
	case strings.Contains(lower, "vault"):
		return "Vault"
	case strings.Contains(lower, "gds"):
		return "GDS"
	case strings.Contains(lower, "plc"):
		return "PLC"
	case strings.Contains(lower, "ews"):
		return "EWS"
	case strings.Contains(lower, "ids"), strings.Contains(lower, "nozomi"):
		return "IDS"
	default:
		return component
	}
}

func inferEventCategory(eventType string, payload map[string]interface{}) string {
	if category, ok := scalarToString(payload["event_category"]); ok && category != "" {
		return category
	}
	if sensitiveAction, ok := scalarToString(payload["sensitive_action"]); ok && strings.EqualFold(sensitiveAction, "true") {
		return "sensitive_operator_action"
	}

	lowerEventType := strings.ToLower(eventType)
	sourceType, _ := scalarToString(payload["source_type"])
	component, _ := scalarToString(payload["component"])
	componentLower := strings.ToLower(component)
	firewallSource := strings.EqualFold(sourceType, "firewall") || strings.Contains(componentLower, "firewall") || strings.Contains(componentLower, "opnsense")

	switch {
	case containsAny(lowerEventType, "renewal", "renew"):
		return "certificate_lifecycle"
	case containsAny(lowerEventType, "certificate", "pki", "crl", "trust"):
		return "pki_lifecycle"
	case containsAny(lowerEventType, "session"):
		return "session"
	case containsAny(lowerEventType, "auth", "login", "unauthorized", "denied", "rejected"):
		return "access_control"
	case containsAny(lowerEventType, "firewall", "flow", "packet"):
		return "network"
	case strings.Contains(lowerEventType, "connection") && firewallSource:
		return "network"
	case containsAny(lowerEventType, "modbus", "plc"):
		return "data_collection"
	case containsAny(lowerEventType, "policy", "approval", "runtime_write"):
		return "policy_audit"
	case containsAny(lowerEventType, "failed", "failure", "error"):
		return "error"
	case containsAny(lowerEventType, "server", "health", "heartbeat", "recovered"):
		return "system_health"
	default:
		return "system_health"
	}
}

func copySafeJSONFieldsToTags(tags map[string]string, payload map[string]interface{}) {
	if tags == nil || payload == nil {
		return
	}

	for key, value := range payload {
		if isSensitiveKey(key) {
			continue
		}

		stringValue, ok := scalarToString(value)
		if !ok || stringValue == "" {
			continue
		}

		if isStructuredCoreField(key) {
			continue
		}

		targetKey := key
		if _, exists := tags[targetKey]; exists {
			targetKey = "json_" + key
		}
		if _, exists := tags[targetKey]; exists {
			continue
		}
		tags[targetKey] = stringValue
	}
}

func isStructuredCoreField(key string) bool {
	switch key {
	case "source_type", "zone", "severity", "event_category", "message", "timestamp":
		return true
	default:
		return false
	}
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, needle := range []string{
		"token",
		"secret",
		"password",
		"passwd",
		"private_key",
		"unseal_key",
		"client_secret",
		"secret_id",
		"refresh_token",
		"access_token",
		"authorization",
		"cookie",
		"api_key",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func scalarToString(v interface{}) (string, bool) {
	switch typed := v.(type) {
	case string:
		return typed, true
	case bool:
		if typed {
			return "true", true
		}
		return "false", true
	case float64:
		return fmt.Sprintf("%v", typed), true
	case nil:
		return "", false
	default:
		return "", false
	}
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}