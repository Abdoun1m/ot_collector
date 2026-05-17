package normalizer

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/normalizers"
	"github.com/Abdoun1m/ot_collector/internal/sources"
	"github.com/Abdoun1m/ot_collector/internal/syslog"
)

func FromParsed(zone string, p syslog.ParsedMessage, sourceIP string) event.Event {
	resolved := sources.Resolve(sourceIP, p.Hostname, p.AppName, p.Message)

	if payload := extractStructuredTelemetryJSON(p.Message); payload != nil {
		evt := fromStructuredTelemetryJSON(sourceIP, zone, p, payload)
		return normalizers.Apply(evt, normalizers.Context{Parsed: p, SourceIP: sourceIP})
	}
	if evt, ok := parseOPNsenseFilterlog(zone, p, sourceIP, resolved); ok {
		return normalizers.Apply(evt, normalizers.Context{Parsed: p, SourceIP: sourceIP})
	}

	src := resolved
	if src.AssetIP == "" {
		src.AssetIP = sourceIP
	}

	tags := map[string]string{
		"syslog_format": p.Format,
		"hostname":      p.Hostname,
		"app_name":      p.AppName,
	}
	enrichOPCUATags(p.Message, tags)

	evt := event.Event{
		ID:            event.NewID(),
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

	return normalizers.Apply(evt, normalizers.Context{Parsed: p, SourceIP: sourceIP})
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
		ID:            event.NewID(),
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
			if parsed.IsZero() {
				return "", false
			}
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
		return "gds_agent"
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

		targetKey := key
		if isStructuredCoreField(key) {
			targetKey = "json_" + key
		}
		if _, exists := tags[targetKey]; exists {
			targetKey = "json_" + key
		}
		if _, exists := tags[targetKey]; exists {
			continue
		}
		tags[targetKey] = stringValue
	}
}

func parseOPNsenseFilterlog(zone string, p syslog.ParsedMessage, sourceIP string, resolved sources.SourceInfo) (event.Event, bool) {
	if !looksLikeFilterlog(p) && resolved.SourceType != "firewall" {
		return event.Event{}, false
	}

	body := stripFilterlogStructuredData(p.Message)
	trimmedBody := strings.TrimSpace(body)
	tags := map[string]string{
		"firewall_vendor":  "opnsense",
		"firewall_backend": "pf",
		"firewall_daemon":  "filterlog",
		"structured_json":  "false",
		"syslog_format":    p.Format,
	}
	if p.Hostname != "" {
		tags["hostname"] = p.Hostname
	}
	if p.AppName != "" {
		tags["app_name"] = p.AppName
	}

	assetName := resolved.AssetName
	if assetName == "" {
		assetName = "OPNsense OT Firewall"
	}
	assetIP := resolved.AssetIP
	if assetIP == "" {
		assetIP = sourceIP
	}

	evt := event.Event{
		ID:         event.NewID(),
		Timestamp:  p.Timestamp,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Zone:       zone,
		SourceType: "firewall",
		AssetName:  assetName,
		AssetIP:    assetIP,
		Severity:   "info",
		Protocol:   "syslog",
		Message:    "firewall_event",
		Raw:        p.Raw,
		Tags:       tags,
	}
	if evt.Zone == "" {
		evt.Zone = "OT"
	}

	if trimmedBody == "" || !isDigit(trimmedBody[0]) {
		tags["parse_warning"] = "missing filterlog csv payload"
		evt.EventCategory = "error"
		evt.Severity = "error"
		return evt, true
	}

	parsed, parseWarning := parseFilterlogCSV(trimmedBody)
	for key, value := range parsed.tags {
		tags[key] = value
	}
	if parsed.action != "" {
		tags["action"] = parsed.action
	}
	if parsed.direction != "" {
		tags["direction"] = parsed.direction
	}
	if parsed.reason != "" {
		tags["reason"] = parsed.reason
	}
	if parseWarning != "" {
		tags["parse_warning"] = parseWarning
	}

	action := strings.ToLower(parsed.action)
	direction := strings.ToLower(parsed.direction)
	reason := strings.ToLower(parsed.reason)
	dstPort := parsed.tags["dst_port"]

	if action == "block" || action == "reject" {
		evt.SourceType = "firewall"
		evt.EventCategory = "security"
		evt.Severity = "warn"
		if action == "reject" {
			evt.Message = "firewall_reject"
		} else {
			evt.Message = "firewall_block"
		}
	} else {
		evt.SourceType = "firewall"
		evt.EventCategory = "network"
		evt.Severity = "info"
		evt.Message = "firewall_pass"
	}

	if strings.Contains(reason, "bad") || parseWarning != "" {
		evt.EventCategory = "error"
		evt.Severity = "error"
		evt.Message = "firewall_event"
	}

	if hint := protocolHintFromPort(dstPort); hint != "" {
		tags["protocol_hint"] = hint
	}
	if isHighValueFirewallEvent(action, dstPort, direction) {
		tags["high_value_firewall_event"] = "true"
		tags["mitre_ics_tactic"] = "Initial Access"
		tags["mitre_ics_technique_hint"] = "Unauthorized Access Attempt"
	}

	return evt, true
}

type filterlogParseResult struct {
	action    string
	reason    string
	direction string
	tags      map[string]string
}

func parseFilterlogCSV(body string) (filterlogParseResult, string) {
	reader := csv.NewReader(strings.NewReader(body))
	reader.FieldsPerRecord = -1
	record, err := reader.Read()
	if err != nil {
		return filterlogParseResult{tags: map[string]string{}}, "invalid filterlog csv"
	}

	result := filterlogParseResult{tags: map[string]string{}}
	if len(record) < 9 {
		for i := range record {
			if record[i] != "" {
				result.tags["field_"+strconv.Itoa(i)] = record[i]
			}
		}
		return result, "short filterlog csv"
	}

	put := func(index int, key string) {
		if index >= 0 && index < len(record) && record[index] != "" {
			result.tags[key] = record[index]
		}
	}

	put(0, "rule_number")
	put(1, "sub_rule_number")
	put(2, "anchor")
	put(3, "tracker")
	put(4, "interface")
	result.reason = record[5]
	result.action = record[6]
	result.direction = record[7]
	put(8, "ip_version")

	if record[8] == "4" {
		parseFilterlogIPv4(record, result.tags)
	} else if record[8] == "6" {
		parseFilterlogIPv6(record, result.tags)
	} else {
		return result, "unknown ip_version"
	}

	return result, ""
}

func parseFilterlogIPv4(record []string, tags map[string]string) {
	put := func(index int, key string) {
		if index >= 0 && index < len(record) && record[index] != "" {
			tags[key] = record[index]
		}
	}
	protocolName := ""
	if len(record) > 16 {
		protocolName = strings.ToLower(record[16])
	}
	put(9, "tos")
	put(10, "ecn")
	put(11, "ttl")
	put(12, "ip_id")
	put(13, "offset")
	put(14, "ip_flags")
	put(15, "protocol_id")
	put(16, "protocol_name")
	put(17, "packet_length")
	put(18, "src_ip")
	put(19, "dst_ip")
	put(20, "src_port")
	put(21, "dst_port")
	put(22, "data_length")
	if len(record) > 23 && protocolName == "tcp" {
		put(23, "tcp_flags")
		put(24, "tcp_sequence")
		put(25, "tcp_ack")
		put(26, "tcp_window")
		put(27, "tcp_urg")
		if len(record) > 28 {
			options := strings.TrimSpace(strings.Join(record[28:], ","))
			if options != "" {
				tags["tcp_options"] = options
			}
		}
	}
	if protocolName == "icmp" {
		put(20, "icmp_type")
		put(21, "icmp_id")
		put(22, "icmp_sequence")
		for i := 23; i < len(record); i++ {
			if record[i] != "" {
				tags["icmp_detail_"+strconv.Itoa(i-23)] = record[i]
			}
		}
	}
}

func parseFilterlogIPv6(record []string, tags map[string]string) {
	put := func(index int, key string) {
		if index >= 0 && index < len(record) && record[index] != "" {
			tags[key] = record[index]
		}
	}
	protocolName := ""
	if len(record) > 12 {
		protocolName = strings.ToLower(record[12])
	}
	put(9, "traffic_class")
	put(10, "flow_label")
	put(11, "hop_limit")
	put(12, "protocol_name")
	put(13, "protocol_id")
	put(14, "packet_length")
	put(15, "src_ip")
	put(16, "dst_ip")
	put(17, "src_port")
	put(18, "dst_port")
	put(19, "data_length")
	if len(record) > 20 && protocolName == "tcp" {
		put(20, "tcp_flags")
		put(21, "tcp_sequence")
		put(22, "tcp_ack")
		put(23, "tcp_window")
		put(24, "tcp_urg")
		if len(record) > 25 {
			options := strings.TrimSpace(strings.Join(record[25:], ","))
			if options != "" {
				tags["tcp_options"] = options
			}
		}
	}
	if protocolName == "icmpv6" {
		put(17, "icmp_type")
		for i := 18; i < len(record); i++ {
			if record[i] != "" {
				tags["icmp_detail_"+strconv.Itoa(i-18)] = record[i]
			}
		}
	}
}

func stripFilterlogStructuredData(message string) string {
	trimmed := strings.TrimSpace(message)
	lastBracket := strings.LastIndex(trimmed, "]")
	if lastBracket < 0 {
		return trimmed
	}
	openBracket := strings.LastIndex(trimmed[:lastBracket], "[")
	if openBracket < 0 {
		return trimmed
	}
	return strings.TrimSpace(trimmed[lastBracket+1:])
}

func looksLikeFilterlog(p syslog.ParsedMessage) bool {
	lowerApp := strings.ToLower(p.AppName)
	lowerHost := strings.ToLower(p.Hostname)
	if strings.Contains(lowerApp, "filterlog") || strings.Contains(lowerHost, "opnsense") {
		return true
	}
	body := stripFilterlogStructuredData(p.Message)
	if body == "" || !isDigit(body[0]) {
		return false
	}
	reader := csv.NewReader(strings.NewReader(body))
	reader.FieldsPerRecord = -1
	record, err := reader.Read()
	if err != nil || len(record) < 9 {
		return false
	}
	action := strings.ToLower(record[6])
	return action == "pass" || action == "block" || action == "reject"
}

func protocolHintFromPort(port string) string {
	switch port {
	case "4840":
		return "opcua"
	case "502":
		return "modbus"
	case "102":
		return "s7comm"
	case "20000":
		return "dnp3"
	case "44818":
		return "enip"
	case "22":
		return "ssh"
	case "443", "8443":
		return "https"
	case "53":
		return "dns"
	case "80", "8080":
		return "http"
	case "8200":
		return "vault"
	case "8088":
		return "collector"
	case "1883", "1884":
		return "mqtt"
	default:
		return ""
	}
}

func isHighValueFirewallEvent(action, dstPort, direction string) bool {
	if direction != "in" {
		return false
	}
	if action != "block" && action != "reject" {
		return false
	}
	switch dstPort {
	case "4840", "502", "22", "443", "8443", "8200", "8088", "1883", "1884", "102", "20000", "44818":
		return true
	default:
		return false
	}
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
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

