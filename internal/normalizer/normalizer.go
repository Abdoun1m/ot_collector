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
	if payload, ok := extractStructuredTelemetryJSON(p.Message); ok {
		return fromStructuredTelemetryJSON(zone, p, sourceIP, payload)
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

func extractStructuredTelemetryJSON(message string) (map[string]interface{}, bool) {
	idx := strings.Index(message, "{")
	if idx < 0 {
		return nil, false
	}

	candidate := strings.TrimSpace(message[idx:])

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(candidate), &payload); err != nil {
		return nil, false
	}

	if _, ok := stringValue(payload, "source_type"); !ok {
		return nil, false
	}

	return payload, true
}

func fromStructuredTelemetryJSON(zone string, p syslog.ParsedMessage, sourceIP string, payload map[string]interface{}) event.Event {
	sourceType := stringValueOr(payload, "source_type", "unknown")
	component := stringValueOr(payload, "component", p.AppName)
	eventZone := stringValueOr(payload, "zone", zone)
	severity := stringValueOr(payload, "severity", "info")
	eventCategory := stringValueOr(payload, "event_category", "system")
	eventType := stringValueOr(payload, "event_type", "structured_telemetry")

	tags := map[string]string{
		"syslog_format":       p.Format,
		"hostname":            p.Hostname,
		"app_name":            p.AppName,
		"structured_json":     "true",
		"component":           component,
		"event_type":          eventType,
		"collector_decision_hint": stringValueOr(payload, "collector_decision", ""),
	}

	for _, k := range []string{
		"reason",
		"opcua_operation",
		"client_application_uri",
		"client_certificate_fingerprint_sha256",
		"user",
		"node_id",
		"browse_name",
		"display_name",
		"plc_name",
		"plc_ip",
		"modbus_port",
		"status",
		"error_code",
		"target",
		"application_uri",
	} {
		if v, ok := stringValue(payload, k); ok && v != "" {
			tags[k] = v
		}
	}

	assetName := component
	if component == "powergrid_opcua_server" {
		assetName = "OPC UA Server"
	}
	assetIP := sourceIP
	if sourceType == "opcua" && sourceIP == "" {
		assetIP = "192.168.1.62"
	}

	return event.Event{
		ID:            newID(),
		Timestamp:     stringValueOr(payload, "timestamp", p.Timestamp),
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

func stringValueOr(payload map[string]interface{}, key string, fallback string) string {
	if v, ok := stringValue(payload, key); ok && v != "" {
		return v
	}
	return fallback
}

func stringValue(payload map[string]interface{}, key string) (string, bool) {
	v, ok := payload[key]
	if !ok || v == nil {
		return "", false
	}

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
	default:
		return fmt.Sprintf("%v", typed), true
	}
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}