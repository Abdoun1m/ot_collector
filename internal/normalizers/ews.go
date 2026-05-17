package normalizers

import (
	"strings"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

func applyEWS(evt *event.Event, _ Context) {
	if evt.SourceType != "ews" {
		return
	}
	if evt.AssetName == "" || strings.EqualFold(evt.AssetName, "unknown") {
		evt.AssetName = "Engineering Workstation"
	}
	if evt.AssetIP == "" {
		evt.AssetIP = "192.168.1.50"
	}

	l := strings.ToLower(cleanMessagePrefix(evt.Message))
	switch {
	case strings.Contains(l, "suspicious_file_change"):
		rewriteMessage(evt, "ews_suspicious_file_change")
		evt.EventCategory = "security"
		evt.Severity = "warning"
	case strings.Contains(l, "collector_send_failed"):
		rewriteMessage(evt, "collector_send_failed")
		evt.EventCategory = "error"
		evt.Severity = "warning"
	case strings.Contains(l, "collector_send_recovered"):
		rewriteMessage(evt, "collector_send_recovered")
		evt.EventCategory = "system_health"
		evt.Severity = "info"
	case strings.Contains(l, "private_key_access_attempt_or_skip"):
		rewriteMessage(evt, "private_key_access_attempt_or_skip")
		evt.EventCategory = "security"
		evt.Severity = "warning"
	case strings.Contains(l, "ews_heartbeat"):
		rewriteMessage(evt, "ews_heartbeat")
		evt.EventCategory = "system_health"
		evt.Tags["noise_hint"] = "sample_candidate"
	}
}
