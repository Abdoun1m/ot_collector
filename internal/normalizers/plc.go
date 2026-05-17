package normalizers

import (
	"regexp"
	"strings"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

var plcUserRE = regexp.MustCompile(`(?i)login success for user:\s*'([^']+)'`)

func applyPLC(evt *event.Event, _ Context) {
	if evt.SourceType != "plc" {
		return
	}

	if evt.AssetName == "" || strings.EqualFold(evt.AssetName, "unknown") || strings.HasPrefix(strings.ToLower(evt.AssetName), "labshock-plc") {
		switch evt.AssetIP {
		case "192.168.1.20":
			evt.AssetName = "PLC1"
		case "192.168.1.21":
			evt.AssetName = "PLC2"
		case "192.168.1.22":
			evt.AssetName = "PLC3"
		case "192.168.1.23":
			evt.AssetName = "PLC4"
		case "192.168.1.24":
			evt.AssetName = "PLC5"
		}
	}

	clean := strings.ToLower(cleanMessagePrefix(evt.Message))
	clean = strings.ReplaceAll(clean, "stoped", "stopped")

	switch {
	case strings.Contains(clean, "attempting to login"):
		rewriteMessage(evt, "plc_login_attempt")
		evt.EventCategory = "access_control"
		evt.Severity = "info"
	case strings.Contains(clean, "login success"):
		rewriteMessage(evt, "plc_login_success")
		evt.EventCategory = "access_control"
		evt.Severity = "info"
		if m := plcUserRE.FindStringSubmatch(cleanMessagePrefix(evt.Message)); len(m) > 1 {
			evt.Tags["plc_user"] = m[1]
		}
	case strings.Contains(clean, "user logout"):
		rewriteMessage(evt, "plc_user_logout")
		evt.EventCategory = "operator_action"
		evt.Severity = "info"
	case strings.Contains(clean, "plc started"):
		rewriteMessage(evt, "plc_started")
		evt.EventCategory = "system"
		evt.Severity = "info"
	case strings.Contains(clean, "plc stopped"):
		rewriteMessage(evt, "plc_stopped")
		evt.EventCategory = "system"
		evt.Severity = "warning"
	}
}
