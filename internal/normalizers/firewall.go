package normalizers

import (
	"strings"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

func applyFirewall(evt *event.Event, ctx Context) {
	if evt.SourceType != "firewall" {
		return
	}
	if evt.AssetName == "" || strings.EqualFold(evt.AssetName, "unknown") || strings.Contains(strings.ToLower(evt.AssetName), "firewall") {
		evt.AssetName = "OPNsense OT Firewall"
	}

	action := strings.ToLower(strings.TrimSpace(evt.Tags["action"]))
	if action == "" {
		l := strings.ToLower(evt.Message)
		switch {
		case strings.Contains(l, "firewall_block"):
			action = "block"
		case strings.Contains(l, "firewall_reject"):
			action = "reject"
		case strings.Contains(l, "firewall_pass"):
			action = "pass"
		}
	}
	if action != "" {
		evt.Tags["action"] = action
	}

	switch action {
	case "block":
		rewriteMessage(evt, "firewall_block")
		evt.EventCategory = "security"
		if evt.Severity == "info" || evt.Severity == "" {
			evt.Severity = "warning"
		}
	case "reject":
		rewriteMessage(evt, "firewall_reject")
		evt.EventCategory = "security"
		if evt.Severity == "info" || evt.Severity == "" {
			evt.Severity = "warning"
		}
	case "pass":
		rewriteMessage(evt, "firewall_pass")
		if evt.EventCategory == "" || evt.EventCategory == "system" {
			evt.EventCategory = "network_traffic"
		}
	}

	if evt.Tags["src_ip"] != "" {
		evt.Tags["source_ip"] = evt.Tags["src_ip"]
	}
	if evt.Tags["dst_ip"] != "" {
		evt.Tags["destination_ip"] = evt.Tags["dst_ip"]
	}
	_ = ctx
}
