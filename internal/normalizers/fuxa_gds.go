package normalizers

import (
	"strings"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

func applyFUXAGDSClient(evt *event.Event, _ Context) {
	if evt.SourceType != "scada_gds_client" {
		return
	}
	if evt.AssetName == "" || strings.EqualFold(evt.AssetName, "unknown") {
		evt.AssetName = "FUXA SCADA GDS Client"
	}
	if evt.AssetIP == "" {
		evt.AssetIP = "192.168.1.60"
	}

	l := strings.ToLower(cleanMessagePrefix(evt.Message))
	switch {
	case containsAny(l, "trust_signature_invalid"):
		rewriteMessage(evt, "trust_signature_invalid")
		evt.EventCategory = "security"
		evt.Severity = "error"
	case containsAny(l, "crl_freshness_failed"):
		rewriteMessage(evt, "crl_freshness_failed")
		evt.EventCategory = "pki_lifecycle"
		evt.Severity = "error"
	case containsAny(l, "private_key_changed"):
		rewriteMessage(evt, "private_key_changed")
		evt.EventCategory = "security"
		evt.Severity = "critical"
	}
}
