package normalizers

import (
	"strings"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

func applyGDSAgent(evt *event.Event, _ Context) {
	if evt.SourceType != "gds_agent" {
		return
	}
	if evt.AssetName == "" || strings.EqualFold(evt.AssetName, "unknown") {
		evt.AssetName = "OT GDS Agent"
	}

	l := strings.ToLower(cleanMessagePrefix(evt.Message))
	switch {
	case containsAny(l, "certificate_expiry_critical"):
		rewriteMessage(evt, "certificate_expiry_critical")
		evt.EventCategory = "pki_validation"
		evt.Severity = "critical"
	case containsAny(l, "certificate_inventory_drift_detected"):
		rewriteMessage(evt, "certificate_inventory_drift_detected")
		evt.EventCategory = "pki_validation"
	case containsAny(l, "gds_cert_missing_runtime"):
		rewriteMessage(evt, "gds_cert_missing_runtime")
		evt.EventCategory = "pki_validation"
		evt.Severity = "warning"
	case containsAny(l, "gds_telemetry_pulled"):
		rewriteMessage(evt, "gds_telemetry_pulled")
		evt.EventCategory = "pki_trust_sync"
		evt.Tags["noise_hint"] = "sample_candidate"
	case containsAny(l, "sync_cycle_success"):
		rewriteMessage(evt, "sync_cycle_success")
		evt.EventCategory = "pki_trust_sync"
		evt.Tags["noise_hint"] = "rate_limit_candidate"
	case containsAny(l, "sync_cycle_failure"):
		rewriteMessage(evt, "sync_cycle_failure")
		evt.EventCategory = "gds_agent_error"
		evt.Severity = "warning"
	case containsAny(l, "trustlist_diff_detected"):
		rewriteMessage(evt, "trustlist_diff_detected")
		evt.EventCategory = "trustlist_diff"
	case containsAny(l, "critical_diff_detected"):
		rewriteMessage(evt, "critical_diff_detected")
		evt.EventCategory = "gds_agent_error"
		evt.Severity = "critical"
	case containsAny(l, "ca_chain_changed"):
		rewriteMessage(evt, "ca_chain_changed")
		evt.EventCategory = "pki_validation"
		evt.Severity = "warning"
	case containsAny(l, "crl_changed"):
		rewriteMessage(evt, "crl_changed")
		evt.EventCategory = "pki_validation"
		evt.Severity = "warning"
	case containsAny(l, "activation_gate_ready"):
		rewriteMessage(evt, "activation_gate_ready")
		evt.EventCategory = "pki_trust_sync"
	case containsAny(l, "activation_gate_denied"):
		rewriteMessage(evt, "activation_gate_denied")
		evt.EventCategory = "pki_validation"
		evt.Severity = "warning"
	case containsAny(l, "package_runtime_activated"):
		rewriteMessage(evt, "package_runtime_activated")
		evt.EventCategory = "pki_trust_sync"
	case containsAny(l, "revocation_dry_run_created"):
		rewriteMessage(evt, "revocation_dry_run_created")
		evt.EventCategory = "pki_validation"
	}
}
