package normalizers

import (
	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/syslog"
)

type Context struct {
	Parsed   syslog.ParsedMessage
	SourceIP string
}

// Apply enriches and normalizes events based on source-specific rules derived
// from logs_by_source documentation, while preserving upstream parser behavior.
func Apply(in event.Event, ctx Context) event.Event {
	evt := in
	ensureBaseTags(&evt)
	canonicalizeSourceIdentity(&evt, ctx)
	normalizeSeverity(&evt)

	applyFirewall(&evt, ctx)
	applyPLC(&evt, ctx)
	applySCADA(&evt, ctx)
	applyEWS(&evt, ctx)
	applyOPCUA(&evt, ctx)
	applyGDSAgent(&evt, ctx)
	applyFUXAGDSClient(&evt, ctx)

	setSourcetype(&evt)
	markAlertCandidate(&evt)
	setDecisionHint(&evt)

	if evt.AssetIP == "" {
		evt.AssetIP = ctx.SourceIP
	}
	if evt.Message == "" {
		evt.Message = "unknown_event"
	}
	if evt.EventCategory == "" {
		evt.EventCategory = "system"
	}
	if evt.SourceType == "" {
		evt.SourceType = "unknown"
	}
	if evt.AssetName == "" {
		evt.AssetName = "unknown"
	}
	if evt.Severity == "" {
		evt.Severity = "info"
	}

	return evt
}
