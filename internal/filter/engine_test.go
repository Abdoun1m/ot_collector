package filter

import (
	"testing"

	"github.com/Abdoun1m/ot_collector/internal/config"
	"github.com/Abdoun1m/ot_collector/internal/event"
)

func TestRuleDrop(t *testing.T) {
	e := New()
	e.SetRules([]config.RuleConfig{
		{ID: "r1", Enabled: true, SourceType: "opcua", Asset: "*", Category: "operator_action", Severity: "*", Operation: "READ", Action: "drop"},
	})
	evt := event.Event{SourceType: "opcua", EventCategory: "operator_action", Tags: map[string]string{"opcua_operation": "READ"}}
	d := e.Evaluate(&evt)
	if !d.Drop {
		t.Fatal("expected drop decision")
	}
}

func TestRuleKeep(t *testing.T) {
	e := New()
	e.SetRules([]config.RuleConfig{
		{ID: "r1", Enabled: true, SourceType: "opcua", Asset: "*", Category: "operator_action", Severity: "*", Operation: "WRITE", Action: "keep", StoreLocally: true, ForwardToDMZ: true},
	})
	evt := event.Event{SourceType: "opcua", EventCategory: "operator_action", Tags: map[string]string{"opcua_operation": "WRITE"}}
	d := e.Evaluate(&evt)
	if !d.Store || !d.Forward || d.Drop {
		t.Fatalf("expected store+forward keep decision, got %+v", d)
	}
}

