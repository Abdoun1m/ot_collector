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

func TestProtectedEventsNeverDroppedByRule(t *testing.T) {
	e := New()
	e.SetRules([]config.RuleConfig{
		{ID: "drop-firewall", Enabled: true, SourceType: "firewall", Asset: "*", Category: "*", Severity: "*", Operation: "*", Action: "drop"},
	})
	for _, msg := range []string{"firewall_block", "plc_login_attempt", "unauthorized_write", "sensitive_write_accepted"} {
		evt := event.Event{SourceType: "firewall", Message: msg, EventCategory: "security", Tags: map[string]string{}}
		d := e.EvaluateRulesOnly(&evt)
		if d.Drop {
			t.Fatalf("expected protected message %s to not be dropped, got %+v", msg, d)
		}
		if !d.Store {
			t.Fatalf("expected protected message %s to be stored", msg)
		}
	}
}

func TestSourceNoiseControlSCADAHeartbeatSampled(t *testing.T) {
	e := New()
	e.SetRules(nil)
	kept := 0
	dropped := 0
	for i := 0; i < 20; i++ {
		evt := event.Event{SourceType: "scada", Message: "scada_api_heartbeat", AssetIP: "192.168.1.60", Tags: map[string]string{}}
		d := e.EvaluateRulesOnly(&evt)
		if d.Drop {
			dropped++
		} else {
			kept++
		}
	}
	if kept == 0 || dropped == 0 {
		t.Fatalf("expected mixed keep/drop for scada heartbeat, kept=%d dropped=%d", kept, dropped)
	}
}

