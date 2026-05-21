package filter

import (
	"path/filepath"
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

func TestExplicitMatrixRuleCanDropSecurityEvents(t *testing.T) {
	e := New()
	e.SetRules([]config.RuleConfig{
		{ID: "drop-firewall", Enabled: true, SourceType: "firewall", Asset: "*", Category: "*", Severity: "*", Operation: "*", Action: "drop"},
	})
	for _, msg := range []string{"firewall_block", "plc_login_attempt", "unauthorized_write", "sensitive_write_accepted"} {
		evt := event.Event{SourceType: "firewall", Message: msg, EventCategory: "security", Tags: map[string]string{}}
		d := e.Evaluate(&evt)
		if !d.Drop {
			t.Fatalf("expected explicit matrix drop for %s, got %+v", msg, d)
		}
	}
}

func TestRuleMatrixSCADAHeartbeatSampled(t *testing.T) {
	e := New()
	e.SetRules([]config.RuleConfig{
		{
			ID: "sample-scada", Enabled: true,
			SourceType: "scada", Asset: "*", Category: "*", Severity: "*", Operation: "*",
			MessageContains: "scada_api_heartbeat",
			Action:          "sample", SampleRate: 0.1, StoreLocally: true, ForwardToDMZ: false,
		},
	})
	kept := 0
	dropped := 0
	for i := 0; i < 20; i++ {
		evt := event.Event{SourceType: "scada", Message: "scada_api_heartbeat", AssetIP: "192.168.1.60", Tags: map[string]string{}}
		d := e.Evaluate(&evt)
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

func TestRuleLevelDedupDrop(t *testing.T) {
	e := New()
	e.SetRules([]config.RuleConfig{
		{
			ID: "dedup", Enabled: true,
			SourceType: "ews", Asset: "*", Category: "*", Severity: "*", Operation: "*",
			Action: "store_only", StoreLocally: true, DedupWindowSeconds: 60,
		},
	})
	evt := event.Event{SourceType: "ews", AssetIP: "192.168.1.50", Message: "ews_heartbeat", Tags: map[string]string{}}
	if d := e.Evaluate(&evt); d.Drop {
		t.Fatalf("first event should be kept, got %+v", d)
	}
	if d := e.Evaluate(&evt); !d.Drop || d.Reason != "rule_duplicate_window" || d.MatchedRuleID != "dedup" {
		t.Fatalf("second event should be rule duplicate drop, got %+v", d)
	}
}

func TestRuleLevelRateLimit(t *testing.T) {
	e := New()
	e.SetRules([]config.RuleConfig{
		{
			ID: "rate", Enabled: true,
			SourceType: "firewall", Asset: "*", Category: "*", Severity: "*", Operation: "*",
			Action: "store_only", StoreLocally: true, RateLimitPerSecond: 1,
		},
	})
	evt := event.Event{SourceType: "firewall", AssetIP: "192.168.1.254", Message: "firewall_pass", Tags: map[string]string{}}
	if d := e.Evaluate(&evt); d.Drop {
		t.Fatalf("first event should be kept, got %+v", d)
	}
	if d := e.Evaluate(&evt); !d.Drop || d.Reason != "rule_rate_limit" || d.MatchedRuleID != "rate" {
		t.Fatalf("second event should be rule rate limited, got %+v", d)
	}
}

func TestFirstMatchingRuleWins(t *testing.T) {
	e := New()
	e.SetRules([]config.RuleConfig{
		{ID: "first", Enabled: true, SourceType: "opcua", Asset: "*", Category: "*", Severity: "*", Operation: "*", Action: "store_only", StoreLocally: true},
		{ID: "second", Enabled: true, SourceType: "opcua", Asset: "*", Category: "*", Severity: "*", Operation: "*", Action: "drop"},
	})
	d := e.Evaluate(&event.Event{SourceType: "opcua", Tags: map[string]string{}})
	if d.MatchedRuleID != "first" || d.Drop {
		t.Fatalf("first rule should win, got %+v", d)
	}
}

func TestDefaultFirewallPassRuleBeatsGenericErrorForward(t *testing.T) {
	store, err := config.NewRuleStore(filepath.Join(t.TempDir(), "rules.json"))
	if err != nil {
		t.Fatalf("new rule store: %v", err)
	}
	e := New()
	e.SetRules(store.All())

	evt := event.Event{
		SourceType:    "firewall",
		AssetIP:       "192.168.1.254",
		Severity:      "error",
		EventCategory: "error",
		Message:       "firewall_pass",
		Raw:           `filterlog pass 192.168.10.20 -> 192.168.1.62`,
		Tags:          map[string]string{},
	}

	d := e.Evaluate(&evt)
	if d.MatchedRuleID != "rule-firewall-pass-sample" {
		t.Fatalf("expected firewall pass sampler before generic error forward, got %+v", d)
	}
	if d.Forward {
		t.Fatalf("firewall pass noise must not forward to DMZ, got %+v", d)
	}
}
