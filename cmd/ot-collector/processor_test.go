package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"log/slog"

	"github.com/Abdoun1m/ot_collector/internal/api"
	"github.com/Abdoun1m/ot_collector/internal/config"
	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/filter"
	"github.com/Abdoun1m/ot_collector/internal/forwarder"
	"github.com/Abdoun1m/ot_collector/internal/storage"
)

// mockDMZ captures events forwarded to the DMZ.
type mockDMZ struct {
	received chan event.Event
	srv      *httptest.Server
}

func newMockDMZ() *mockDMZ {
	m := &mockDMZ{received: make(chan event.Event, 200)}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var evt event.Event
		_ = json.NewDecoder(r.Body).Decode(&evt)
		select {
		case m.received <- evt:
		default:
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	return m
}

func (m *mockDMZ) waitForID(id string, timeout time.Duration) (event.Event, bool) {
	deadline := time.After(timeout)
	for {
		select {
		case evt := <-m.received:
			if evt.ID == id {
				return evt, true
			}
		case <-deadline:
			return event.Event{}, false
		}
	}
}

// newTestProcessor builds a Processor wired to a temp JSONL store and a mock DMZ.
// The rule set is a catch-all store_and_forward rule so every event is stored and forwarded.
func newTestProcessor(t *testing.T, dmz *mockDMZ) (*Processor, *storage.JSONLStore) {
	t.Helper()
	tmpDir := t.TempDir()

	store := storage.NewJSONLStore(tmpDir+"/events.jsonl", slog.Default())

	dmzURL := ""
	if dmz != nil {
		dmzURL = dmz.srv.URL + "/events"
	}
	fwd := forwarder.New(dmzURL, slog.Default(), 5)

	eng := filter.New()
	eng.SetRules([]config.RuleConfig{
		{
			ID:           "rule-test-all",
			Enabled:      true,
			SourceType:   "*",
			Asset:        "*",
			Category:     "*",
			Severity:     "*",
			Operation:    "*",
			Action:       "store_and_forward",
			SampleRate:   1,
			ForwardToDMZ: true,
			StoreLocally: true,
		},
	})

	fwdStore, err := config.NewForwardingStore(tmpDir + "/forwarding.json")
	if err != nil {
		t.Fatalf("NewForwardingStore: %v", err)
	}
	_ = fwdStore.Replace(config.ForwardingConfig{
		DMZCollectorURL:     dmzURL,
		Enabled:             true,
		ForwardOnlyFiltered: false,
	})

	return &Processor{
		zone:           "OT",
		store:          store,
		forwarder:      fwd,
		stats:          NewStats(),
		filterEngine:   eng,
		streamHub:      api.NewStreamHub(),
		forwardingCfg:  fwdStore,
		logger:         slog.Default(),
		forwardTimeout: 5,
	}, store
}

func readEventByID(t *testing.T, store *storage.JSONLStore, id string) (event.Event, bool) {
	t.Helper()
	// Small wait for synchronous storage append to complete.
	time.Sleep(30 * time.Millisecond)
	evts, err := store.ReadFiltered(storage.EventQuery{Limit: 500})
	if err != nil {
		t.Fatalf("ReadFiltered: %v", err)
	}
	for _, e := range evts {
		if e.ID == id {
			return e, true
		}
	}
	return event.Event{}, false
}

// ── Test 1: POST /events path — gds_agent event stored in OT and forwarded to DMZ ──

func TestProcessNormalized_GDSAgent_StoreAndForward(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()
	proc, store := newTestProcessor(t, dmz)

	evtID := fmt.Sprintf("test-gds-%d", time.Now().UnixNano())
	proc.ProcessNormalized(event.Event{
		ID:            evtID,
		SourceType:    "gds_agent",
		AssetIP:       "192.168.1.30",
		Severity:      "info",
		EventCategory: "system",
		Message:       "gds agent heartbeat",
	})

	// OT storage
	stored, ok := readEventByID(t, store, evtID)
	if !ok {
		t.Fatalf("event %s not found in OT storage", evtID)
	}
	if stored.SourceType != "gds_agent" {
		t.Errorf("OT source_type: want gds_agent, got %s", stored.SourceType)
	}

	// DMZ
	dmzEvt, ok := dmz.waitForID(evtID, 3*time.Second)
	if !ok {
		t.Fatalf("event %s not received in DMZ", evtID)
	}
	if dmzEvt.SourceType != "gds_agent" {
		t.Errorf("DMZ source_type: want gds_agent, got %s", dmzEvt.SourceType)
	}
}

// ── Test 2: /test-event path — gds-agent (hyphen) normalised to gds_agent ──

func TestProcessNormalized_GDSHyphen_NormalisedAndForwarded(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()
	proc, store := newTestProcessor(t, dmz)

	evtID := fmt.Sprintf("test-gds-hyp-%d", time.Now().UnixNano())
	proc.ProcessNormalized(event.Event{
		ID:            evtID,
		SourceType:    "gds-agent", // hyphen variant
		AssetIP:       "192.168.1.30",
		Severity:      "info",
		EventCategory: "system",
		Message:       "gds-agent test event",
	})

	stored, ok := readEventByID(t, store, evtID)
	if !ok {
		t.Fatalf("event %s not found in OT storage", evtID)
	}
	if stored.SourceType != "gds_agent" {
		t.Errorf("OT source_type: want gds_agent, got %s", stored.SourceType)
	}

	dmzEvt, ok := dmz.waitForID(evtID, 3*time.Second)
	if !ok {
		t.Fatalf("event %s not received in DMZ", evtID)
	}
	if dmzEvt.SourceType != "gds_agent" {
		t.Errorf("DMZ source_type: want gds_agent, got %s", dmzEvt.SourceType)
	}
}

// ── Test 3: Firewall event stored in OT and forwarded to DMZ ──

func TestProcessNormalized_Firewall_StoreAndForward(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()
	proc, store := newTestProcessor(t, dmz)

	evtID := fmt.Sprintf("test-fw-%d", time.Now().UnixNano())
	proc.ProcessNormalized(event.Event{
		ID:            evtID,
		SourceType:    "firewall",
		AssetIP:       "192.168.1.1",
		Severity:      "warn",
		EventCategory: "security",
		Message:       "firewall_block",
	})

	if _, ok := readEventByID(t, store, evtID); !ok {
		t.Fatalf("firewall event %s not found in OT storage", evtID)
	}
	if _, ok := dmz.waitForID(evtID, 3*time.Second); !ok {
		t.Fatalf("firewall event %s not received in DMZ", evtID)
	}
}

// ── Test 4: opnsense alias normalised to firewall ──

func TestNormalizeSourceType_OPNsense(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()
	proc, store := newTestProcessor(t, dmz)

	evtID := fmt.Sprintf("test-opn-%d", time.Now().UnixNano())
	proc.ProcessNormalized(event.Event{
		ID:         evtID,
		SourceType: "opnsense",
		Message:    "firewall event via opnsense alias",
	})

	stored, ok := readEventByID(t, store, evtID)
	if !ok {
		t.Fatalf("event %s not found in OT storage", evtID)
	}
	if stored.SourceType != "firewall" {
		t.Errorf("expected source_type=firewall after normalisation, got %s", stored.SourceType)
	}
}

// ── Test 5: store_and_forward rule action sets both Store and Forward ──

func TestFilterEngine_StoreAndForwardAction(t *testing.T) {
	eng := filter.New()
	eng.SetRules([]config.RuleConfig{
		{
			ID:           "r1",
			Enabled:      true,
			SourceType:   "*",
			Asset:        "*",
			Category:     "*",
			Severity:     "*",
			Operation:    "*",
			Action:       "store_and_forward",
			ForwardToDMZ: true,
			StoreLocally: true,
			SampleRate:   1,
		},
	})
	evt := &event.Event{SourceType: "gds_agent", Message: "x", Tags: map[string]string{}}
	d := eng.EvaluateRulesOnly(evt)
	if !d.Store {
		t.Error("Store should be true for store_and_forward action")
	}
	if !d.Forward {
		t.Error("Forward should be true for store_and_forward action")
	}
	if d.Drop {
		t.Error("Drop should be false for store_and_forward action")
	}
}

// ── Test 6: wildcard rule matches gds_agent ──

func TestFilterEngine_WildcardMatchesGDSAgent(t *testing.T) {
	eng := filter.New()
	eng.SetRules([]config.RuleConfig{
		{
			ID:           "r-wild",
			Enabled:      true,
			SourceType:   "*",
			Asset:        "*",
			Category:     "*",
			Severity:     "*",
			Operation:    "*",
			Action:       "store_and_forward",
			ForwardToDMZ: true,
			StoreLocally: true,
			SampleRate:   1,
		},
	})
	evt := &event.Event{SourceType: "gds_agent", Tags: map[string]string{}}
	d := eng.EvaluateRulesOnly(evt)
	if d.MatchedRuleID != "r-wild" {
		t.Errorf("expected rule r-wild to match gds_agent, got matched_rule_id=%q", d.MatchedRuleID)
	}
}

// ── Test 7: ID preserved through ingest ──

func TestProcessNormalized_IDPreserved(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()
	proc, store := newTestProcessor(t, dmz)

	wantID := "my-explicit-id-abc123"
	proc.ProcessNormalized(event.Event{
		ID:         wantID,
		SourceType: "opcua",
		Message:    "id preservation test",
	})

	stored, ok := readEventByID(t, store, wantID)
	if !ok {
		t.Fatalf("event with ID %s not found in OT storage", wantID)
	}
	if stored.ID != wantID {
		t.Errorf("ID changed: want %s, got %s", wantID, stored.ID)
	}

	dmzEvt, ok := dmz.waitForID(wantID, 3*time.Second)
	if !ok {
		t.Fatalf("event %s not received in DMZ", wantID)
	}
	if dmzEvt.ID != wantID {
		t.Errorf("DMZ ID changed: want %s, got %s", wantID, dmzEvt.ID)
	}
}

// ── Test 8: collector_decision tag is store_and_forward when forwarding occurs ──

func TestProcessNormalized_CollectorDecisionTag(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()
	proc, store := newTestProcessor(t, dmz)

	evtID := fmt.Sprintf("test-tag-%d", time.Now().UnixNano())
	proc.ProcessNormalized(event.Event{
		ID:         evtID,
		SourceType: "gds_agent",
		Message:    "tag test",
	})

	stored, ok := readEventByID(t, store, evtID)
	if !ok {
		t.Fatalf("event %s not found", evtID)
	}
	if got := stored.Tags["collector_decision"]; got != "store_and_forward" {
		t.Errorf("collector_decision: want store_and_forward, got %q", got)
	}
	if stored.Tags["siem_index_hint"] == "" {
		t.Error("siem_index_hint tag is empty")
	}
	if stored.Tags["splunk_sourcetype"] == "" {
		t.Error("splunk_sourcetype tag is empty")
	}
}

// ── Test 9: API events bypass dedup (two identical messages both stored) ──

func TestProcessNormalized_APIBypassesDedup(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()
	proc, store := newTestProcessor(t, dmz)

	id1 := fmt.Sprintf("dedup-1-%d", time.Now().UnixNano())
	id2 := fmt.Sprintf("dedup-2-%d", time.Now().UnixNano())

	evt := event.Event{
		SourceType: "gds_agent",
		AssetIP:    "10.0.0.1",
		Message:    "same message every time",
	}

	evt.ID = id1
	proc.ProcessNormalized(evt)
	evt.ID = id2
	proc.ProcessNormalized(evt)

	if _, ok := readEventByID(t, store, id1); !ok {
		t.Errorf("first event %s not found (dedup falsely fired)", id1)
	}
	if _, ok := readEventByID(t, store, id2); !ok {
		t.Errorf("second event %s not found (dedup falsely fired for API path)", id2)
	}
}

// ── Test 10: normalizeSourceType covers all documented aliases ──

func TestNormalizeSourceType_AllAliases(t *testing.T) {
	cases := []struct{ in, want string }{
		{"gds-agent", "gds_agent"},
		{"gds_agent", "gds_agent"},
		{"GDS-Agent", "gds_agent"},
		{"opnsense", "firewall"},
		{"firewall", "firewall"},
		{"OPCUA", "opcua"},
		{"fuxa", "scada"},
		{"openplc", "plc"},
		{"nozomi", "ids"},
		{"unknown", "unknown"},
		{"", ""},
	}
	for _, c := range cases {
		got := normalizeSourceType(c.in)
		if got != c.want {
			t.Errorf("normalizeSourceType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ── Test 11: /forwarding/test-direct mock DMZ returns 202 ──

func TestForwardingTestDirect_DMZReachable(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()

	resp, err := http.Post(dmz.srv.URL+"/events", "application/json",
		strings.NewReader(`{"id":"health-check","source_type":"test"}`))
	if err != nil {
		t.Fatalf("DMZ health check request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("DMZ health check: want 202, got %d", resp.StatusCode)
	}
}
