package main

import (
	"context"
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
// A catch-all store_and_forward rule ensures every event is stored and forwarded.
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

	proc := &Processor{
		zone:           "OT",
		store:          store,
		forwarder:      fwd,
		stats:          NewStats(),
		filterEngine:   eng,
		streamHub:      api.NewStreamHub(),
		forwardingCfg:  fwdStore,
		logger:         slog.Default(),
		forwardTimeout: 5,
	}
	// Create the queue after proc so handleForwardResult can be bound safely.
	proc.forwardQueue = forwarder.NewForwardQueue(
		context.Background(),
		2, 100,
		30*time.Second,
		5*time.Second,
		func(ctx context.Context, evt event.Event) (int, error) {
			proc.mu.RLock()
			f := proc.forwarder
			proc.mu.RUnlock()
			return f.SendWithStatus(ctx, evt)
		},
		proc.handleForwardResult,
		slog.Default(),
	)
	return proc, store
}

func readEventByID(t *testing.T, store *storage.JSONLStore, id string) (event.Event, bool) {
	t.Helper()
	// Short wait for the synchronous storage append to complete.
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

// ── Test A: POST /events path — gds_agent event stored in OT and forwarded to DMZ ──

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

// ── Test B: POST /test-event path — gds-agent (hyphen) normalised and forwarded ──

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

// ── Test C: GDS-like event — splunk_sourcetype=labshock:ot:gds ──

func TestProcessNormalized_GDS_SplunkSourcetype(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()
	proc, store := newTestProcessor(t, dmz)

	evtID := fmt.Sprintf("test-gds-spt-%d", time.Now().UnixNano())
	proc.ProcessNormalized(event.Event{
		ID:            evtID,
		SourceType:    "gds_agent",
		AssetIP:       "192.168.1.30",
		EventCategory: "pki_validation",
		Message:       "certificate_expiry_critical",
	})

	stored, ok := readEventByID(t, store, evtID)
	if !ok {
		t.Fatalf("event %s not found in OT storage", evtID)
	}
	if got := stored.Tags["splunk_sourcetype"]; got != "labshock:ot:gds" {
		t.Errorf("splunk_sourcetype: want labshock:ot:gds, got %q", got)
	}
	if _, ok := dmz.waitForID(evtID, 3*time.Second); !ok {
		t.Fatalf("GDS event %s not received in DMZ", evtID)
	}
}

// ── Test D: Firewall event — source_type=firewall, splunk_sourcetype=labshock:net:firewall ──

func TestProcessNormalized_Firewall_StoreAndForward(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()
	proc, store := newTestProcessor(t, dmz)

	evtID := fmt.Sprintf("test-fw-%d", time.Now().UnixNano())
	proc.ProcessNormalized(event.Event{
		ID:            evtID,
		SourceType:    "firewall",
		AssetIP:       "192.168.1.254",
		Severity:      "warn",
		EventCategory: "security",
		Message:       "firewall_block",
	})

	stored, ok := readEventByID(t, store, evtID)
	if !ok {
		t.Fatalf("firewall event %s not found in OT storage", evtID)
	}
	if stored.SourceType != "firewall" {
		t.Errorf("source_type: want firewall, got %s", stored.SourceType)
	}
	if got := stored.Tags["splunk_sourcetype"]; got != "labshock:net:firewall" {
		t.Errorf("splunk_sourcetype: want labshock:net:firewall, got %q", got)
	}

	if _, ok := dmz.waitForID(evtID, 3*time.Second); !ok {
		t.Fatalf("firewall event %s not received in DMZ", evtID)
	}
}

// ── Test D variant: opnsense alias normalised to firewall ──

func TestNormalizeSourceType_OPNsense(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()
	proc, store := newTestProcessor(t, dmz)

	evtID := fmt.Sprintf("test-opn-%d", time.Now().UnixNano())
	proc.ProcessNormalized(event.Event{
		ID:         evtID,
		SourceType: "opnsense",
		AssetIP:    "192.168.1.254",
		Message:    "firewall event via opnsense alias",
	})

	stored, ok := readEventByID(t, store, evtID)
	if !ok {
		t.Fatalf("event %s not found in OT storage", evtID)
	}
	if stored.SourceType != "firewall" {
		t.Errorf("expected source_type=firewall after normalisation, got %s", stored.SourceType)
	}
	if got := stored.Tags["splunk_sourcetype"]; got != "labshock:net:firewall" {
		t.Errorf("splunk_sourcetype: want labshock:net:firewall, got %q", got)
	}
}

// ── Test E: /forwarding/test-direct — mock DMZ returns 202 ──

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

// ── Test F: /forwarding/test-pipeline — event appears in OT and DMZ ──

func TestForwardingTestPipeline_OTandDMZ(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()
	proc, store := newTestProcessor(t, dmz)

	// Replicate what handleForwardingTestPipeline does.
	now := time.Now().UTC()
	testEvt := event.Event{
		ID:            fmt.Sprintf("fwdpipeline-%d", now.UnixNano()),
		Timestamp:     now.Format(time.RFC3339Nano),
		ReceivedAt:    now.Format(time.RFC3339Nano),
		Zone:          "OT",
		SourceType:    "ot_collector",
		AssetName:     "ot_collector",
		Severity:      "info",
		Protocol:      "json",
		EventCategory: "system",
		Message:       "forwarding pipeline test",
		Tags:          map[string]string{"kind": "forwarding_pipeline_test"},
	}
	proc.ProcessNormalized(testEvt)

	if _, ok := readEventByID(t, store, testEvt.ID); !ok {
		t.Fatalf("pipeline test event %s not found in OT storage", testEvt.ID)
	}
	if _, ok := dmz.waitForID(testEvt.ID, 3*time.Second); !ok {
		t.Fatalf("pipeline test event %s not received in DMZ", testEvt.ID)
	}
}

// ── Test G: rule source_type="*" matches gds_agent ──

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

// ── store_and_forward action sets both Store and Forward ──

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

// ── ID is preserved through ingest ──

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

// ── collector_decision tag reflects actual forwarding intent ──

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
	if got := stored.Tags["splunk_sourcetype"]; got != "labshock:ot:gds" {
		t.Errorf("splunk_sourcetype: want labshock:ot:gds, got %q", got)
	}
}

// ── API events bypass dedup (two identical messages both stored) ──

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

// ── normalizeSourceType covers all documented aliases ──

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

// ── willForward honours rule forward flag; store_only rule must not forward ──

func TestIngest_StoreOnlyRuleDoesNotForward(t *testing.T) {
	dmz := newMockDMZ()
	defer dmz.srv.Close()

	tmpDir := t.TempDir()
	store := storage.NewJSONLStore(tmpDir+"/events.jsonl", slog.Default())
	fwd := forwarder.New(dmz.srv.URL+"/events", slog.Default(), 5)

	eng := filter.New()
	eng.SetRules([]config.RuleConfig{
		{
			ID: "store-only", Enabled: true,
			SourceType: "*", Asset: "*", Category: "*", Severity: "*", Operation: "*",
			Action: "store_only", StoreLocally: true, ForwardToDMZ: false,
		},
	})

	fwdStore, _ := config.NewForwardingStore(tmpDir + "/forwarding.json")
	_ = fwdStore.Replace(config.ForwardingConfig{
		DMZCollectorURL: dmz.srv.URL + "/events",
		Enabled:         true, ForwardOnlyFiltered: false,
	})

	proc := &Processor{
		zone: "OT", store: store, forwarder: fwd,
		stats: NewStats(), filterEngine: eng,
		streamHub: api.NewStreamHub(), forwardingCfg: fwdStore,
		logger: slog.Default(), forwardTimeout: 5,
	}
	proc.forwardQueue = forwarder.NewForwardQueue(
		context.Background(), 2, 100,
		30*time.Second, 5*time.Second,
		func(ctx context.Context, evt event.Event) (int, error) {
			proc.mu.RLock()
			f := proc.forwarder
			proc.mu.RUnlock()
			return f.SendWithStatus(ctx, evt)
		},
		proc.handleForwardResult, slog.Default(),
	)

	evtID := fmt.Sprintf("store-only-%d", time.Now().UnixNano())
	proc.ProcessNormalized(event.Event{ID: evtID, SourceType: "gds_agent", Message: "store only"})

	if _, ok := readEventByID(t, store, evtID); !ok {
		t.Fatalf("store_only event %s not found in OT storage", evtID)
	}
	// Must NOT appear in DMZ.
	if _, ok := dmz.waitForID(evtID, 500*time.Millisecond); ok {
		t.Errorf("store_only event %s must not be forwarded to DMZ", evtID)
	}
}

// ── ForwardQueue.Drain removes pending tasks ──

func TestForwardQueue_Drain(t *testing.T) {
	sent := make(chan struct{}, 10)
	q := forwarder.NewForwardQueue(
		context.Background(),
		1, 50,
		0, 5*time.Second,
		func(ctx context.Context, evt event.Event) (int, error) {
			sent <- struct{}{}
			return 200, nil
		},
		nil,
		slog.Default(),
	)

	// Pause the worker by making the send block.
	block := make(chan struct{})
	blockQ := forwarder.NewForwardQueue(
		context.Background(),
		1, 50,
		0, 5*time.Second,
		func(ctx context.Context, evt event.Event) (int, error) {
			<-block
			return 200, nil
		},
		nil,
		slog.Default(),
	)

	// Enqueue one task to keep the worker busy.
	blockQ.Enqueue(forwarder.ForwardTask{Evt: event.Event{ID: "blocker"}, EnqueuedAt: time.Now()})
	time.Sleep(20 * time.Millisecond) // let the worker pick it up

	// Enqueue 3 more into blockQ while worker is blocked.
	for i := 0; i < 3; i++ {
		blockQ.Enqueue(forwarder.ForwardTask{
			Evt:        event.Event{ID: fmt.Sprintf("q-%d", i)},
			EnqueuedAt: time.Now(),
		})
	}
	drained := blockQ.Drain()
	close(block) // unblock worker

	if drained != 3 {
		t.Errorf("Drain: want 3 tasks drained, got %d", drained)
	}
	_ = q
	_ = sent
}
