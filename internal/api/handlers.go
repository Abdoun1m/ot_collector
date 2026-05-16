package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/config"
	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/sources"
	"github.com/Abdoun1m/ot_collector/internal/storage"
)

func (a *API) handleHealth(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, map[string]any{
		"status":                 "ok",
		"service":                "ot_collector",
		"zone":                   a.zone,
		"udp_syslog_port":        a.udpPort,
		"tcp_syslog_port":        a.tcpPort,
		"api_port":               a.apiPort,
		"events_file":            a.eventsFile,
		"dmz_forwarding_enabled": a.dmzEnabled,
	})
}

func (a *API) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		a.handlePostEvents(w, r)
		return
	}
	if r.Method != http.MethodGet {
		a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	query := storage.EventQuery{
		Limit:      parsePositiveInt(r.URL.Query().Get("limit"), 100),
		SourceType: strings.TrimSpace(r.URL.Query().Get("source_type")),
		Severity:   strings.TrimSpace(r.URL.Query().Get("severity")),
		Category:   strings.TrimSpace(r.URL.Query().Get("category")),
		AssetIP:    strings.TrimSpace(r.URL.Query().Get("asset_ip")),
		Search:     strings.TrimSpace(r.URL.Query().Get("search")),
	}
	events, err := a.store.ReadFiltered(query)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "failed to read events")
		return
	}
	a.writeJSON(w, http.StatusOK, events)
}

func (a *API) handlePostEvents(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		a.writeError(w, http.StatusBadRequest, "empty request body")
		return
	}

	var batch []event.Event
	if len(body) > 0 && body[0] == '[' {
		if err := json.Unmarshal(body, &batch); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid event array")
			return
		}
	} else {
		var evt event.Event
		if err := json.Unmarshal(body, &evt); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid event object")
			return
		}
		batch = []event.Event{evt}
	}

	ids := make([]string, 0, len(batch))
	for _, evt := range batch {
		normalizePostedEvent(&evt, a.zone)
		ids = append(ids, evt.ID)
		a.processor.ProcessNormalized(evt)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"status": "accepted", "accepted": len(batch), "ids": ids})
}

func (a *API) handleSources(w http.ResponseWriter, _ *http.Request) {
	seen := a.stats.Sources()
	byIP := map[string]map[string]any{}
	for _, s := range seen {
		if ip, ok := s["asset_ip"].(string); ok && ip != "" {
			byIP[ip] = s
		}
	}
	for _, src := range a.sourceStore.All() {
		evCount := 0
		lastSeen := ""
		if existing, ok := byIP[src.IP]; ok {
			if v, ok := existing["event_count"].(int); ok {
				evCount = v
			}
			if v, ok := existing["event_count"].(float64); ok {
				evCount = int(v)
			}
			if v, ok := existing["event_count"].(int64); ok {
				evCount = int(v)
			}
			if v, ok := existing["last_seen"].(string); ok {
				lastSeen = v
			}
		}
		byIP[src.IP] = map[string]any{
			"asset_name":  src.Name,
			"asset_ip":    src.IP,
			"source_type": src.Type,
			"event_count": evCount,
			"last_seen":   lastSeen,
		}
	}
	out := make([]map[string]any, 0, len(byIP))
	for _, v := range byIP {
		out = append(out, v)
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) handleStats(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, a.stats.Snapshot())
}

func (a *API) handleStatsSummary(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, a.stats.Summary())
}

func (a *API) handleStatsTimeline(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, a.stats.Timeline())
}

func (a *API) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		a.writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	id, ch := a.streamHub.Subscribe()
	defer a.streamHub.Unsubscribe(id)
	fmt.Fprintf(w, "event: ready\ndata: {\"status\":\"connected\"}\n\n")
	flusher.Flush()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case evt, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: event\ndata: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func (a *API) handleStorageRepair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	report, err := a.store.Repair()
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "storage repair failed")
		return
	}
	a.writeJSON(w, http.StatusOK, report)
}

func (a *API) handleFilterConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.writeJSON(w, http.StatusOK, a.processor.CurrentFilterConfig())
		return
	}
	if r.Method != http.MethodPost {
		a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	defer r.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&payload); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid filter config payload")
		return
	}
	a.writeJSON(w, http.StatusOK, a.processor.UpdateFilterConfig(payload))
}

func (a *API) handleConfigSources(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, a.sourceStore.All())
	case http.MethodPost:
		defer r.Body.Close()
		var all []config.SourceConfig
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&all); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid source payload")
			return
		}
		if err := a.sourceStore.Replace(all); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to persist sources")
			return
		}
		a.knownSources = sourcesKnownFromConfig(all)
		a.writeJSON(w, http.StatusOK, all)
	default:
		a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *API) handleConfigSourceByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/config/sources/")
	if id == "" {
		a.writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	switch r.Method {
	case http.MethodPut:
		defer r.Body.Close()
		var one config.SourceConfig
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&one); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid source payload")
			return
		}
		one.ID = id
		if err := a.sourceStore.Upsert(one); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to update source")
			return
		}
		a.knownSources = sourcesKnownFromConfig(a.sourceStore.All())
		a.writeJSON(w, http.StatusOK, one)
	case http.MethodDelete:
		if err := a.sourceStore.Delete(id); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to delete source")
			return
		}
		a.knownSources = sourcesKnownFromConfig(a.sourceStore.All())
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *API) handleConfigRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, a.ruleStore.All())
	case http.MethodPost:
		defer r.Body.Close()
		var all []config.RuleConfig
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&all); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid rules payload")
			return
		}
		if err := a.ruleStore.Replace(all); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to save rules")
			return
		}
		a.processor.SetRules(all)
		a.writeJSON(w, http.StatusOK, all)
	default:
		a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *API) handleConfigRuleByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/config/rules/")
	if id == "" {
		a.writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	switch r.Method {
	case http.MethodPut:
		defer r.Body.Close()
		var one config.RuleConfig
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&one); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid rule payload")
			return
		}
		one.ID = id
		if err := a.ruleStore.Upsert(one); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to update rule")
			return
		}
		a.processor.SetRules(a.ruleStore.All())
		a.writeJSON(w, http.StatusOK, one)
	case http.MethodDelete:
		if err := a.ruleStore.Delete(id); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to delete rule")
			return
		}
		a.processor.SetRules(a.ruleStore.All())
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *API) handleConfigRulesTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	defer r.Body.Close()
	var payload struct {
		Event event.Event `json:"event"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&payload); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid test payload")
		return
	}
	a.writeJSON(w, http.StatusOK, a.processor.RuleTest(payload.Event))
}

func (a *API) handleConfigForwarding(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, a.processor.ForwardingConfig())
	case http.MethodPost:
		defer r.Body.Close()
		var cfg config.ForwardingConfig
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&cfg); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid forwarding config")
			return
		}
		if err := a.processor.UpdateForwardingConfig(cfg); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to save forwarding config")
			return
		}
		a.writeJSON(w, http.StatusOK, cfg)
	default:
		a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *API) handleForwardingTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cfg := a.processor.ForwardingConfig()
	dmzURL := strings.TrimSpace(cfg.DMZCollectorURL)
	if dmzURL == "" {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"success": false,
			"error":   "forwarding URL not configured",
		})
		return
	}
	now := time.Now().UTC()
	testEvt := event.Event{
		ID:            fmt.Sprintf("fwdtest-%d", now.UnixNano()),
		Timestamp:     now.Format(time.RFC3339Nano),
		ReceivedAt:    now.Format(time.RFC3339Nano),
		Zone:          a.zone,
		SourceType:    "ot_collector",
		AssetName:     "ot_collector",
		Severity:      "info",
		Protocol:      "json",
		EventCategory: "system",
		Message:       "forwarding connectivity test",
		Tags:          map[string]string{"kind": "forwarding_test"},
	}
	body, _ := json.Marshal(testEvt)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dmzURL, bytes.NewReader(body))
	if err != nil {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	testClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := testClient.Do(req)
	elapsedMS := time.Since(start).Milliseconds()
	if err != nil {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"success":    false,
			"elapsed_ms": elapsedMS,
			"error":      err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	a.writeJSON(w, http.StatusOK, map[string]any{
		"success":       success,
		"status_code":   resp.StatusCode,
		"elapsed_ms":    elapsedMS,
		"response_body": strings.TrimSpace(string(respBytes)),
		"error":         "",
	})
}

// handleForwardingResetQueue drains all pending (not yet in-flight) tasks from
// the forward queue.  It never deletes /data/events.jsonl or any config file.
func (a *API) handleForwardingResetQueue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	drained := a.processor.ResetForwardQueue()
	a.writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"drained_count": drained,
		"note":          "in-flight sends were not interrupted; only pending queue items were removed",
	})
}

// handleForwardingTestPipeline injects a real test event through the full shared
// ingest pipeline (rule evaluation, storage, async DMZ forwarding) and returns
// the event ID so the caller can poll /events to verify end-to-end delivery.
func (a *API) handleForwardingTestPipeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	now := time.Now().UTC()
	testEvt := event.Event{
		ID:            fmt.Sprintf("fwdpipeline-%d", now.UnixNano()),
		Timestamp:     now.Format(time.RFC3339Nano),
		ReceivedAt:    now.Format(time.RFC3339Nano),
		Zone:          a.zone,
		SourceType:    "ot_collector",
		AssetName:     "ot_collector",
		Severity:      "info",
		Protocol:      "json",
		EventCategory: "system",
		Message:       "forwarding pipeline test",
		Tags:          map[string]string{"kind": "forwarding_pipeline_test"},
	}
	a.processor.ProcessNormalized(testEvt)
	a.writeJSON(w, http.StatusOK, map[string]any{
		"status":   "injected",
		"event_id": testEvt.ID,
		"note":     "event passed through ingest pipeline; DMZ forwarding is async — poll /events?search=" + testEvt.ID,
	})
}

func (a *API) handleTestEvent(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var payload struct {
		Raw      string       `json:"raw"`
		SourceIP string       `json:"source_ip"`
		Event    *event.Event `json:"event"`
	}
	_ = json.Unmarshal(body, &payload)
	if payload.Event != nil {
		// Preserve all caller-supplied fields; only fill in blanks.
		evt := *payload.Event
		if evt.ID == "" {
			evt.ID = event.NewID()
		}
		if evt.Zone == "" {
			evt.Zone = a.zone
		}
		if evt.Protocol == "" {
			evt.Protocol = "json"
		}
		if evt.Tags == nil {
			evt.Tags = map[string]string{}
		}
		a.processor.ProcessNormalized(evt)
		a.writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted", "id": evt.ID})
		return
	}
	raw := strings.TrimSpace(payload.Raw)
	if raw == "" {
		raw = strings.TrimSpace(string(body))
	}
	if raw == "" {
		a.writeError(w, http.StatusBadRequest, "provide raw or event")
		return
	}
	src := strings.TrimSpace(payload.SourceIP)
	if src == "" {
		src = "127.0.0.1"
	}
	a.processor.ProcessRaw(raw, src, "api")
	a.writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (a *API) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *API) writeError(w http.ResponseWriter, status int, msg string) {
	a.writeJSON(w, status, map[string]string{"error": msg})
}

func parsePositiveInt(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func normalizePostedEvent(evt *event.Event, zone string) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if evt.ID == "" {
		evt.ID = event.NewID()
	}
	if evt.Timestamp == "" {
		evt.Timestamp = now
	}
	if evt.ReceivedAt == "" {
		evt.ReceivedAt = now
	}
	if evt.Zone == "" {
		evt.Zone = zone
	}
	if evt.Protocol == "" {
		evt.Protocol = "json"
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
	if evt.EventCategory == "" {
		evt.EventCategory = "system"
	}
	if evt.Tags == nil {
		evt.Tags = map[string]string{}
	}
}

func sourcesKnownFromConfig(all []config.SourceConfig) map[string]sources.SourceInfo {
	out := make(map[string]sources.SourceInfo, len(all))
	for _, s := range all {
		out[s.IP] = sources.SourceInfo{AssetName: s.Name, SourceType: s.Type, AssetIP: s.IP}
	}
	return out
}
