package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/filter"
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

func (a *API) handleSources(w http.ResponseWriter, _ *http.Request) {
	seen := a.stats.Sources()
	byIP := map[string]map[string]any{}
	for _, s := range seen {
		if ip, ok := s["asset_ip"].(string); ok && ip != "" {
			byIP[ip] = s
		}
	}
	for ip, known := range a.knownSources {
		if _, ok := byIP[ip]; ok {
			continue
		}
		byIP[ip] = map[string]any{
			"asset_name":  known.AssetName,
			"asset_ip":    known.AssetIP,
			"source_type": known.SourceType,
			"event_count": 0,
			"last_seen":   "",
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
	var cfg filter.Config
	if err := json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(&cfg); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid filter config payload")
		return
	}
	applied := a.processor.UpdateFilterConfig(cfg)
	a.writeJSON(w, http.StatusOK, applied)
}

func (a *API) handleTestEvent(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var payload struct {
		Raw     string      `json:"raw"`
		SourceIP string     `json:"source_ip"`
		Event   *event.Event `json:"event"`
	}
	_ = json.Unmarshal(body, &payload)

	if payload.Event != nil {
		if payload.Event.Zone == "" {
			payload.Event.Zone = a.zone
		}
		if payload.Event.Protocol == "" {
			payload.Event.Protocol = "syslog"
		}
		a.processor.ProcessNormalized(*payload.Event)
		a.writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
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
