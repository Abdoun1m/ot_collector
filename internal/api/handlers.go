package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Abdoun1m/ot_collector/internal/event"
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
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if parsed, err := strconv.Atoi(q); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	events, err := a.store.ReadLast(limit)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "failed to read events")
		return
	}
	a.writeJSON(w, http.StatusOK, events)
}

func (a *API) handleSources(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, map[string]any{
		"known_sources": a.knownSources,
		"counters":      a.stats.SourceCounters(),
	})
}

func (a *API) handleStats(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, a.stats.Snapshot())
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

