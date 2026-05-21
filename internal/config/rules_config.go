package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type RuleConfig struct {
	ID                 string  `json:"id"`
	Enabled            bool    `json:"enabled"`
	SourceType         string  `json:"source_type"`
	Asset              string  `json:"asset"`
	Category           string  `json:"category"`
	Severity           string  `json:"severity"`
	Operation          string  `json:"operation"`
	EventType          string  `json:"event_type"`
	MessageContains    string  `json:"message_contains"`
	TagKey             string  `json:"tag_key"`
	TagValue           string  `json:"tag_value"`
	Action             string  `json:"action"`
	SampleRate         float64 `json:"sample_rate"`
	ForwardToDMZ       bool    `json:"forward_to_dmz"`
	StoreLocally       bool    `json:"store_locally"`
	ShowInUI           *bool   `json:"show_in_ui,omitempty"`
	DedupWindowSeconds int     `json:"dedup_window_seconds"`
	RateLimitPerSecond int     `json:"rate_limit_per_second"`
	Notes              string  `json:"notes"`
}

type RuleStore struct {
	mu   sync.RWMutex
	path string
	data []RuleConfig
}

func NewRuleStore(path string) (*RuleStore, error) {
	s := &RuleStore{path: path}
	if err := s.loadOrInit(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *RuleStore) All() []RuleConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RuleConfig, len(s.data))
	copy(out, s.data)
	return out
}

func (s *RuleStore) Replace(all []RuleConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = sanitizeRules(all)
	return s.persistLocked()
}

func (s *RuleStore) Upsert(one RuleConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for i := range s.data {
		if s.data[i].ID == one.ID {
			s.data[i] = one
			found = true
			break
		}
	}
	if !found {
		s.data = append(s.data, one)
	}
	s.data = sanitizeRules(s.data)
	return s.persistLocked()
}

func (s *RuleStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.data[:0]
	for _, it := range s.data {
		if it.ID != id {
			out = append(out, it)
		}
	}
	s.data = out
	return s.persistLocked()
}

func (s *RuleStore) loadOrInit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.data = defaultRules()
			return s.persistLocked()
		}
		return err
	}
	var arr []RuleConfig
	if len(b) > 0 {
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
	}
	if len(arr) == 0 {
		arr = defaultRules()
	}
	s.data = sanitizeRules(arr)
	return s.persistLocked()
}

func (s *RuleStore) persistLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func sanitizeRules(in []RuleConfig) []RuleConfig {
	out := make([]RuleConfig, 0, len(in))
	for _, r := range in {
		if r.ID == "" {
			continue
		}
		if r.SourceType == "" {
			r.SourceType = "*"
		}
		if r.Asset == "" {
			r.Asset = "*"
		}
		if r.Category == "" {
			r.Category = "*"
		}
		if r.Severity == "" {
			r.Severity = "*"
		}
		if r.Operation == "" {
			r.Operation = "*"
		}
		if r.EventType == "" {
			r.EventType = "*"
		}
		if r.TagKey == "" && r.TagValue != "" {
			r.TagKey = "*"
		}
		if r.Action == "" {
			r.Action = "keep"
		}
		if r.SampleRate <= 0 {
			r.SampleRate = 1
		}
		if r.ShowInUI == nil {
			show := true
			r.ShowInUI = &show
		}
		out = append(out, r)
	}
	return out
}

func defaultRules() []RuleConfig {
	show := true
	return []RuleConfig{
		{ID: "rule-security-forward", Enabled: true, SourceType: "*", Asset: "*", Category: "security", Severity: "*", Operation: "*", EventType: "*", Action: "store_and_forward", SampleRate: 1, ForwardToDMZ: true, StoreLocally: true, ShowInUI: &show, Notes: "Forward all security events"},
		{ID: "rule-critical-forward", Enabled: true, SourceType: "*", Asset: "*", Category: "*", Severity: "critical", Operation: "*", EventType: "*", Action: "store_and_forward", SampleRate: 1, ForwardToDMZ: true, StoreLocally: true, ShowInUI: &show, Notes: "Forward all critical events"},
		{ID: "rule-error-forward", Enabled: true, SourceType: "*", Asset: "*", Category: "*", Severity: "error", Operation: "*", EventType: "*", Action: "store_and_forward", SampleRate: 1, ForwardToDMZ: true, StoreLocally: true, ShowInUI: &show, Notes: "Forward all error events"},
		{ID: "rule-firewall-block-forward", Enabled: true, SourceType: "firewall", Asset: "*", Category: "*", Severity: "*", Operation: "*", EventType: "*", MessageContains: "firewall_block", Action: "store_and_forward", SampleRate: 1, ForwardToDMZ: true, StoreLocally: true, ShowInUI: &show, Notes: "Forward firewall blocks"},
		{ID: "rule-opcua-sensitive-forward", Enabled: true, SourceType: "opcua", Asset: "*", Category: "*", Severity: "*", Operation: "*", EventType: "*", TagKey: "sensitive_action", TagValue: "true", Action: "store_and_forward", SampleRate: 1, ForwardToDMZ: true, StoreLocally: true, ShowInUI: &show, Notes: "Forward sensitive OPC UA actions"},
		{ID: "rule-opcua-write-forward", Enabled: true, SourceType: "opcua", Asset: "*", Category: "operator_action", Severity: "*", Operation: "WRITE", EventType: "*", Action: "store_and_forward", SampleRate: 1, ForwardToDMZ: true, StoreLocally: true, ShowInUI: &show, Notes: "Forward OPC UA writes"},
		{ID: "rule-opcua-read-sample", Enabled: true, SourceType: "opcua", Asset: "*", Category: "operator_action", Severity: "*", Operation: "READ", EventType: "*", Action: "sample", SampleRate: 0.05, ForwardToDMZ: false, StoreLocally: true, ShowInUI: &show, DedupWindowSeconds: 10, Notes: "Sample OPC UA reads to reduce noise"},
		{ID: "rule-ews-heartbeat-sample", Enabled: true, SourceType: "ews", Asset: "*", Category: "system_health", Severity: "info", Operation: "*", EventType: "*", MessageContains: "ews_heartbeat", Action: "sample", SampleRate: 0.2, ForwardToDMZ: false, StoreLocally: true, ShowInUI: &show, Notes: "Sample EWS heartbeat"},
		{ID: "rule-scada-heartbeat-sample", Enabled: true, SourceType: "scada", Asset: "*", Category: "system_health", Severity: "info", Operation: "*", EventType: "*", MessageContains: "heartbeat", Action: "sample", SampleRate: 0.1, ForwardToDMZ: false, StoreLocally: true, ShowInUI: &show, Notes: "Sample SCADA heartbeat"},
		{ID: "rule-gds-sync-success-sample", Enabled: true, SourceType: "gds_agent", Asset: "*", Category: "*", Severity: "info", Operation: "*", EventType: "*", MessageContains: "sync_cycle_success", Action: "sample", SampleRate: 0.25, ForwardToDMZ: false, StoreLocally: true, ShowInUI: &show, Notes: "Sample GDS sync success"},
		{ID: "rule-firewall-pass-sample", Enabled: true, SourceType: "firewall", Asset: "*", Category: "network", Severity: "info", Operation: "*", EventType: "*", MessageContains: "firewall_pass", Action: "sample", SampleRate: 0.3, ForwardToDMZ: false, StoreLocally: true, ShowInUI: &show, DedupWindowSeconds: 10, RateLimitPerSecond: 50, Notes: "Sample firewall pass/network noise"},
		{ID: "rule-plc-network-sample", Enabled: true, SourceType: "plc", Asset: "*", Category: "network", Severity: "*", Operation: "*", EventType: "*", Action: "sample", SampleRate: 0.3, ForwardToDMZ: false, StoreLocally: true, ShowInUI: &show, Notes: "Sample PLC network chatter"},
		{ID: "default-store-only", Enabled: true, SourceType: "*", Asset: "*", Category: "*", Severity: "*", Operation: "*", EventType: "*", Action: "store_only", SampleRate: 1, ForwardToDMZ: false, StoreLocally: true, ShowInUI: &show, Notes: "Default catch-all: store locally only"},
	}
}
