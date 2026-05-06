package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type RuleConfig struct {
	ID           string  `json:"id"`
	Enabled      bool    `json:"enabled"`
	SourceType   string  `json:"source_type"`
	Asset        string  `json:"asset"`
	Category     string  `json:"category"`
	Severity     string  `json:"severity"`
	Operation    string  `json:"operation"`
	Action       string  `json:"action"`
	SampleRate   float64 `json:"sample_rate"`
	ForwardToDMZ bool    `json:"forward_to_dmz"`
	StoreLocally bool    `json:"store_locally"`
	Notes        string  `json:"notes"`
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
		if r.Action == "" {
			r.Action = "keep"
		}
		if r.SampleRate <= 0 {
			r.SampleRate = 1
		}
		out = append(out, r)
	}
	return out
}

func defaultRules() []RuleConfig {
	return []RuleConfig{
		{ID: "rule-opcua-read-sample", Enabled: true, SourceType: "opcua", Asset: "*", Category: "operator_action", Severity: "*", Operation: "READ", Action: "sample", SampleRate: 0.1, ForwardToDMZ: false, StoreLocally: true, Notes: "Sample OPC UA reads to reduce noise"},
		{ID: "rule-opcua-write-keep", Enabled: true, SourceType: "opcua", Asset: "*", Category: "operator_action", Severity: "*", Operation: "WRITE", Action: "keep", SampleRate: 1, ForwardToDMZ: true, StoreLocally: true},
		{ID: "rule-ews-op-action", Enabled: true, SourceType: "ews", Asset: "*", Category: "operator_action", Severity: "*", Operation: "*", Action: "keep", SampleRate: 1, ForwardToDMZ: true, StoreLocally: true},
		{ID: "rule-scada-security", Enabled: true, SourceType: "scada", Asset: "*", Category: "security", Severity: "*", Operation: "*", Action: "keep", SampleRate: 1, ForwardToDMZ: true, StoreLocally: true},
		{ID: "rule-plc-network-sample", Enabled: true, SourceType: "plc", Asset: "*", Category: "network", Severity: "*", Operation: "*", Action: "sample", SampleRate: 0.3, ForwardToDMZ: false, StoreLocally: true},
	}
}

