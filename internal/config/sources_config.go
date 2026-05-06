package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type SourceConfig struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	IP             string `json:"ip"`
	Protocol       string `json:"protocol"`
	Impact         string `json:"impact"`
	Zone           string `json:"zone"`
	Enabled        bool   `json:"enabled"`
	ForwardEnabled bool   `json:"forward_enabled"`
	Notes          string `json:"notes"`
}

type SourceStore struct {
	mu   sync.RWMutex
	path string
	data []SourceConfig
}

func NewSourceStore(path string) (*SourceStore, error) {
	s := &SourceStore{path: path}
	if err := s.loadOrInit(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SourceStore) All() []SourceConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SourceConfig, len(s.data))
	copy(out, s.data)
	return out
}

func (s *SourceStore) Replace(all []SourceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = sanitizeSources(all)
	return s.persistLocked()
}

func (s *SourceStore) Upsert(one SourceConfig) error {
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
	s.data = sanitizeSources(s.data)
	return s.persistLocked()
}

func (s *SourceStore) Delete(id string) error {
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

func (s *SourceStore) loadOrInit() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}

	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.data = defaultSources()
			return s.persistLocked()
		}
		return err
	}
	var arr []SourceConfig
	if len(b) > 0 {
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
	}
	if len(arr) == 0 {
		arr = defaultSources()
	}
	s.data = sanitizeSources(arr)
	return s.persistLocked()
}

func (s *SourceStore) persistLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func sanitizeSources(in []SourceConfig) []SourceConfig {
	out := make([]SourceConfig, 0, len(in))
	for _, s := range in {
		if s.ID == "" {
			continue
		}
		if s.Name == "" {
			s.Name = s.ID
		}
		if s.Protocol == "" {
			s.Protocol = "syslog"
		}
		out = append(out, s)
	}
	return out
}

func defaultSources() []SourceConfig {
	return []SourceConfig{
		{ID: "plc1", Name: "PLC1", Type: "plc", IP: "192.168.1.20", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc2", Name: "PLC2", Type: "plc", IP: "192.168.1.21", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc3", Name: "PLC3", Type: "plc", IP: "192.168.1.22", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc4", Name: "PLC4", Type: "plc", IP: "192.168.1.23", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc5", Name: "PLC5", Type: "plc", IP: "192.168.1.24", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "fuxa-scada", Name: "FUXA SCADA", Type: "scada", IP: "192.168.1.60", Protocol: "syslog", Impact: "high", Zone: "L2", Enabled: true, ForwardEnabled: true},
		{ID: "opcua-server", Name: "OPC UA Server", Type: "opcua", IP: "192.168.1.62", Protocol: "syslog", Impact: "critical", Zone: "L2", Enabled: true, ForwardEnabled: true},
		{ID: "ews", Name: "EWS", Type: "ews", IP: "192.168.1.50", Protocol: "syslog", Impact: "high", Zone: "L2/L3", Enabled: true, ForwardEnabled: true},
		{ID: "ot-firewall", Name: "Future Firewall", Type: "firewall", IP: "192.168.1.254", Protocol: "syslog", Impact: "critical", Zone: "L3", Enabled: false, ForwardEnabled: true},
		{ID: "future-ids", Name: "Future IDS", Type: "ids", IP: "", Protocol: "syslog", Impact: "critical", Zone: "L3", Enabled: false, ForwardEnabled: true},
	}
}

