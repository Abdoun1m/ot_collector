package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type ForwardingConfig struct {
	DMZCollectorURL         string `json:"dmz_collector_url"`
	Enabled                 bool   `json:"enabled"`
	ForwardOnlyFiltered     bool   `json:"forward_only_filtered_events"`
	ForwardQueueStatus      string `json:"forward_queue_status"`
	FailedForwardCount      int64  `json:"failed_forward_count"`
	LastSuccessfulForwardAt string `json:"last_successful_forward_time"`
}

type ForwardingStore struct {
	mu   sync.RWMutex
	path string
	data ForwardingConfig
}

func NewForwardingStore(path string) (*ForwardingStore, error) {
	s := &ForwardingStore{path: path}
	if err := s.loadOrInit(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ForwardingStore) Get() ForwardingConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}

func (s *ForwardingStore) Replace(cfg ForwardingConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = cfg
	if s.data.ForwardQueueStatus == "" {
		s.data.ForwardQueueStatus = "ok"
	}
	return s.persistLocked()
}

func (s *ForwardingStore) UpdateForwardResult(success bool, when string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if success {
		s.data.LastSuccessfulForwardAt = when
	} else {
		s.data.FailedForwardCount++
	}
	return s.persistLocked()
}

func (s *ForwardingStore) loadOrInit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.data = ForwardingConfig{Enabled: false, ForwardOnlyFiltered: true, ForwardQueueStatus: "ok"}
			return s.persistLocked()
		}
		return err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &s.data); err != nil {
			return err
		}
	}
	if s.data.ForwardQueueStatus == "" {
		s.data.ForwardQueueStatus = "ok"
	}
	return s.persistLocked()
}

func (s *ForwardingStore) persistLocked() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

