package storage

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

type JSONLStore struct {
	path   string
	logger *slog.Logger
	mu     sync.Mutex
}

func NewJSONLStore(path string, logger *slog.Logger) *JSONLStore {
	return &JSONLStore{path: path, logger: logger}
}

func (s *JSONLStore) Path() string {
	return s.path
}

func (s *JSONLStore) Append(evt event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	return enc.Encode(evt)
}

func (s *JSONLStore) ReadLast(limit int) ([]event.Event, error) {
	if limit <= 0 {
		limit = 100
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []event.Event{}, nil
		}
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lines := make([]event.Event, 0, limit)
	for scanner.Scan() {
		var e event.Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			s.logger.Warn("failed to parse JSONL line", "error", err)
			continue
		}
		lines = append(lines, e)
		if len(lines) > limit {
			lines = lines[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

