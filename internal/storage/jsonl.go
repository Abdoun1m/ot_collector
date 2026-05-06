package storage

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

type JSONLStore struct {
	path   string
	logger *slog.Logger
	mu     sync.Mutex
}

type EventQuery struct {
	Limit      int
	SourceType string
	Severity   string
	Category   string
	AssetIP    string
	Search     string
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
	return s.ReadFiltered(EventQuery{Limit: limit})
}

func (s *JSONLStore) ReadFiltered(q EventQuery) ([]event.Event, error) {
	limit := q.Limit
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
		if !matchesQuery(e, q) {
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

func matchesQuery(e event.Event, q EventQuery) bool {
	if q.SourceType != "" && !strings.EqualFold(e.SourceType, q.SourceType) {
		return false
	}
	if q.Severity != "" && !strings.EqualFold(e.Severity, q.Severity) {
		return false
	}
	if q.Category != "" && !strings.EqualFold(e.EventCategory, q.Category) {
		return false
	}
	if q.AssetIP != "" && !strings.EqualFold(e.AssetIP, q.AssetIP) {
		return false
	}
	if q.Search != "" {
		s := strings.ToLower(q.Search)
		blob := strings.ToLower(strings.Join([]string{
			e.Message, e.Raw, e.AssetName, e.AssetIP, e.SourceType, e.Severity, e.EventCategory,
		}, " "))
		if !strings.Contains(blob, s) {
			for k, v := range e.Tags {
				if strings.Contains(strings.ToLower(k), s) || strings.Contains(strings.ToLower(v), s) {
					return true
				}
			}
			return false
		}
	}
	return true
}
