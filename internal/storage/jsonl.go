package storage

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
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

	record, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	if bytes.IndexByte(record, 0) >= 0 {
		return errors.New("refusing to write JSONL record containing null byte")
	}
	record = append(record, '\n')

	n, err := f.Write(record)
	if err != nil {
		return err
	}
	if n != len(record) {
		return io.ErrShortWrite
	}
	return nil
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

	lines := make([]event.Event, 0, limit)
	reader := bufio.NewReader(f)
	var offset int64
	var lineNo int64
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			lineNo++
			start := offset
			offset += int64(len(line))

			e, ok := s.parseLine(line, lineNo, start)
			if !ok {
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
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		return nil, err
	}
	return lines, nil
}

type RepairReport struct {
	Path         string `json:"path"`
	ValidLines   int64  `json:"valid_lines"`
	InvalidLines int64  `json:"invalid_lines"`
	NullLines    int64  `json:"null_lines"`
	BytesWritten int64  `json:"bytes_written"`
}

func (s *JSONLStore) Repair() (RepairReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	report := RepairReport{Path: s.path}
	in, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return report, nil
		}
		return report, err
	}

	tmp := s.path + ".repair.tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		_ = in.Close()
		return report, err
	}

	reader := bufio.NewReader(in)
	var offset int64
	var lineNo int64
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			lineNo++
			start := offset
			offset += int64(len(line))
			clean := sanitizeJSONLLine(line)
			if len(clean) == 0 {
				if bytes.IndexByte(line, 0) >= 0 {
					report.NullLines++
				}
				report.InvalidLines++
				s.logger.Warn("dropping invalid JSONL line during repair", "line", lineNo, "offset", start, "reason", "empty_or_null_padded")
			} else {
				var evt event.Event
				if err := json.Unmarshal(clean, &evt); err != nil {
					report.InvalidLines++
					s.logger.Warn("dropping invalid JSONL line during repair", "line", lineNo, "offset", start, "error", err)
				} else {
					record, err := json.Marshal(evt)
					if err != nil {
						_ = out.Close()
						return report, err
					}
					record = append(record, '\n')
					n, err := out.Write(record)
					if err != nil {
						_ = out.Close()
						return report, err
					}
					if n != len(record) {
						_ = out.Close()
						return report, io.ErrShortWrite
					}
					report.ValidLines++
					report.BytesWritten += int64(n)
				}
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		_ = out.Close()
		return report, err
	}
	if err := out.Close(); err != nil {
		_ = in.Close()
		return report, err
	}
	if err := in.Close(); err != nil {
		return report, err
	}
	return report, os.Rename(tmp, s.path)
}

func (s *JSONLStore) parseLine(line []byte, lineNo, offset int64) (event.Event, bool) {
	var e event.Event
	clean := sanitizeJSONLLine(line)
	if len(clean) == 0 {
		if bytes.IndexByte(line, 0) >= 0 {
			s.logger.Warn("skipping null-padded JSONL line", "line", lineNo, "offset", offset, "bytes", len(line))
		}
		return e, false
	}
	if err := json.Unmarshal(clean, &e); err != nil {
		s.logger.Warn("failed to parse JSONL line", "line", lineNo, "offset", offset, "bytes", len(line), "error", err)
		return e, false
	}
	return e, true
}

func sanitizeJSONLLine(line []byte) []byte {
	return bytes.Trim(line, "\x00\r\n\t ")
}

func matchesQuery(e event.Event, q EventQuery) bool {
	if q.SourceType != "" && canonicalSourceType(e.SourceType) != canonicalSourceType(q.SourceType) {
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

func canonicalSourceType(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "_")
	switch s {
	case "opnsense":
		return "firewall"
	case "fuxa":
		return "scada"
	case "openplc":
		return "plc"
	default:
		return s
	}
}
