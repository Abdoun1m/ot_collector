package storage

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

func TestJSONLStoreGDSAgentHundredEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	store := NewJSONLStore(path, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	for i := 0; i < 100; i++ {
		if err := store.Append(gdsEvent(i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	got, err := store.ReadFiltered(EventQuery{Limit: 150, SourceType: "gds-agent"})
	if err != nil {
		t.Fatalf("read filtered: %v", err)
	}
	if len(got) != 100 {
		t.Fatalf("expected 100 gds-agent events, got %d", len(got))
	}

	restarted := NewJSONLStore(path, slog.New(slog.NewTextHandler(os.Stdout, nil)))
	got, err = restarted.ReadFiltered(EventQuery{Limit: 150, SourceType: "gds-agent"})
	if err != nil {
		t.Fatalf("read after restart: %v", err)
	}
	if len(got) != 100 {
		t.Fatalf("expected 100 gds-agent events after restart, got %d", len(got))
	}
}

func TestJSONLStoreSkipsAndRepairsNullPaddedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	store := NewJSONLStore(path, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	if err := store.Append(gdsEvent(1)); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0, 0, 0, '\n'}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(`{"source_type":"gds-agent","message":"valid with padding"}` + "\x00\x00\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := store.ReadFiltered(EventQuery{Limit: 10, SourceType: "gds-agent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 readable gds-agent events before repair, got %d", len(got))
	}

	report, err := store.Repair()
	if err != nil {
		t.Fatal(err)
	}
	if report.ValidLines != 2 || report.InvalidLines != 1 {
		t.Fatalf("unexpected repair report: %+v", report)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range raw {
		if b == 0 {
			t.Fatalf("null byte remained after repair at offset %d", i)
		}
	}
}

func gdsEvent(i int) event.Event {
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	return event.Event{
		ID:            time.Now().UTC().Format("20060102150405.000000000"),
		Timestamp:     ts,
		ReceivedAt:    ts,
		Zone:          "OT",
		SourceType:    "gds-agent",
		AssetName:     "gds-agent",
		AssetIP:       "192.168.1.80",
		Severity:      "info",
		Protocol:      "json",
		EventCategory: "system",
		Message:       "gds-agent event",
		Raw:           "gds-agent event",
		Tags:          map[string]string{"seq": string(rune('0' + (i % 10)))},
	}
}

