package normalizers

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/syslog"
)

type fixtureRecord struct {
	Name     string `json:"name"`
	SourceIP string `json:"source_ip"`
	Parsed   struct {
		Message  string `json:"message"`
		Hostname string `json:"hostname"`
		AppName  string `json:"app_name"`
		Format   string `json:"format"`
	} `json:"parsed"`
	Base struct {
		SourceType string `json:"source_type"`
	} `json:"base"`
	Expect struct {
		SourceType      string `json:"source_type"`
		AssetName       string `json:"asset_name"`
		EventCategory   string `json:"event_category"`
		Message         string `json:"message"`
		SplunkSourcetype string `json:"splunk_sourcetype"`
	} `json:"expect"`
}

func TestSourceFixtures(t *testing.T) {
	b, err := os.ReadFile("../../tests/fixtures/source_events.json")
	if err != nil {
		t.Fatalf("failed to read fixture file: %v", err)
	}
	var fixtures []fixtureRecord
	if err := json.Unmarshal(b, &fixtures); err != nil {
		t.Fatalf("failed to parse fixture file: %v", err)
	}

	for _, fx := range fixtures {
		t.Run(fx.Name, func(t *testing.T) {
			in := event.Event{
				ID:            event.NewID(),
				Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
				ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
				Zone:          "OT",
				SourceType:    fx.Base.SourceType,
				AssetIP:       fx.SourceIP,
				Severity:      "warn",
				Protocol:      "syslog",
				EventCategory: "system",
				Message:       fx.Parsed.Message,
				Raw:           fx.Parsed.Message,
				Tags:          map[string]string{},
			}
			out := Apply(in, Context{Parsed: syslog.ParsedMessage{
				Message:  fx.Parsed.Message,
				Hostname: fx.Parsed.Hostname,
				AppName:  fx.Parsed.AppName,
				Format:   fx.Parsed.Format,
			}, SourceIP: fx.SourceIP})

			if out.SourceType != fx.Expect.SourceType {
				t.Fatalf("expected source_type=%s got=%s", fx.Expect.SourceType, out.SourceType)
			}
			if out.AssetName != fx.Expect.AssetName {
				t.Fatalf("expected asset_name=%s got=%s", fx.Expect.AssetName, out.AssetName)
			}
			if out.EventCategory != fx.Expect.EventCategory {
				t.Fatalf("expected event_category=%s got=%s", fx.Expect.EventCategory, out.EventCategory)
			}
			if out.Message != fx.Expect.Message {
				t.Fatalf("expected message=%s got=%s", fx.Expect.Message, out.Message)
			}
			if out.Tags["splunk_sourcetype"] != fx.Expect.SplunkSourcetype {
				t.Fatalf("expected sourcetype=%s got=%s", fx.Expect.SplunkSourcetype, out.Tags["splunk_sourcetype"])
			}
			if out.Tags["normalized"] != "true" {
				t.Fatalf("expected normalized=true")
			}
			if out.Tags["normalization_source"] != "logs_by_sources_md" {
				t.Fatalf("expected normalization_source tag")
			}
			if out.Tags["parser_version"] == "" {
				t.Fatalf("expected parser_version tag")
			}
			if out.Tags["siem_index_hint"] != "ot_security" {
				t.Fatalf("expected siem_index_hint=ot_security")
			}
		})
	}
}
