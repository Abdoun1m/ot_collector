package normalizers

import (
	"testing"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/syslog"
)

func TestSCADARawLineNormalization(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		wantMessage     string
		wantCategory    string
		wantSeverity    string
		wantTarget      string
		wantTargetIP    string
		wantTargetPort  string
		wantAlert       string
		wantOriginalMsg bool
	}{
		{
			name:            "read memory error",
			message:         "<131>May 17 15:28:53 localhost SCADA[29]: 2026-05-17T15:28:53.900Z [error] 'PLC1' _readMemory error! [object Object]",
			wantMessage:     "scada_plc_read_memory_error",
			wantCategory:    "data_collection",
			wantSeverity:    "error",
			wantTarget:      "PLC1",
			wantAlert:       "",
			wantOriginalMsg: true,
		},
		{
			name:            "plc attempt",
			message:         "2026-05-17T15:28:54.900Z [info] 'RAIL AUTO' try to connect 192.168.1.23",
			wantMessage:     "scada_plc_connection_attempt",
			wantCategory:    "data_collection",
			wantSeverity:    "info",
			wantTarget:      "RAIL AUTO",
			wantTargetIP:    "192.168.1.23",
			wantOriginalMsg: true,
		},
		{
			name:            "plc1 attempt",
			message:         "2026-05-17T15:29:02.176Z [info] 'PLC1' try to connect 192.168.1.20",
			wantMessage:     "scada_plc_connection_attempt",
			wantCategory:    "data_collection",
			wantSeverity:    "info",
			wantTarget:      "PLC1",
			wantTargetIP:    "192.168.1.20",
			wantOriginalMsg: true,
		},
		{
			name:            "plc1 attempt rfc3164 wrapped",
			message:         "<134>May 17 15:29:02 localhost SCADA[29]: 2026-05-17T15:29:02.176Z [info] 'PLC1' try to connect 192.168.1.20",
			wantMessage:     "scada_plc_connection_attempt",
			wantCategory:    "data_collection",
			wantSeverity:    "info",
			wantTarget:      "PLC1",
			wantTargetIP:    "192.168.1.20",
			wantOriginalMsg: true,
		},
		{
			name:            "opcua lost",
			message:         "2026-05-17T15:28:55.900Z [error] 'opcua' connection lost!",
			wantMessage:     "scada_opcua_connection_lost",
			wantCategory:    "data_collection",
			wantSeverity:    "error",
			wantTarget:      "opcua",
			wantAlert:       "true",
			wantOriginalMsg: true,
		},
		{
			name:            "opcua session closed",
			message:         "2026-05-17T15:28:55.900Z [warning] 'opcua' Warning => Session closed",
			wantMessage:     "scada_opcua_session_closed",
			wantCategory:    "data_collection",
			wantSeverity:    "warning",
			wantTarget:      "opcua",
			wantOriginalMsg: true,
		},
		{
			name:            "econnrefused",
			message:         "2026-05-17T15:28:56.900Z [error] connect ECONNREFUSED 192.168.1.20:502",
			wantMessage:     "scada_plc_connection_refused",
			wantCategory:    "data_collection",
			wantSeverity:    "error",
			wantTargetIP:    "192.168.1.20",
			wantTargetPort:  "502",
			wantOriginalMsg: true,
		},
		{
			name:            "polling overload",
			message:         "2026-05-17T15:28:57.900Z [warning] working (connection || polling) overload",
			wantMessage:     "scada_polling_overload",
			wantCategory:    "data_collection",
			wantSeverity:    "warning",
			wantOriginalMsg: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := event.Event{
				ID:            event.NewID(),
				Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
				ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
				Zone:          "OT",
				SourceType:    "scada",
				AssetIP:       "192.168.1.60",
				Severity:      "info",
				Protocol:      "syslog",
				EventCategory: "system",
				Message:       tc.message,
				Raw:           tc.message,
				Tags:          map[string]string{},
			}
			out := Apply(in, Context{Parsed: syslog.ParsedMessage{Message: tc.message, Hostname: "localhost", AppName: "SCADA", Format: "raw"}, SourceIP: "192.168.1.60"})

			if out.Message != tc.wantMessage {
				t.Fatalf("expected message %s got %s", tc.wantMessage, out.Message)
			}
			if out.EventCategory != tc.wantCategory {
				t.Fatalf("expected category %s got %s", tc.wantCategory, out.EventCategory)
			}
			if tc.wantSeverity != "" && out.Severity != tc.wantSeverity {
				t.Fatalf("expected severity %s got %s", tc.wantSeverity, out.Severity)
			}
			if tc.wantTarget != "" && out.Tags["target"] != tc.wantTarget {
				t.Fatalf("expected target %s got %s", tc.wantTarget, out.Tags["target"])
			}
			if tc.wantTargetIP != "" && out.Tags["target_ip"] != tc.wantTargetIP {
				t.Fatalf("expected target_ip %s got %s", tc.wantTargetIP, out.Tags["target_ip"])
			}
			if tc.wantTargetPort != "" && out.Tags["target_port"] != tc.wantTargetPort {
				t.Fatalf("expected target_port %s got %s", tc.wantTargetPort, out.Tags["target_port"])
			}
			if tc.wantAlert != "" && out.Tags["alert_candidate"] != tc.wantAlert {
				t.Fatalf("expected alert_candidate %s got %s", tc.wantAlert, out.Tags["alert_candidate"])
			}
			if tc.wantAlert == "" {
				if _, ok := out.Tags["alert_candidate"]; ok && out.Message == "scada_plc_read_memory_error" {
					t.Fatalf("did not expect alert_candidate for non-threshold read memory event")
				}
			}
			if tc.wantOriginalMsg && out.Tags["original_message"] == "" {
				t.Fatalf("expected original_message tag")
			}
		})
	}
}
