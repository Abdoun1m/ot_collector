package filter

import (
	"testing"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

func TestOPCUAReadSamplingDropsSecondEvent(t *testing.T) {
	e := New()
	e.Update(Config{
		DropOPCUAReads:    true,
		DropDuplicates:    false,
		SampleRate:        0.5,
		DedupWindowSec:    5,
		MaxEventsPerSec:   0,
		OPCUAReadKeepEvery: 0,
	})

	evt1 := sampleReadEvent()
	drop1, _ := e.ShouldDrop(&evt1)
	if drop1 {
		t.Fatal("first event should be kept")
	}
	if evt1.Tags["opcua_noise"] != "true" {
		t.Fatalf("expected opcua_noise=true, got %q", evt1.Tags["opcua_noise"])
	}

	evt2 := sampleReadEvent()
	drop2, _ := e.ShouldDrop(&evt2)
	if !drop2 {
		t.Fatal("second event should be dropped with 0.5 sampling")
	}
}

func TestOPCUAWriteNeverSampled(t *testing.T) {
	e := New()
	evt := event.Event{
		SourceType: "opcua",
		AssetIP:    "192.168.1.62",
		Message:    "write cmd",
		Tags: map[string]string{
			"opcua_event_type": "CMD",
			"opcua_operation":  "WRITE",
		},
	}
	drop, _ := e.ShouldDrop(&evt)
	if drop {
		t.Fatal("write event should not be sampled by opcua read filter")
	}
}

func TestDuplicateDrop(t *testing.T) {
	e := New()
	e.Update(Config{
		DropOPCUAReads:    false,
		DropDuplicates:    true,
		SampleRate:        1,
		DedupWindowSec:    10,
		MaxEventsPerSec:   0,
		OPCUAReadKeepEvery: 0,
	})
	evt := event.Event{
		SourceType: "scada",
		AssetIP:    "192.168.1.60",
		Message:    "duplicate me",
	}
	d1, _ := e.ShouldDrop(&evt)
	if d1 {
		t.Fatal("first duplicate candidate should be kept")
	}
	d2, reason := e.ShouldDrop(&evt)
	if !d2 || reason != "duplicate" {
		t.Fatalf("expected duplicate drop, got drop=%v reason=%q", d2, reason)
	}
}

func sampleReadEvent() event.Event {
	return event.Event{
		SourceType: "opcua",
		AssetIP:    "192.168.1.62",
		Message:    "read cmd",
		Tags: map[string]string{
			"opcua_event_type": "CMD",
			"opcua_operation":  "READ",
			"user":             "admin",
			"node_id":          "ns=2;i=1214",
			"browse_name":      "Vanne4",
			"mode":             "MAINTAINED",
			"value":            "false",
		},
	}
}

