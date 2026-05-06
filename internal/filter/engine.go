package filter

import (
	"math"
	"strings"
	"sync"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

type Config struct {
	DropOPCUAReads    bool    `json:"drop_opcua_reads"`
	DropDuplicates    bool    `json:"drop_duplicates"`
	SampleRate        float64 `json:"sample_rate"`
	DedupWindowSec    int     `json:"dedup_window_seconds"`
	MaxEventsPerSec   int     `json:"max_events_per_second"`
	OPCUAReadKeepEvery int    `json:"opcua_read_keep_every"`
}

type rateState struct {
	second int64
	count  int
}

type dupState struct {
	lastSeen time.Time
}

type Engine struct {
	mu sync.RWMutex

	cfg Config

	stateMu          sync.Mutex
	opcuaReadCounter map[string]int
	dedupCache       map[string]dupState
	rateBySource     map[string]rateState
}

func New() *Engine {
	return &Engine{
		cfg: DefaultConfig(),
		opcuaReadCounter: map[string]int{},
		dedupCache:       map[string]dupState{},
		rateBySource:     map[string]rateState{},
	}
}

func DefaultConfig() Config {
	return Config{
		DropOPCUAReads:    true,
		DropDuplicates:    true,
		SampleRate:        0.2,
		DedupWindowSec:    5,
		MaxEventsPerSec:   500,
		OPCUAReadKeepEvery: 0,
	}
}

func (e *Engine) Update(cfg Config) Config {
	e.mu.Lock()
	defer e.mu.Unlock()

	if cfg.SampleRate < 0 {
		cfg.SampleRate = 0
	}
	if cfg.SampleRate > 1 {
		cfg.SampleRate = 1
	}
	if cfg.DedupWindowSec < 0 {
		cfg.DedupWindowSec = 0
	}
	if cfg.MaxEventsPerSec < 0 {
		cfg.MaxEventsPerSec = 0
	}
	if cfg.OPCUAReadKeepEvery < 0 {
		cfg.OPCUAReadKeepEvery = 0
	}

	e.cfg = cfg
	return e.cfg
}

func (e *Engine) Current() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

func (e *Engine) ShouldDrop(evt *event.Event) (bool, string) {
	if evt == nil {
		return false, ""
	}

	cfg := e.Current()
	now := time.Now().UTC()

	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	if cfg.MaxEventsPerSec > 0 {
		sourceKey := evt.AssetIP
		if sourceKey == "" {
			sourceKey = evt.SourceType
		}
		sec := now.Unix()
		rs := e.rateBySource[sourceKey]
		if rs.second != sec {
			rs.second = sec
			rs.count = 0
		}
		rs.count++
		e.rateBySource[sourceKey] = rs
		if rs.count > cfg.MaxEventsPerSec {
			return true, "rate_limit"
		}
	}

	if cfg.DropDuplicates && cfg.DedupWindowSec > 0 {
		dupKey := strings.Join([]string{evt.AssetIP, evt.SourceType, evt.Message}, "|")
		if ds, ok := e.dedupCache[dupKey]; ok {
			if now.Sub(ds.lastSeen) <= time.Duration(cfg.DedupWindowSec)*time.Second {
				e.dedupCache[dupKey] = dupState{lastSeen: now}
				return true, "duplicate"
			}
		}
		e.dedupCache[dupKey] = dupState{lastSeen: now}
	}

	if cfg.DropOPCUAReads && isOPCUARead(evt) {
		if evt.Tags == nil {
			evt.Tags = map[string]string{}
		}
		evt.Tags["opcua_noise"] = "true"

		keepEvery := cfg.OPCUAReadKeepEvery
		if keepEvery <= 0 {
			keepEvery = sampleToKeepEvery(cfg.SampleRate)
		}
		if keepEvery <= 1 {
			return false, ""
		}

		key := strings.Join([]string{
			evt.AssetIP,
			evt.Tags["user"],
			evt.Tags["node_id"],
			evt.Tags["browse_name"],
			evt.Tags["mode"],
			evt.Tags["value"],
		}, "|")

		e.opcuaReadCounter[key]++
		c := e.opcuaReadCounter[key]
		if c%keepEvery != 1 {
			return true, "opcua_read_sample"
		}
	}

	return false, ""
}

func isOPCUARead(evt *event.Event) bool {
	if evt.SourceType != "opcua" || evt.Tags == nil {
		return false
	}
	return strings.EqualFold(evt.Tags["opcua_event_type"], "CMD") &&
		strings.EqualFold(evt.Tags["opcua_operation"], "READ")
}

func sampleToKeepEvery(sampleRate float64) int {
	if sampleRate <= 0 {
		return 0
	}
	if sampleRate >= 1 {
		return 1
	}
	n := int(math.Round(1 / sampleRate))
	if n < 1 {
		return 1
	}
	return n
}

