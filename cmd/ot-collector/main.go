package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/api"
	"github.com/Abdoun1m/ot_collector/internal/config"
	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/filter"
	"github.com/Abdoun1m/ot_collector/internal/forwarder"
	"github.com/Abdoun1m/ot_collector/internal/normalizer"
	"github.com/Abdoun1m/ot_collector/internal/storage"
	"github.com/Abdoun1m/ot_collector/internal/syslog"
)

type sourceStats struct {
	AssetName  string `json:"asset_name"`
	AssetIP    string `json:"asset_ip"`
	SourceType string `json:"source_type"`
	EventCount int64  `json:"event_count"`
	LastSeen   string `json:"last_seen"`
}

type Stats struct {
	mu           sync.RWMutex
	total        int64
	bySeverity   map[string]int64
	bySourceType map[string]int64
	byCategory   map[string]int64
	byAsset      map[string]int64
	byCommand    map[string]int64
	bySourceIP   map[string]int64
	timeline     map[string]int64
	sources      map[string]sourceStats
	lastEventAt  string
}

func NewStats() *Stats {
	return &Stats{
		bySeverity:   map[string]int64{},
		bySourceType: map[string]int64{},
		byCategory:   map[string]int64{},
		byAsset:      map[string]int64{},
		byCommand:    map[string]int64{},
		bySourceIP:   map[string]int64{},
		timeline:     map[string]int64{},
		sources:      map[string]sourceStats{},
	}
}

func (s *Stats) Add(e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	s.bySeverity[e.Severity]++
	s.bySourceType[e.SourceType]++
	s.byCategory[e.EventCategory]++
	s.byAsset[e.AssetName]++
	if e.AssetIP != "" {
		s.bySourceIP[e.AssetIP]++
	}
	if cmd := e.Tags["browse_name"]; cmd != "" {
		s.byCommand[cmd]++
	}

	bucket := parseMinuteBucket(e.ReceivedAt)
	s.timeline[bucket]++

	sourceKey := e.AssetIP
	if sourceKey == "" {
		sourceKey = e.AssetName
	}
	ss := s.sources[sourceKey]
	ss.AssetName = e.AssetName
	ss.AssetIP = e.AssetIP
	ss.SourceType = e.SourceType
	ss.EventCount++
	ss.LastSeen = e.ReceivedAt
	s.sources[sourceKey] = ss

	s.lastEventAt = e.ReceivedAt
}

func (s *Stats) Snapshot() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]any{
		"total_events":   s.total,
		"by_severity":    cloneMap(s.bySeverity),
		"by_source_type": cloneMap(s.bySourceType),
		"by_category":    cloneMap(s.byCategory),
		"by_asset":       cloneMap(s.byAsset),
		"last_event_time": s.lastEventAt,
	}
}

func (s *Stats) SourceCounters() map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneMap(s.bySourceIP)
}

func cloneMap(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s *Stats) Summary() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]any{
		"total_events":   s.total,
		"by_source_type": cloneMap(s.bySourceType),
		"by_severity":    cloneMap(s.bySeverity),
		"by_category":    cloneMap(s.byCategory),
		"top_assets":     topN(s.byAsset, 5),
		"top_commands":   topN(s.byCommand, 10),
	}
}

func (s *Stats) Timeline() []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, len(s.timeline))
	for k := range s.timeline {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{
			"timestamp": k,
			"count":     s.timeline[k],
		})
	}
	return out
}

func (s *Stats) Sources() []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]sourceStats, 0, len(s.sources))
	for _, v := range s.sources {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].EventCount > out[j].EventCount
	})
	mapped := make([]map[string]any, 0, len(out))
	for _, src := range out {
		mapped = append(mapped, map[string]any{
			"asset_name":  src.AssetName,
			"asset_ip":    src.AssetIP,
			"source_type": src.SourceType,
			"event_count": src.EventCount,
			"last_seen":   src.LastSeen,
		})
	}
	return mapped
}

func parseMinuteBucket(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Now().UTC().Format("2006-01-02T15:04:00Z")
	}
	return t.UTC().Format("2006-01-02T15:04:00Z")
}

func topN(m map[string]int64, n int) []map[string]any {
	type kv struct {
		Key   string
		Count int64
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{Key: k, Count: v})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})
	if len(items) > n {
		items = items[:n]
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{
			"name":  it.Key,
			"count": it.Count,
		})
	}
	return out
}

type Processor struct {
	zone         string
	store        *storage.JSONLStore
	forwarder    *forwarder.Forwarder
	stats        *Stats
	filterEngine *filter.Engine
	streamHub    *api.StreamHub
	logger       *slog.Logger
}

func (p *Processor) ProcessRaw(raw, sourceIP, _ string) {
	parsed := syslog.Parse(raw)
	evt := normalizer.FromParsed(p.zone, parsed, sourceIP)
	if drop, reason := p.filterEngine.ShouldDrop(&evt); drop {
		p.logger.Debug("event dropped by filter", "reason", reason, "source_type", evt.SourceType, "asset_ip", evt.AssetIP)
		return
	}
	p.ProcessNormalized(evt)
}

func (p *Processor) ProcessNormalized(evt event.Event) {
	if evt.ReceivedAt == "" {
		evt.ReceivedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if evt.Timestamp == "" {
		evt.Timestamp = evt.ReceivedAt
	}
	if evt.Zone == "" {
		evt.Zone = p.zone
	}
	if evt.Protocol == "" {
		evt.Protocol = "syslog"
	}
	if evt.Tags == nil {
		evt.Tags = map[string]string{}
	}

	if err := p.store.Append(evt); err != nil {
		p.logger.Error("failed to append event", "error", err)
	} else {
		p.stats.Add(evt)
		p.streamHub.Publish(evt)
	}

	if p.forwarder.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := p.forwarder.Send(ctx, evt); err != nil {
			p.logger.Warn("dmz forwarding failed", "error", err)
		}
	}
}

func (p *Processor) CurrentFilterConfig() filter.Config {
	return p.filterEngine.Current()
}

func (p *Processor) UpdateFilterConfig(cfg filter.Config) filter.Config {
	return p.filterEngine.Update(cfg)
}

func main() {
	cfg := config.Load()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store := storage.NewJSONLStore(cfg.EventsFile, logger)
	stats := NewStats()
	fwd := forwarder.New(cfg.DMZCollectorURL, logger)
	streamHub := api.NewStreamHub()
	filterEngine := filter.New()
	processor := &Processor{
		zone:         cfg.Zone,
		store:        store,
		forwarder:    fwd,
		stats:        stats,
		filterEngine: filterEngine,
		streamHub:    streamHub,
		logger:       logger,
	}

	incoming := make(chan syslog.IncomingLog, 2048)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-incoming:
				if !ok {
					return
				}
				processor.ProcessRaw(msg.Raw, msg.SourceIP, msg.Transport)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := syslog.RunUDPServer(ctx, cfg.UDPSyslogAddr, incoming, logger); err != nil {
			logger.Error("udp server failed", "error", err)
			cancel()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := syslog.RunTCPServer(ctx, cfg.TCPSyslogAddr, incoming, logger); err != nil {
			logger.Error("tcp server failed", "error", err)
			cancel()
		}
	}()

	udpPort := extractPort(cfg.UDPSyslogAddr)
	tcpPort := extractPort(cfg.TCPSyslogAddr)
	apiPort := extractPort(cfg.APIAddr)
	apiServer := api.New(
		cfg.APIAddr,
		cfg.Zone,
		udpPort,
		tcpPort,
		apiPort,
		cfg.EventsFile,
		fwd.Enabled(),
		store,
		stats,
		processor,
		streamHub,
		logger,
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := apiServer.Run(ctx); err != nil {
			logger.Error("api server failed", "error", err)
			cancel()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down ot collector")
	wg.Wait()
}

func extractPort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		parts := strings.Split(addr, ":")
		if len(parts) > 0 {
			p = parts[len(parts)-1]
		}
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return 0
	}
	return n
}
