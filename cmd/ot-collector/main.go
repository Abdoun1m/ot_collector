package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/api"
	"github.com/Abdoun1m/ot_collector/internal/config"
	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/forwarder"
	"github.com/Abdoun1m/ot_collector/internal/normalizer"
	"github.com/Abdoun1m/ot_collector/internal/storage"
	"github.com/Abdoun1m/ot_collector/internal/syslog"
)

type Stats struct {
	mu           sync.RWMutex
	total        int64
	bySeverity   map[string]int64
	bySourceType map[string]int64
	byAsset      map[string]int64
	bySourceIP   map[string]int64
	lastEventAt  string
}

func NewStats() *Stats {
	return &Stats{
		bySeverity:   map[string]int64{},
		bySourceType: map[string]int64{},
		byAsset:      map[string]int64{},
		bySourceIP:   map[string]int64{},
	}
}

func (s *Stats) Add(e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	s.bySeverity[e.Severity]++
	s.bySourceType[e.SourceType]++
	s.byAsset[e.AssetName]++
	if e.AssetIP != "" {
		s.bySourceIP[e.AssetIP]++
	}
	s.lastEventAt = e.ReceivedAt
}

func (s *Stats) Snapshot() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]any{
		"total_events":   s.total,
		"by_severity":    cloneMap(s.bySeverity),
		"by_source_type": cloneMap(s.bySourceType),
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

type Processor struct {
	zone      string
	store     *storage.JSONLStore
	forwarder *forwarder.Forwarder
	stats     *Stats
	logger    *slog.Logger
}

func (p *Processor) ProcessRaw(raw, sourceIP, _ string) {
	parsed := syslog.Parse(raw)
	evt := normalizer.FromParsed(p.zone, parsed, sourceIP)
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
	}

	if p.forwarder.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := p.forwarder.Send(ctx, evt); err != nil {
			p.logger.Warn("dmz forwarding failed", "error", err)
		}
	}
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
	processor := &Processor{
		zone:      cfg.Zone,
		store:     store,
		forwarder: fwd,
		stats:     stats,
		logger:    logger,
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
