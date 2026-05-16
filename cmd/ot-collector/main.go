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
	"github.com/Abdoun1m/ot_collector/internal/sources"
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
	mu sync.RWMutex

	total            int64
	storedCount      int64
	droppedCount     int64
	sampledCount     int64
	forwardedCount   int64
	failedForwardCnt int64

	bySeverity   map[string]int64
	bySourceType map[string]int64
	byCategory   map[string]int64
	byAsset      map[string]int64
	byCommand    map[string]int64
	byRule       map[string]int64
	byDecision   map[string]int64
	bySourceIP   map[string]int64
	timeline     map[string]int64
	sources      map[string]sourceStats
	lastEventAt  string
	lastForwardOK string

	rateSecond int64
	rateCount  int64
	rateEPS    int64
}

func NewStats() *Stats {
	return &Stats{
		bySeverity:   map[string]int64{},
		bySourceType: map[string]int64{},
		byCategory:   map[string]int64{},
		byAsset:      map[string]int64{},
		byCommand:    map[string]int64{},
		byRule:       map[string]int64{},
		byDecision:   map[string]int64{},
		bySourceIP:   map[string]int64{},
		timeline:     map[string]int64{},
		sources:      map[string]sourceStats{},
	}
}

func (s *Stats) AddStored(e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	s.storedCount++
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
	s.timeline[parseMinuteBucket(e.ReceivedAt)]++
	k := e.AssetIP
	if k == "" {
		k = e.AssetName
	}
	ss := s.sources[k]
	ss.AssetName = e.AssetName
	ss.AssetIP = e.AssetIP
	ss.SourceType = e.SourceType
	ss.EventCount++
	ss.LastSeen = e.ReceivedAt
	s.sources[k] = ss
	s.lastEventAt = e.ReceivedAt
	s.bumpRate()
}

func (s *Stats) AddDecision(decision string, ruleID string, sampled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byDecision[decision]++
	if ruleID != "" {
		s.byRule[ruleID]++
	}
	if sampled {
		s.sampledCount++
	}
}

func (s *Stats) AddDropped(ruleID, reason string, sampled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	s.droppedCount++
	s.byDecision["drop"]++
	if reason != "" {
		s.byDecision[reason]++
	}
	if ruleID != "" {
		s.byRule[ruleID]++
	}
	if sampled {
		s.sampledCount++
	}
	s.bumpRate()
}

func (s *Stats) AddForwardResult(success bool, when string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if success {
		s.forwardedCount++
		s.lastForwardOK = when
	} else {
		s.failedForwardCnt++
	}
}

func (s *Stats) bumpRate() {
	sec := time.Now().Unix()
	if s.rateSecond != sec {
		s.rateSecond = sec
		s.rateEPS = s.rateCount
		s.rateCount = 0
	}
	s.rateCount++
}

func (s *Stats) Snapshot() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]any{
		"total_events":            s.total,
		"by_severity":             cloneMap(s.bySeverity),
		"by_source_type":          cloneMap(s.bySourceType),
		"by_category":             cloneMap(s.byCategory),
		"by_asset":                cloneMap(s.byAsset),
		"last_event_time":         s.lastEventAt,
		"stored_count":            s.storedCount,
		"dropped_count":           s.droppedCount,
		"sampled_count":           s.sampledCount,
		"forwarded_count":         s.forwardedCount,
		"failed_forward_count":    s.failedForwardCnt,
		"event_rate_per_second":   s.rateEPS,
		"last_successful_forward": s.lastForwardOK,
	}
}

func (s *Stats) Summary() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]any{
		"total_events":             s.total,
		"by_source_type":           cloneMap(s.bySourceType),
		"by_severity":              cloneMap(s.bySeverity),
		"by_category":              cloneMap(s.byCategory),
		"top_assets":               topN(s.byAsset, 5),
		"top_commands":             topN(s.byCommand, 10),
		"stored_count":             s.storedCount,
		"dropped_count":            s.droppedCount,
		"sampled_count":            s.sampledCount,
		"forwarded_count":          s.forwardedCount,
		"failed_forward_count":     s.failedForwardCnt,
		"by_rule":                  cloneMap(s.byRule),
		"by_decision":              cloneMap(s.byDecision),
		"event_rate_per_second":    s.rateEPS,
		"last_successful_forward_time": s.lastForwardOK,
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
		out = append(out, map[string]any{"timestamp": k, "count": s.timeline[k]})
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
	sort.Slice(out, func(i, j int) bool { return out[i].EventCount > out[j].EventCount })
	m := make([]map[string]any, 0, len(out))
	for _, src := range out {
		m = append(m, map[string]any{
			"asset_name":  src.AssetName,
			"asset_ip":    src.AssetIP,
			"source_type": src.SourceType,
			"event_count": src.EventCount,
			"last_seen":   src.LastSeen,
		})
	}
	return m
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

func parseMinuteBucket(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Now().UTC().Format("2006-01-02T15:04:00Z")
	}
	return t.UTC().Format("2006-01-02T15:04:00Z")
}

func topN(m map[string]int64, n int) []map[string]any {
	type kv struct{ Key string; Count int64 }
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > n {
		items = items[:n]
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{"name": it.Key, "count": it.Count})
	}
	return out
}

type Processor struct {
	zone            string
	store           *storage.JSONLStore
	forwarder       *forwarder.Forwarder
	stats           *Stats
	filterEngine    *filter.Engine
	streamHub       *api.StreamHub
	forwardingCfg   *config.ForwardingStore
	logger          *slog.Logger
	forwardTimeout  int
}

func (p *Processor) ProcessRaw(raw, sourceIP, _ string) {
	parsed := syslog.Parse(raw)
	evt := normalizer.FromParsed(p.zone, parsed, sourceIP)
	if evt.Tags == nil {
		evt.Tags = map[string]string{}
	}
	decision := p.filterEngine.Evaluate(&evt)
	evt.Tags["collector_decision"] = decisionTag(decision)
	if decision.MatchedRuleID != "" {
		evt.Tags["matched_rule_id"] = decision.MatchedRuleID
	}
	if decision.Drop {
		p.stats.AddDropped(decision.MatchedRuleID, decision.Reason, decision.Sampled)
		p.logger.Debug("dropped event by decision", "reason", decision.Reason, "rule_id", decision.MatchedRuleID)
		return
	}
	p.stats.AddDecision(decisionTag(decision), decision.MatchedRuleID, decision.Sampled)
	p.ProcessNormalizedWithDecision(evt, decision)
}

func (p *Processor) ProcessNormalized(evt event.Event) {
	if evt.Tags == nil {
		evt.Tags = map[string]string{}
	}
	decision := p.filterEngine.Evaluate(&evt)
	evt.Tags["collector_decision"] = decisionTag(decision)
	if decision.MatchedRuleID != "" {
		evt.Tags["matched_rule_id"] = decision.MatchedRuleID
	}
	if decision.Drop {
		p.stats.AddDropped(decision.MatchedRuleID, decision.Reason, decision.Sampled)
		return
	}
	p.stats.AddDecision(decisionTag(decision), decision.MatchedRuleID, decision.Sampled)
	p.ProcessNormalizedWithDecision(evt, decision)
}

func (p *Processor) ProcessNormalizedWithDecision(evt event.Event, decision filter.Decision) {
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

	if decision.Store {
		if err := p.store.Append(evt); err != nil {
			p.logger.Error("failed to append event", "error", err)
		} else {
			p.stats.AddStored(evt)
			if decision.Show {
				p.streamHub.Publish(evt)
			}
		}
	}

	fcfg := p.forwardingCfg.Get()
	shouldForward := decision.Forward || (fcfg.Enabled && !fcfg.ForwardOnlyFiltered)
	if shouldForward && p.forwarder.Enabled() {
		go func(evt event.Event) {
			if err := p.forwarder.Send(context.Background(), evt); err != nil {
				p.logger.Warn("dmz forwarding failed", "error", err, "event_id", evt.ID)
				now := time.Now().UTC().Format(time.RFC3339Nano)
				p.stats.AddForwardResult(false, "")
				_ = p.forwardingCfg.UpdateForwardResult(false, now, err.Error())
			} else {
				now := time.Now().UTC().Format(time.RFC3339Nano)
				p.stats.AddForwardResult(true, now)
				_ = p.forwardingCfg.UpdateForwardResult(true, now, "")
			}
		}(evt)
	}
}

func decisionTag(d filter.Decision) string {
	if d.Drop {
		return "drop"
	}
	if d.Store && d.Forward {
		return "forward"
	}
	if d.Store && !d.Forward {
		if d.Sampled {
			return "sample"
		}
		return "store_only"
	}
	if !d.Store && d.Forward {
		return "forward_only"
	}
	return "store_only"
}

func (p *Processor) CurrentFilterConfig() map[string]any {
	return map[string]any{"mode": "rule_matrix"}
}

func (p *Processor) UpdateFilterConfig(_ map[string]any) map[string]any {
	return p.CurrentFilterConfig()
}

func (p *Processor) CurrentRules() []config.RuleConfig {
	return p.filterEngine.Rules()
}

func (p *Processor) SetRules(rules []config.RuleConfig) {
	p.filterEngine.SetRules(rules)
}

func (p *Processor) RuleTest(evt event.Event) filter.Decision {
	return p.filterEngine.Evaluate(&evt)
}

func (p *Processor) ForwardingConfig() config.ForwardingConfig {
	return p.forwardingCfg.Get()
}

func (p *Processor) UpdateForwardingConfig(cfg config.ForwardingConfig) error {
	if err := p.forwardingCfg.Replace(cfg); err != nil {
		return err
	}
	p.forwarder = forwarder.New(cfg.DMZCollectorURL, p.logger, p.forwardTimeout)
	return nil
}

func main() {
	cfg := config.Load()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store := storage.NewJSONLStore(cfg.EventsFile, logger)
	stats := NewStats()

	sourceStore, err := config.NewSourceStore("/data/sources.json")
	if err != nil {
		logger.Error("failed to init source store", "error", err)
		return
	}
	ruleStore, err := config.NewRuleStore("/data/rules.json")
	if err != nil {
		logger.Error("failed to init rule store", "error", err)
		return
	}
	forwardingStore, err := config.NewForwardingStore("/data/forwarding.json")
	if err != nil {
		logger.Error("failed to init forwarding store", "error", err)
		return
	}
	sources.SetDefaultResolver(sources.NewResolver(sourceStore))

	fcfg := forwardingStore.Get()
	dmzURL := cfg.DMZCollectorURL
	if fcfg.DMZCollectorURL != "" {
		dmzURL = fcfg.DMZCollectorURL
	}
	fwd := forwarder.New(dmzURL, logger, cfg.ForwardTimeoutSeconds)
	streamHub := api.NewStreamHub()
	filterEngine := filter.New()
	filterEngine.SetRules(ruleStore.All())

	processor := &Processor{
		zone:           cfg.Zone,
		store:          store,
		forwarder:      fwd,
		stats:          stats,
		filterEngine:   filterEngine,
		streamHub:      streamHub,
		forwardingCfg:  forwardingStore,
		logger:         logger,
		forwardTimeout: cfg.ForwardTimeoutSeconds,
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

	apiServer := api.New(
		cfg.APIAddr,
		cfg.Zone,
		extractPort(cfg.UDPSyslogAddr),
		extractPort(cfg.TCPSyslogAddr),
		extractPort(cfg.APIAddr),
		cfg.EventsFile,
		fwd.Enabled(),
		store,
		stats,
		processor,
		sourceStore,
		ruleStore,
		forwardingStore,
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

