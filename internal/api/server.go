package api

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/filter"
	"github.com/Abdoun1m/ot_collector/internal/config"
	"github.com/Abdoun1m/ot_collector/internal/sources"
	"github.com/Abdoun1m/ot_collector/internal/storage"
	webassets "github.com/Abdoun1m/ot_collector/web"
)

type StatsProvider interface {
	Snapshot() map[string]any
	SourceCounters() map[string]int64
	Summary() map[string]any
	Timeline() []map[string]any
	Sources() []map[string]any
}

type Processor interface {
	ProcessRaw(raw, sourceIP, transport string)
	ProcessNormalized(evt event.Event)
	CurrentFilterConfig() map[string]any
	UpdateFilterConfig(cfg map[string]any) map[string]any
	CurrentRules() []config.RuleConfig
	SetRules(rules []config.RuleConfig)
	RuleTest(evt event.Event) filter.Decision
	ForwardingConfig() config.ForwardingConfig
	UpdateForwardingConfig(cfg config.ForwardingConfig) error
}

type API struct {
	addr         string
	zone         string
	udpPort      int
	tcpPort      int
	apiPort      int
	eventsFile   string
	dmzEnabled   bool
	store        *storage.JSONLStore
	stats        StatsProvider
	processor    Processor
	streamHub    *StreamHub
	sourceStore  *config.SourceStore
	ruleStore    *config.RuleStore
	forwardingStore *config.ForwardingStore
	knownSources map[string]sources.SourceInfo
	logger       *slog.Logger
}

func New(addr string, zone string, udpPort int, tcpPort int, apiPort int, eventsFile string, dmzEnabled bool, store *storage.JSONLStore, stats StatsProvider, processor Processor, sourceStore *config.SourceStore, ruleStore *config.RuleStore, forwardingStore *config.ForwardingStore, streamHub *StreamHub, logger *slog.Logger) *API {
	return &API{
		addr:         addr,
		zone:         zone,
		udpPort:      udpPort,
		tcpPort:      tcpPort,
		apiPort:      apiPort,
		eventsFile:   eventsFile,
		dmzEnabled:   dmzEnabled,
		store:        store,
		stats:        stats,
		processor:    processor,
		streamHub:    streamHub,
		sourceStore:  sourceStore,
		ruleStore:    ruleStore,
		forwardingStore: forwardingStore,
		knownSources: sources.Known(),
		logger:       logger,
	}
}

func (a *API) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/events", a.handleEvents)
	mux.HandleFunc("/events/stream", a.handleEventStream)
	mux.HandleFunc("/storage/repair", a.handleStorageRepair)
	mux.HandleFunc("/sources", a.handleSources)
	mux.HandleFunc("/stats", a.handleStats)
	mux.HandleFunc("/stats/summary", a.handleStatsSummary)
	mux.HandleFunc("/stats/timeline", a.handleStatsTimeline)
	mux.HandleFunc("/filter/config", a.handleFilterConfig)
	mux.HandleFunc("/config/sources", a.handleConfigSources)
	mux.HandleFunc("/config/sources/", a.handleConfigSourceByID)
	mux.HandleFunc("/config/rules", a.handleConfigRules)
	mux.HandleFunc("/config/rules/", a.handleConfigRuleByID)
	mux.HandleFunc("/config/rules/test", a.handleConfigRulesTest)
	mux.HandleFunc("/config/forwarding", a.handleConfigForwarding)
	mux.HandleFunc("/forwarding/test", a.handleForwardingTest)
	mux.HandleFunc("/forwarding/test-direct", a.handleForwardingTest)
	mux.HandleFunc("/forwarding/test-pipeline", a.handleForwardingTestPipeline)
	mux.HandleFunc("/test-event", a.handleTestEvent)

	sub, err := fs.Sub(webassets.FS, ".")
	if err == nil {
		mux.Handle("/", http.FileServer(http.FS(sub)))
	}

	server := &http.Server{
		Addr:              a.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", a.addr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	a.logger.Info("api server listening", "addr", a.addr)
	err = server.Serve(ln)
	if err == nil || err == http.ErrServerClosed {
		return nil
	}
	return err
}
