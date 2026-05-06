package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/sources"
	"github.com/Abdoun1m/ot_collector/internal/storage"
)

type StatsProvider interface {
	Snapshot() map[string]any
	SourceCounters() map[string]int64
}

type Processor interface {
	ProcessRaw(raw, sourceIP, transport string)
	ProcessNormalized(evt event.Event)
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
	knownSources map[string]sources.SourceInfo
	logger       *slog.Logger
}

func New(addr string, zone string, udpPort int, tcpPort int, apiPort int, eventsFile string, dmzEnabled bool, store *storage.JSONLStore, stats StatsProvider, processor Processor, logger *slog.Logger) *API {
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
		knownSources: sources.Known(),
		logger:       logger,
	}
}

func (a *API) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/events", a.handleEvents)
	mux.HandleFunc("/sources", a.handleSources)
	mux.HandleFunc("/stats", a.handleStats)
	mux.HandleFunc("/test-event", a.handleTestEvent)

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
