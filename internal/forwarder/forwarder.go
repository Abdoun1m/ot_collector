package forwarder

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

type Forwarder struct {
	url    string
	client *http.Client
	logger *slog.Logger
}

func New(url string, logger *slog.Logger) *Forwarder {
	return &Forwarder{
		url: strings.TrimSpace(url),
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
		logger: logger,
	}
}

func (f *Forwarder) Enabled() bool {
	return f.url != ""
}

func (f *Forwarder) Send(ctx context.Context, evt event.Event) error {
	if !f.Enabled() {
		return nil
	}
	body, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPStatusError{StatusCode: resp.StatusCode}
	}
	return nil
}

type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return "dmz collector returned non-success status"
}

