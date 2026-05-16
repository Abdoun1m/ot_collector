package forwarder

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

func New(url string, logger *slog.Logger, timeoutSecs int) *Forwarder {
	if timeoutSecs <= 0 {
		timeoutSecs = 10
	}
	return &Forwarder{
		url: strings.TrimSpace(url),
		client: &http.Client{
			Timeout: time.Duration(timeoutSecs) * time.Second,
		},
		logger: logger,
	}
}

func (f *Forwarder) Enabled() bool {
	return f.url != ""
}

// Send forwards an event to the DMZ collector. Returns an error on network or
// non-2xx response. Prefer SendWithStatus when the HTTP status code is needed.
func (f *Forwarder) Send(ctx context.Context, evt event.Event) error {
	_, err := f.SendWithStatus(ctx, evt)
	return err
}

// SendWithStatus forwards an event and returns the HTTP status code alongside
// any error. Status is 0 when the request never reached the server.
func (f *Forwarder) SendWithStatus(ctx context.Context, evt event.Event) (int, error) {
	if !f.Enabled() {
		return 0, nil
	}
	body, err := json.Marshal(evt)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	elapsedMS := time.Since(start).Milliseconds()
	if err != nil {
		f.logger.Debug("forward failed",
			"event_id", evt.ID,
			"forwarding_url", f.url,
			"payload_size_bytes", len(body),
			"elapsed_ms", elapsedMS,
			"error", err,
		)
		return 0, err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
	respSnippet := strings.TrimSpace(string(respBytes))
	f.logger.Debug("forward attempt",
		"event_id", evt.ID,
		"forwarding_url", f.url,
		"payload_size_bytes", len(body),
		"elapsed_ms", elapsedMS,
		"http_status", resp.StatusCode,
		"response_body_first_200_chars", respSnippet,
	)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, &HTTPStatusError{StatusCode: resp.StatusCode, Body: respSnippet}
	}
	return resp.StatusCode, nil
}

type HTTPStatusError struct {
	StatusCode int
	Body       string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("dmz collector returned status %d", e.StatusCode)
}
