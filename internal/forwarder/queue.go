package forwarder

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

// ForwardTask is a single unit of work for the ForwardQueue.
type ForwardTask struct {
	Evt           event.Event
	IngestionPath string
	EnqueuedAt    time.Time
}

// ForwardResult is the outcome reported to the onResult callback.
type ForwardResult struct {
	EventID       string
	IngestionPath string
	Skipped       bool
	SkipReason    string
	ElapsedMS     int64
	HTTPStatus    int
	Err           error
}

// ForwardQueue is a bounded, worker-pool-based async forwarder.
// Workers read tasks from a buffered channel and call doSend for each one.
// Stale tasks (older than maxAge) are discarded without a send attempt.
type ForwardQueue struct {
	tasks    chan ForwardTask
	doSend   func(ctx context.Context, evt event.Event) (int, error)
	maxAge   time.Duration
	timeout  time.Duration
	onResult func(ForwardResult)
	logger   *slog.Logger
	wg       sync.WaitGroup
	queued   atomic.Int64
	inFlight atomic.Int64
}

// NewForwardQueue starts n worker goroutines backed by a buffered channel of
// size bufSize.  Workers run until ctx is cancelled.
//
// doSend is called by workers with a per-send timeout context derived from
// timeout.  onResult (optional) is called after every processed task.
func NewForwardQueue(
	ctx context.Context,
	workers, bufSize int,
	maxAge, timeout time.Duration,
	doSend func(context.Context, event.Event) (int, error),
	onResult func(ForwardResult),
	logger *slog.Logger,
) *ForwardQueue {
	if workers <= 0 {
		workers = 4
	}
	if bufSize <= 0 {
		bufSize = 2048
	}
	q := &ForwardQueue{
		tasks:    make(chan ForwardTask, bufSize),
		doSend:   doSend,
		maxAge:   maxAge,
		timeout:  timeout,
		onResult: onResult,
		logger:   logger,
	}
	for i := 0; i < workers; i++ {
		q.wg.Add(1)
		go q.worker(ctx)
	}
	return q
}

// Enqueue submits a task non-blocking. Returns false if the channel is full.
func (q *ForwardQueue) Enqueue(task ForwardTask) bool {
	select {
	case q.tasks <- task:
		q.queued.Add(1)
		return true
	default:
		return false
	}
}

// Drain removes all pending (not yet picked up by a worker) tasks and returns
// the count discarded.  In-flight sends are not interrupted.
func (q *ForwardQueue) Drain() int64 {
	var n int64
	for {
		select {
		case <-q.tasks:
			n++
			q.queued.Add(-1)
		default:
			return n
		}
	}
}

func (q *ForwardQueue) QueuedCount() int64  { return q.queued.Load() }
func (q *ForwardQueue) InFlightCount() int64 { return q.inFlight.Load() }

func (q *ForwardQueue) worker(ctx context.Context) {
	defer q.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-q.tasks:
			if !ok {
				return
			}
			q.queued.Add(-1)
			q.inFlight.Add(1)
			q.process(ctx, task)
			q.inFlight.Add(-1)
		}
	}
}

func (q *ForwardQueue) process(ctx context.Context, task ForwardTask) {
	result := ForwardResult{
		EventID:       task.Evt.ID,
		IngestionPath: task.IngestionPath,
	}

	if q.maxAge > 0 && time.Since(task.EnqueuedAt) > q.maxAge {
		result.Skipped = true
		result.SkipReason = "max_age_exceeded"
		q.logger.Debug("forward task discarded: stale",
			"event_id", task.Evt.ID,
			"age_ms", time.Since(task.EnqueuedAt).Milliseconds(),
			"max_age_ms", q.maxAge.Milliseconds(),
		)
		if q.onResult != nil {
			q.onResult(result)
		}
		return
	}

	sendCtx := ctx
	var cancel context.CancelFunc
	if q.timeout > 0 {
		sendCtx, cancel = context.WithTimeout(ctx, q.timeout)
		defer cancel()
	}

	start := time.Now()
	status, err := q.doSend(sendCtx, task.Evt)
	result.ElapsedMS = time.Since(start).Milliseconds()
	result.HTTPStatus = status
	result.Err = err

	if q.onResult != nil {
		q.onResult(result)
	}
}
