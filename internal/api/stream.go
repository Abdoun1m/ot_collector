package api

import (
	"sync"

	"github.com/Abdoun1m/ot_collector/internal/event"
)

type StreamHub struct {
	mu      sync.RWMutex
	nextID  int
	clients map[int]chan event.Event
}

func NewStreamHub() *StreamHub {
	return &StreamHub{
		clients: map[int]chan event.Event{},
	}
}

func (h *StreamHub) Subscribe() (int, <-chan event.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.nextID
	h.nextID++
	ch := make(chan event.Event, 256)
	h.clients[id] = ch
	return id, ch
}

func (h *StreamHub) Unsubscribe(id int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ch, ok := h.clients[id]; ok {
		delete(h.clients, id)
		close(ch)
	}
}

func (h *StreamHub) Publish(evt event.Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, ch := range h.clients {
		select {
		case ch <- evt:
		default:
		}
	}
}

