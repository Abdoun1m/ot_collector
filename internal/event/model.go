package event

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type Event struct {
	ID            string            `json:"id"`
	Timestamp     string            `json:"timestamp"`
	ReceivedAt    string            `json:"received_at"`
	Zone          string            `json:"zone"`
	SourceType    string            `json:"source_type"`
	AssetName     string            `json:"asset_name"`
	AssetIP       string            `json:"asset_ip"`
	Severity      string            `json:"severity"`
	Protocol      string            `json:"protocol"`
	EventCategory string            `json:"event_category"`
	Message       string            `json:"message"`
	Raw           string            `json:"raw"`
	Tags          map[string]string `json:"tags"`
}

func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}

