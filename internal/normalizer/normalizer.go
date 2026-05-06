package normalizer

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/event"
	"github.com/Abdoun1m/ot_collector/internal/sources"
	"github.com/Abdoun1m/ot_collector/internal/syslog"
)

func FromParsed(zone string, p syslog.ParsedMessage, sourceIP string) event.Event {
	src := sources.Resolve(sourceIP, p.Hostname, p.AppName, p.Message)
	if src.AssetIP == "" {
		src.AssetIP = sourceIP
	}

	tags := map[string]string{
		"syslog_format": p.Format,
		"hostname":      p.Hostname,
		"app_name":      p.AppName,
	}
	enrichOPCUATags(p.Message, tags)

	return event.Event{
		ID:            newID(),
		Timestamp:     p.Timestamp,
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Zone:          zone,
		SourceType:    src.SourceType,
		AssetName:     src.AssetName,
		AssetIP:       src.AssetIP,
		Severity:      classifySeverity(p.Message, p.SeverityNumber),
		Protocol:      "syslog",
		EventCategory: classifyCategory(p.Message),
		Message:       p.Message,
		Raw:           p.Raw,
		Tags:          tags,
	}
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}
