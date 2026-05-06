package syslog

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ParsedMessage struct {
	Priority       *int
	Facility       *int
	SeverityNumber *int
	Timestamp      string
	Hostname       string
	AppName        string
	Message        string
	Raw            string
	Format         string
}

type IncomingLog struct {
	Raw       string
	SourceIP  string
	Transport string
}

var (
	rfc5424RE = regexp.MustCompile(`^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$`)
	rfc3164RE = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(\S+)\s+([^:]+):\s*(.*)$`)
)

func Parse(raw string) ParsedMessage {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ParsedMessage{
			Message:   "",
			Raw:       "",
			Format:    "raw",
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		}
	}

	if m := rfc5424RE.FindStringSubmatch(raw); len(m) == 9 {
		p, _ := strconv.Atoi(m[1])
		fac := p / 8
		sev := p % 8
		msg := strings.TrimSpace(m[8])
		if msg == "" {
			msg = raw
		}
		return ParsedMessage{
			Priority:       &p,
			Facility:       &fac,
			SeverityNumber: &sev,
			Timestamp:      normalizeTime(m[3]),
			Hostname:       m[4],
			AppName:        m[5],
			Message:        msg,
			Raw:            raw,
			Format:         "rfc5424",
		}
	}

	if m := rfc3164RE.FindStringSubmatch(raw); len(m) == 5 {
		return ParsedMessage{
			Priority:  nil,
			Timestamp: parseRFC3164Timestamp(m[1]),
			Hostname:  m[2],
			AppName:   m[3],
			Message:   m[4],
			Raw:       raw,
			Format:    "rfc3164",
		}
	}

	return ParsedMessage{
		Message:   raw,
		Raw:       raw,
		Format:    "raw",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func parseRFC3164Timestamp(ts string) string {
	layout := "Jan 2 15:04:05"
	t, err := time.Parse(layout, ts)
	if err != nil {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	now := time.Now()
	parsed := time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location())
	return parsed.UTC().Format(time.RFC3339Nano)
}

func normalizeTime(ts string) string {
	if ts == "" || ts == "-" {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.UTC().Format(time.RFC3339Nano)
	}
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.UTC().Format(time.RFC3339Nano)
	}
	return time.Now().UTC().Format(time.RFC3339Nano)
}
