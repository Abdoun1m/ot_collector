package config

import (
	"log/slog"
	"os"
)

type Config struct {
	Zone            string
	UDPSyslogAddr   string
	TCPSyslogAddr   string
	APIAddr         string
	EventsFile      string
	DMZCollectorURL string
	LogLevel        slog.Level
}

func Load() Config {
	cfg := Config{
		Zone:            getenv("OT_COLLECTOR_ZONE", "OT"),
		UDPSyslogAddr:   getenv("UDP_SYSLOG_ADDR", "0.0.0.0:514"),
		TCPSyslogAddr:   getenv("TCP_SYSLOG_ADDR", "0.0.0.0:1514"),
		APIAddr:         getenv("API_ADDR", "0.0.0.0:8088"),
		EventsFile:      getenv("EVENTS_FILE", "/data/events.jsonl"),
		DMZCollectorURL: getenv("DMZ_COLLECTOR_URL", ""),
		LogLevel:        parseLevel(getenv("LOG_LEVEL", "info")),
	}
	return cfg
}

func getenv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func parseLevel(v string) slog.Level {
	switch v {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

