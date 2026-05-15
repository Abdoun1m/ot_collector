package syslog

import "testing"

func TestParseRFC3164WithPriorityAndFilterlogAppName(t *testing.T) {
	raw := `<134>May 15 11:41:57 OPNsense.internal filterlog[34194]: 81,,,a8ab5e70f001bf0cfbc06896fadb9e87,em1,match,pass,in,4,0x0,,64,11121,0,DF,6,tcp,60,192.168.10.20,192.168.1.62,41378,4840,0,S,624066190,,64240,,mss;sackOK;TS;nop;wscale`

	parsed := Parse(raw)

	if parsed.Format != "rfc3164" {
		t.Fatalf("expected format rfc3164, got %q", parsed.Format)
	}
	if parsed.Hostname != "OPNsense.internal" {
		t.Fatalf("expected hostname OPNsense.internal, got %q", parsed.Hostname)
	}
	if parsed.AppName != "filterlog" {
		t.Fatalf("expected app_name filterlog, got %q", parsed.AppName)
	}
	if parsed.Message != "81,,,a8ab5e70f001bf0cfbc06896fadb9e87,em1,match,pass,in,4,0x0,,64,11121,0,DF,6,tcp,60,192.168.10.20,192.168.1.62,41378,4840,0,S,624066190,,64240,,mss;sackOK;TS;nop;wscale" {
		t.Fatalf("unexpected message: %q", parsed.Message)
	}
	if parsed.Priority == nil || *parsed.Priority != 134 {
		t.Fatalf("expected priority 134, got %#v", parsed.Priority)
	}
	if parsed.SeverityNumber == nil || *parsed.SeverityNumber != 6 {
		t.Fatalf("expected severity 6, got %#v", parsed.SeverityNumber)
	}
}

func TestNormalizeAppName(t *testing.T) {
	if got := normalizeAppName("filterlog[34194]"); got != "filterlog" {
		t.Fatalf("expected filterlog, got %q", got)
	}
	if got := normalizeAppName(" filterlog "); got != "filterlog" {
		t.Fatalf("expected trimmed app name, got %q", got)
	}
}
