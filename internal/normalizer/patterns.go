package normalizer

import (
	"regexp"
	"strings"
)

var keyValueRE = regexp.MustCompile(`([A-Za-z_]+)=("([^"]*)"|[^\s]+)`)

func classifySeverity(msg string, sevNum *int) string {
	if sev, ok := classifyOPCUASeverity(msg); ok {
		return sev
	}

	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "[critical]"), strings.Contains(m, "fatal"), strings.Contains(m, "critical"):
		return "critical"
	case strings.Contains(m, "[error]"), strings.Contains(m, " error"):
		return "error"
	case strings.Contains(m, "[warn]"), strings.Contains(m, "warning"), strings.Contains(m, " warn"):
		return "warning"
	case strings.Contains(m, "[debug]"), strings.Contains(m, "debug"):
		return "debug"
	case strings.Contains(m, "[info]"), strings.Contains(m, " info"):
		return "info"
	}

	if sevNum == nil {
		return "info"
	}
	switch *sevNum {
	case 0, 1, 2:
		return "critical"
	case 3:
		return "error"
	case 4:
		return "warning"
	case 5, 6:
		return "info"
	case 7:
		return "debug"
	default:
		return "info"
	}
}

func classifyCategory(msg string) string {
	if isOPCUAMessage(msg) {
		return classifyOPCUACategory(msg)
	}

	m := strings.ToLower(msg)
	switch {
	case containsAny(m, "failed login", "unauthorized", "protected tag", "illegal data address", "illegal function", "rejected connection", "rejected", "invalid command"):
		return "security"
	case containsAny(m, "user ", " wrote value", "set tag", " command", "operator"):
		return "operator_action"
	case containsAny(m, "timeout", "retry", "max retry", "connection failed", "polling error"):
		return "communication"
	case containsAny(m, "client accepted", "client connected", "new client connected", "closed the connection", "disconnected"):
		return "network"
	case containsAny(m, "scan cycle time exceeded", "runtime", "program started", "server started", "version", "starting"):
		return "runtime"
	case containsAny(m, "alarm", "high priority", "threshold"):
		return "alarm"
	default:
		return "system"
	}
}

func isOPCUAMessage(msg string) bool {
	return strings.Contains(strings.ToUpper(msg), "[OPCUA]")
}

func classifyOPCUACategory(msg string) string {
	u := strings.ToUpper(msg)
	l := strings.ToLower(msg)

	switch {
	case strings.Contains(u, "[CMD]"):
		return "operator_action"
	case strings.Contains(u, "[SESSION]"):
		return "network"
	case strings.Contains(u, "[SECURITY]"):
		return "security"
	case strings.Contains(u, "[STARTUP]"), strings.Contains(u, "[SHUTDOWN]"):
		return "runtime"
	case strings.Contains(u, "[ERROR]"):
		switch {
		case containsAny(l, "rejected", "unauthorized", "invalid certificate", "bad user", "denied"):
			return "security"
		case containsAny(l, "timeout", "disconnected", "connection failed"):
			return "communication"
		default:
			return "system"
		}
	case containsAny(l, "rejected connection"):
		return "security"
	case containsAny(l, "client session created", "client session closed"):
		return "network"
	default:
		return "system"
	}
}

func classifyOPCUASeverity(msg string) (string, bool) {
	u := strings.ToUpper(msg)
	l := strings.ToLower(msg)

	switch {
	case strings.Contains(u, "[ERROR]"):
		return "error", true
	case strings.Contains(u, "[SHUTDOWN]"), strings.Contains(u, "[STARTUP]"):
		return "info", true
	case strings.Contains(u, "[SECURITY]"), containsAny(l, "rejected connection", "rejected", "unauthorized", "denied", "invalid certificate"):
		return "warning", true
	case containsAny(l, "authentication failed", "bad user"):
		return "error", true
	case strings.Contains(u, "[CMD]") && (containsAny(u, "MODE=PULSE", "MODE=MAINTAINED")):
		if containsAny(l, "protected tag", "safety tag", "emergency", "reset", "unauthorized", "guest", "failed") {
			return "warning", true
		}
		return "info", true
	case containsAny(l, "protected tag", "safety tag", "emergency", "reset"):
		return "warning", true
	default:
		return "", false
	}
}

func enrichOPCUATags(msg string, tags map[string]string) {
	if !isOPCUAMessage(msg) || tags == nil {
		return
	}

	u := strings.ToUpper(msg)
	if strings.Contains(u, "[READ][CMD]") {
		tags["opcua_operation"] = "READ"
		tags["opcua_event_type"] = "CMD"
	} else if strings.Contains(u, "[WRITE][CMD]") {
		tags["opcua_operation"] = "WRITE"
		tags["opcua_event_type"] = "CMD"
	} else {
		if strings.Contains(u, "[CMD]") {
			tags["opcua_event_type"] = "CMD"
		}
		if strings.Contains(u, "[SESSION]") {
			tags["opcua_event_type"] = "SESSION"
		}
		if strings.Contains(u, "[SECURITY]") {
			tags["opcua_event_type"] = "SECURITY"
		}
		if strings.Contains(u, "[ERROR]") {
			tags["opcua_event_type"] = "ERROR"
		}
		if strings.Contains(u, "[STARTUP]") {
			tags["opcua_event_type"] = "STARTUP"
		}
		if strings.Contains(u, "[SHUTDOWN]") {
			tags["opcua_event_type"] = "SHUTDOWN"
		}
	}

	if v := extractKeyValue(msg, "User"); v != "" {
		tags["user"] = v
	}
	if v := extractKeyValue(msg, "NodeId"); v != "" {
		tags["node_id"] = v
	}
	if v := extractKeyValue(msg, "Browse"); v != "" {
		tags["browse_name"] = v
	}
	if v := extractKeyValue(msg, "Display"); v != "" {
		tags["display_name"] = v
	}
	if v := extractKeyValue(msg, "Mode"); v != "" {
		tags["mode"] = v
	}
	if v := extractKeyValue(msg, "Value"); v != "" {
		tags["value"] = v
	}

	if detectSensitiveAction(msg) {
		tags["sensitive_action"] = "true"
	}

	l := strings.ToLower(msg)
	if strings.Contains(u, "[CMD]") {
		tags["mitre_ics_tactic"] = "Impair Process Control"
		tags["mitre_ics_technique_hint"] = "Manipulation of Control"
	}
	if containsAny(l, "rejected", "unauthorized", "invalid certificate", "bad user", "denied") || strings.Contains(u, "[SECURITY]") {
		tags["mitre_ics_tactic"] = "Initial Access / Defense Evasion"
		tags["mitre_ics_technique_hint"] = "Unauthorized Access Attempt"
	}
}

func extractKeyValue(msg string, key string) string {
	matches := keyValueRE.FindAllStringSubmatch(msg, -1)
	for _, m := range matches {
		if len(m) < 4 {
			continue
		}
		if strings.EqualFold(m[1], key) {
			v := m[2]
			v = strings.Trim(v, `"`)
			return v
		}
	}
	return ""
}

func detectSensitiveAction(msg string) bool {
	m := strings.ToLower(msg)
	return containsAny(
		m,
		"reset",
		"emergency",
		"stop",
		"start",
		"commandedemarrage",
		"safety",
		"relay",
		"valve",
		"vanne",
		"switch",
		"dcy",
	)
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
