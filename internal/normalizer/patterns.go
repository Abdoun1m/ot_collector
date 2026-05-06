package normalizer

import "strings"

func classifySeverity(msg string, sevNum *int) string {
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

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

