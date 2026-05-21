package filter

import (
	"strings"
	"sync"
	"time"

	"github.com/Abdoun1m/ot_collector/internal/config"
	"github.com/Abdoun1m/ot_collector/internal/event"
)

type Decision struct {
	Store         bool   `json:"store"`
	Forward       bool   `json:"forward"`
	Show          bool   `json:"show"`
	Drop          bool   `json:"drop"`
	Sampled       bool   `json:"sampled"`
	MatchedRuleID string `json:"matched_rule_id"`
	Reason        string `json:"decision_reason"`
}

type rateState struct {
	second int64
	count  int
}

type dupState struct {
	lastSeen time.Time
}

type Engine struct {
	mu sync.RWMutex

	rules []config.RuleConfig

	stateMu      sync.Mutex
	dedupCache   map[string]dupState
	rateBySource map[string]rateState
	sampleCounts map[string]int
}

func New() *Engine {
	return &Engine{
		rules:        []config.RuleConfig{},
		dedupCache:   map[string]dupState{},
		rateBySource: map[string]rateState{},
		sampleCounts: map[string]int{},
	}
}

func (e *Engine) ConfigureRuntime(maxEventsPerSec, dedupWindowSec int, debugStoreDrop bool) {
	// Kept for backwards compatibility with older callers. Runtime flood
	// controls now belong in RuleConfig and are evaluated per matched rule.
	_, _, _ = maxEventsPerSec, dedupWindowSec, debugStoreDrop
}

func (e *Engine) SetRules(rules []config.RuleConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = make([]config.RuleConfig, len(rules))
	copy(e.rules, rules)
}

func (e *Engine) Rules() []config.RuleConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]config.RuleConfig, len(e.rules))
	copy(out, e.rules)
	return out
}

// Evaluate applies the first matching enabled matrix rule. All storage,
// forwarding, sampling, duplicate-window, rate-limit, and UI visibility
// decisions come from that rule.
func (e *Engine) Evaluate(evt *event.Event) Decision {
	if evt == nil {
		return Decision{Store: true, Show: true, Drop: false, MatchedRuleID: "default-store-only", Reason: "nil_event_default"}
	}
	now := time.Now().UTC()
	e.mu.RLock()
	rules := make([]config.RuleConfig, len(e.rules))
	copy(rules, e.rules)
	e.mu.RUnlock()

	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	return e.applyRules(evt, rules, now)
}

// EvaluateRulesOnly is retained for older tests/callers. It now intentionally
// uses the same matrix path as Evaluate.
func (e *Engine) EvaluateRulesOnly(evt *event.Event) Decision {
	return e.Evaluate(evt)
}

// applyRules must be called with e.stateMu held (sample counter is updated inside).
func (e *Engine) applyRules(evt *event.Event, rules []config.RuleConfig, now time.Time) Decision {
	operation := operationFor(evt)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !matchField(rule.SourceType, evt.SourceType) {
			continue
		}
		if !matchField(rule.Asset, evt.AssetName) && !matchField(rule.Asset, evt.AssetIP) {
			continue
		}
		if !matchField(rule.Category, evt.EventCategory) {
			continue
		}
		if !matchField(rule.Severity, evt.Severity) {
			continue
		}
		if !matchField(rule.Operation, operation) {
			continue
		}
		if !matchField(rule.EventType, evt.Tags["event_type"]) {
			continue
		}
		if rule.MessageContains != "" && !messageContains(evt, rule.MessageContains) {
			continue
		}
		if !matchTag(rule, evt) {
			continue
		}

		show := ruleShowInUI(rule)
		if rule.RateLimitPerSecond > 0 {
			key := rateKey(rule, evt)
			sec := now.Unix()
			rs := e.rateBySource[key]
			if rs.second != sec {
				rs.second = sec
				rs.count = 0
			}
			rs.count++
			e.rateBySource[key] = rs
			if rs.count > rule.RateLimitPerSecond {
				return e.dropDecision("rule_rate_limit", rule.ID)
			}
		}

		if rule.DedupWindowSeconds > 0 {
			key := dedupKey(rule, evt, operation)
			if ds, ok := e.dedupCache[key]; ok && now.Sub(ds.lastSeen) <= time.Duration(rule.DedupWindowSeconds)*time.Second {
				e.dedupCache[key] = dupState{lastSeen: now}
				return e.dropDecision("rule_duplicate_window", rule.ID)
			}
			e.dedupCache[key] = dupState{lastSeen: now}
		}

		switch strings.ToLower(rule.Action) {
		case "drop":
			return Decision{Store: rule.StoreLocally, Forward: false, Show: show && rule.StoreLocally, Drop: true, MatchedRuleID: rule.ID, Reason: "rule_drop"}
		case "forward_only":
			return Decision{Store: false, Forward: true, Show: show, Drop: false, MatchedRuleID: rule.ID, Reason: "rule_forward_only"}
		case "store_only":
			return Decision{Store: true, Forward: false, Show: show, Drop: false, MatchedRuleID: rule.ID, Reason: "rule_store_only"}
		case "store_and_forward":
			return Decision{Store: true, Forward: true, Show: show, Drop: false, MatchedRuleID: rule.ID, Reason: "rule_store_and_forward"}
		case "sample":
			rate := rule.SampleRate
			if rate <= 0 {
				rate = 0.1
			}
			keepEvery := sampleToKeepEvery(rate)
			key := strings.Join([]string{rule.ID, evt.AssetIP, evt.AssetName, evt.EventCategory, evt.Message}, "|")
			e.sampleCounts[key]++
			if keepEvery <= 1 || e.sampleCounts[key]%keepEvery == 1 {
				return Decision{Store: rule.StoreLocally, Forward: rule.ForwardToDMZ, Show: show, Drop: false, Sampled: true, MatchedRuleID: rule.ID, Reason: "rule_sample_keep"}
			}
			return e.dropDecision("rule_sample_drop", rule.ID)
		default: // keep
			return Decision{Store: rule.StoreLocally, Forward: rule.ForwardToDMZ, Show: show, Drop: false, MatchedRuleID: rule.ID, Reason: "rule_keep"}
		}
	}

	return Decision{Store: true, Forward: false, Show: true, Drop: false, MatchedRuleID: "default-store-only", Reason: "default_store_only"}
}

func (e *Engine) dropDecision(reason, ruleID string) Decision {
	return Decision{
		Store:         false,
		Forward:       false,
		Show:          false,
		Drop:          true,
		Sampled:       strings.Contains(reason, "sample"),
		MatchedRuleID: ruleID,
		Reason:        reason,
	}
}

func operationFor(evt *event.Event) string {
	if evt == nil || evt.Tags == nil {
		return ""
	}
	if op := evt.Tags["opcua_operation"]; op != "" {
		return strings.ToUpper(op)
	}
	return strings.ToUpper(evt.Tags["operation"])
}

func messageContains(evt *event.Event, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" || needle == "*" {
		return true
	}
	haystack := strings.ToLower(strings.Join([]string{evt.Message, evt.Raw}, " "))
	return strings.Contains(haystack, needle)
}

func matchTag(rule config.RuleConfig, evt *event.Event) bool {
	key := strings.TrimSpace(rule.TagKey)
	if key == "" || key == "*" {
		return true
	}
	if evt == nil || evt.Tags == nil {
		return false
	}
	value, ok := evt.Tags[key]
	if !ok {
		return false
	}
	return matchField(rule.TagValue, value)
}

func ruleShowInUI(rule config.RuleConfig) bool {
	if rule.ShowInUI == nil {
		return true
	}
	return *rule.ShowInUI
}

func rateKey(rule config.RuleConfig, evt *event.Event) string {
	source := evt.AssetIP
	if source == "" {
		source = evt.AssetName
	}
	if source == "" {
		source = evt.SourceType
	}
	return strings.Join([]string{rule.ID, source}, "|")
}

func dedupKey(rule config.RuleConfig, evt *event.Event, operation string) string {
	return strings.Join([]string{
		rule.ID,
		evt.AssetIP,
		evt.AssetName,
		evt.SourceType,
		evt.EventCategory,
		evt.Severity,
		operation,
		evt.Tags["event_type"],
		evt.Message,
	}, "|")
}

func matchField(ruleValue, eventValue string) bool {
	rv := comparableValue(ruleValue)
	ev := comparableValue(eventValue)
	return rv == "*" || rv == "" || rv == ev
}

func comparableValue(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.ReplaceAll(v, "-", "_")
	if v == "warn" {
		return "warning"
	}
	return v
}

func sampleToKeepEvery(sampleRate float64) int {
	if sampleRate <= 0 {
		return 10
	}
	if sampleRate >= 1 {
		return 1
	}
	return int(1 / sampleRate)
}
