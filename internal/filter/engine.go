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

	maxEventsPerSec int
	dedupWindowSec  int
	debugStoreDrop  bool

	rules []config.RuleConfig

	stateMu      sync.Mutex
	dedupCache   map[string]dupState
	rateBySource map[string]rateState
	sampleCounts map[string]int
}

func New() *Engine {
	return &Engine{
		maxEventsPerSec: 800,
		dedupWindowSec:  5,
		rules:           []config.RuleConfig{},
		dedupCache:      map[string]dupState{},
		rateBySource:    map[string]rateState{},
		sampleCounts:    map[string]int{},
	}
}

func (e *Engine) ConfigureRuntime(maxEventsPerSec, dedupWindowSec int, debugStoreDrop bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if maxEventsPerSec >= 0 {
		e.maxEventsPerSec = maxEventsPerSec
	}
	if dedupWindowSec >= 0 {
		e.dedupWindowSec = dedupWindowSec
	}
	e.debugStoreDrop = debugStoreDrop
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

func (e *Engine) Evaluate(evt *event.Event) Decision {
	if evt == nil {
		return Decision{Store: true, Show: true, Drop: false, Reason: "nil_event_default"}
	}
	now := time.Now().UTC()
	e.mu.RLock()
	rules := make([]config.RuleConfig, len(e.rules))
	copy(rules, e.rules)
	maxEps := e.maxEventsPerSec
	dedupSec := e.dedupWindowSec
	debugStoreDrop := e.debugStoreDrop
	e.mu.RUnlock()

	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	if maxEps > 0 {
		sourceKey := evt.AssetIP
		if sourceKey == "" {
			sourceKey = evt.SourceType
		}
		sec := now.Unix()
		rs := e.rateBySource[sourceKey]
		if rs.second != sec {
			rs.second = sec
			rs.count = 0
		}
		rs.count++
		e.rateBySource[sourceKey] = rs
		if rs.count > maxEps {
			return e.dropDecision("rate_limit", "", debugStoreDrop)
		}
	}

	if dedupSec > 0 {
		dupKey := strings.Join([]string{evt.AssetIP, evt.SourceType, evt.Message}, "|")
		if ds, ok := e.dedupCache[dupKey]; ok && now.Sub(ds.lastSeen) <= time.Duration(dedupSec)*time.Second {
			e.dedupCache[dupKey] = dupState{lastSeen: now}
			return e.dropDecision("duplicate_window", "", debugStoreDrop)
		}
		e.dedupCache[dupKey] = dupState{lastSeen: now}
	}

	operation := strings.ToUpper(evt.Tags["opcua_operation"])
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

		switch strings.ToLower(rule.Action) {
		case "drop":
			return e.dropDecision("rule_drop", rule.ID, debugStoreDrop)
		case "forward_only":
			return Decision{Store: false, Forward: true, Show: true, Drop: false, MatchedRuleID: rule.ID, Reason: "rule_forward_only"}
		case "store_only":
			return Decision{Store: true, Forward: false, Show: true, Drop: false, MatchedRuleID: rule.ID, Reason: "rule_store_only"}
		case "sample":
			rate := rule.SampleRate
			if rate <= 0 {
				rate = 0.1
			}
			keepEvery := sampleToKeepEvery(rate)
			key := strings.Join([]string{rule.ID, evt.AssetIP, evt.AssetName, evt.EventCategory, evt.Message}, "|")
			e.sampleCounts[key]++
			if keepEvery <= 1 || e.sampleCounts[key]%keepEvery == 1 {
				return Decision{Store: rule.StoreLocally, Forward: rule.ForwardToDMZ, Show: true, Drop: false, Sampled: true, MatchedRuleID: rule.ID, Reason: "rule_sample_keep"}
			}
			return e.dropDecision("rule_sample_drop", rule.ID, debugStoreDrop)
		default: // keep
			return Decision{Store: rule.StoreLocally, Forward: rule.ForwardToDMZ, Show: true, Drop: false, MatchedRuleID: rule.ID, Reason: "rule_keep"}
		}
	}

	return Decision{Store: true, Forward: false, Show: true, Drop: false, Reason: "default_store_no_forward"}
}

func (e *Engine) dropDecision(reason, ruleID string, debugStoreDrop bool) Decision {
	return Decision{
		Store:         debugStoreDrop,
		Forward:       false,
		Show:          debugStoreDrop,
		Drop:          !debugStoreDrop,
		Sampled:       strings.Contains(reason, "sample"),
		MatchedRuleID: ruleID,
		Reason:        reason,
	}
}

func matchField(ruleValue, eventValue string) bool {
	rv := strings.TrimSpace(strings.ToLower(ruleValue))
	ev := strings.TrimSpace(strings.ToLower(eventValue))
	return rv == "*" || rv == "" || rv == ev
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
