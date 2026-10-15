package fingerprint

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/ecakeman/temp/internal/model"
)

// Rule is one entry in rules/rules.json. Product rules use a higher priority
// than protocol-only rules. Ports never reject a match; a listed port only
// breaks a tie.
type Rule struct {
	Name         string  `json:"name"`
	Priority     int     `json:"priority"`
	Pattern      string  `json:"pattern"`
	Ports        []int   `json:"ports,omitempty"`
	Protocol     string  `json:"protocol"`
	Product      string  `json:"product"`
	VersionGroup string  `json:"version_group,omitempty"`
	OSHintGroup  string  `json:"os_hint_group,omitempty"`
	Confidence   float64 `json:"confidence"`
}

type compiledRule struct {
	rule Rule
	re   *regexp.Regexp
}

// Engine matches normalized banners against compiled rules.
type Engine struct {
	rules []compiledRule
}

// Load reads and validates a rule file. A bad pattern, confidence, or capture
// group name is a hard error so a broken config cannot silently drop coverage.
func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules %s: %w", path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var rules []Rule
	if err := dec.Decode(&rules); err != nil {
		return nil, fmt.Errorf("parse rules %s: %w", path, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse rules %s: trailing data", path)
		}
		return nil, fmt.Errorf("parse rules %s: trailing data: %w", path, err)
	}
	if rules == nil {
		return nil, fmt.Errorf("parse rules %s: expected a JSON array", path)
	}
	compiled := make([]compiledRule, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for i, rule := range rules {
		if err := validateRule(rule, seen); err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", i, rule.Name, err)
		}
		seen[rule.Name] = struct{}{}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %s: compile pattern: %w", rule.Name, err)
		}
		if rule.VersionGroup != "" && re.SubexpIndex(rule.VersionGroup) < 0 {
			return nil, fmt.Errorf("rule %s: missing capture group %q", rule.Name, rule.VersionGroup)
		}
		if rule.OSHintGroup != "" && re.SubexpIndex(rule.OSHintGroup) < 0 {
			return nil, fmt.Errorf("rule %s: missing capture group %q", rule.Name, rule.OSHintGroup)
		}
		compiled = append(compiled, compiledRule{rule: rule, re: re})
	}
	return &Engine{rules: compiled}, nil
}

func validateRule(rule Rule, seen map[string]struct{}) error {
	if strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if _, ok := seen[rule.Name]; ok {
		return fmt.Errorf("duplicate name")
	}
	if strings.TrimSpace(rule.Pattern) == "" {
		return fmt.Errorf("pattern is required")
	}
	if strings.TrimSpace(rule.Protocol) == "" {
		return fmt.Errorf("protocol is required")
	}
	if rule.Confidence < 0 || rule.Confidence > 1 {
		return fmt.Errorf("confidence %v is outside [0,1]", rule.Confidence)
	}
	for _, port := range rule.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid hint port %d", port)
		}
	}
	return nil
}

// IdentifyBatch preserves input order. One unreadable banner cannot abort the batch.
func (e *Engine) IdentifyBatch(items []model.Input) []model.Result {
	out := make([]model.Result, len(items))
	for i, item := range items {
		out[i] = e.Identify(item.IP, item.Port, item.Banner)
	}
	return out
}

// Identify returns unknown instead of failing when nothing matches.
func (e *Engine) Identify(ip string, port int, banner string) (res model.Result) {
	defer func() {
		if recover() != nil {
			res = model.Unknown(ip, port)
		}
	}()
	normalized := Normalize(banner)
	bestScore := -1
	bestPort := false
	var best *compiledRule
	var bestMatch []string
	for i := range e.rules {
		cr := &e.rules[i]
		match := cr.re.FindStringSubmatch(normalized)
		if match == nil {
			continue
		}
		portHit := portListed(cr.rule.Ports, port)
		if best == nil || cr.rule.Priority > bestScore || (cr.rule.Priority == bestScore && portHit && !bestPort) {
			bestScore = cr.rule.Priority
			bestPort = portHit
			best = cr
			bestMatch = match
		}
	}
	if best == nil {
		return model.Unknown(ip, port)
	}
	return model.Result{
		IP:         ip,
		Port:       port,
		Protocol:   best.rule.Protocol,
		Product:    best.rule.Product,
		Version:    capture(best.re, bestMatch, best.rule.VersionGroup),
		OSHint:     canonicalOS(capture(best.re, bestMatch, best.rule.OSHintGroup)),
		Confidence: best.rule.Confidence,
	}
}

func capture(re *regexp.Regexp, match []string, name string) string {
	if name == "" {
		return ""
	}
	idx := re.SubexpIndex(name)
	if idx < 0 || idx >= len(match) {
		return ""
	}
	return strings.TrimSpace(match[idx])
}

func portListed(ports []int, port int) bool {
	for _, candidate := range ports {
		if candidate == port {
			return true
		}
	}
	return false
}

func canonicalOS(hint string) string {
	if hint == "" {
		return ""
	}
	if known, ok := osNames[strings.ToLower(hint)]; ok {
		return known
	}
	return hint
}

var osNames = map[string]string{
	"ubuntu":    "Ubuntu",
	"debian":    "Debian",
	"freebsd":   "FreeBSD",
	"netbsd":    "NetBSD",
	"openbsd":   "OpenBSD",
	"centos":    "CentOS",
	"redhat":    "RedHat",
	"rocky":     "Rocky",
	"almalinux": "AlmaLinux",
	"alpine":    "Alpine",
	"windows":   "Windows",
	"amazon":    "Amazon",
	"kali":      "Kali",
	"raspbian":  "Raspbian",
}
