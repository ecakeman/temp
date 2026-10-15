package fingerprint

import (
	"regexp"
	"strconv"
	"strings"
)

// HTTPMessage is the structural view of a banner. It never decides which
// product is present; product rules only see Server when this view is valid
// and the header values do not conflict.
type HTTPMessage struct {
	OK         bool
	StatusLine string
	Server     string
	Conflict   bool
}

var statusLinePattern = regexp.MustCompile(`(?i)^(HTTP/1\.[0-9])[ \t]+([0-9]{3})(?:[ \t]+\S.*)?$`)

// ParseHTTP accepts only a banner whose first line is an HTTP/1.x status line
// with a status code from 100 to 599. Headers are read until the first blank
// line, so text in the body cannot supply a Server value.
func ParseHTTP(banner string) HTTPMessage {
	line, rest := cutLine(banner)
	matches := statusLinePattern.FindStringSubmatch(line)
	if matches == nil {
		return HTTPMessage{}
	}
	code, err := strconv.Atoi(matches[2])
	if err != nil || code < 100 || code > 599 {
		return HTTPMessage{}
	}
	var server string
	seen := false
	conflict := false
	for rest != "" {
		header, next := cutLine(rest)
		rest = next
		if header == "" {
			break
		}
		name, value, ok := splitHeader(header)
		if !ok || !strings.EqualFold(name, "Server") {
			continue
		}
		value = strings.TrimSpace(value)
		if !seen {
			server = value
			seen = true
			continue
		}
		if value != server {
			conflict = true
			server = ""
		}
	}
	return HTTPMessage{
		OK:         true,
		StatusLine: line,
		Server:     server,
		Conflict:   conflict,
	}
}

func cutLine(s string) (line, rest string) {
	i := strings.IndexAny(s, "\r\n")
	if i < 0 {
		return s, ""
	}
	line = s[:i]
	rest = s[i:]
	switch {
	case strings.HasPrefix(rest, "\r\n"):
		rest = rest[2:]
	default:
		rest = rest[1:]
	}
	return line, rest
}

func splitHeader(line string) (name, value string, ok bool) {
	name, value, ok = strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, " \t") {
		return "", "", false
	}
	return name, value, true
}
