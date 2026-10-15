package fingerprint

import "strings"

// Normalize decodes textual banner escapes without stripping real control bytes.
// JSON already turns "\n" and "\u0000" into the corresponding bytes. Scanners
// also embed the four characters '\','x','0','0'. Those are decoded here.
// Real NUL, TLS record headers, and other protocol bytes are preserved.
func Normalize(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			out = append(out, s[i])
			continue
		}
		value, size, ok := decodeEscape(s[i:])
		if !ok {
			out = append(out, s[i])
			continue
		}
		out = append(out, value...)
		i += size - 1
	}
	return string(out)
}

func decodeEscape(s string) (value []byte, size int, ok bool) {
	switch s[1] {
	case 'n':
		return []byte{'\n'}, 2, true
	case 'r':
		return []byte{'\r'}, 2, true
	case 't':
		return []byte{'\t'}, 2, true
	case '0':
		return []byte{0}, 2, true
	case '\\':
		return []byte{'\\'}, 2, true
	case 'x', 'X':
		if len(s) >= 4 && isHex(s[2]) && isHex(s[3]) {
			return []byte{unhex(s[2])<<4 | unhex(s[3])}, 4, true
		}
	}
	return nil, 0, false
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func unhex(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	default:
		return b - 'A' + 10
	}
}
