package fingerprint

import (
	"testing"
)

func TestNormalizeTextEscapes(t *testing.T) {
	got := Normalize(`J\x00\x00\x00\n8.0.32\x00`)
	want := string([]byte{'J', 0, 0, 0, '\n', '8', '.', '0', '.', '3', '2', 0})
	if got != want {
		t.Fatalf("mysql text escape:\n got %q\nwant %q", got, want)
	}
}

func TestNormalizeKeepsRealControls(t *testing.T) {
	raw := string([]byte{0x16, 0x03, 0x01, 0x00, 'A'})
	if got := Normalize(raw); got != raw {
		t.Fatalf("binary banner changed: %q", got)
	}
	if got := Normalize("plain SSH-2.0-OpenSSH_8.9p1"); got != "plain SSH-2.0-OpenSSH_8.9p1" {
		t.Fatalf("plain text changed: %q", got)
	}
}

func TestNormalizeCRLFText(t *testing.T) {
	got := Normalize(`QUIT\r\n`)
	if got != "QUIT\r\n" {
		t.Fatalf("got %q", got)
	}
}
