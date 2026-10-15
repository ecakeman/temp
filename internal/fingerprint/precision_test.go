package fingerprint

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ecakeman/temp/internal/model"
)

func TestPrecisionDecoys(t *testing.T) {
	engine := loadTestEngine(t)
	cases := []struct {
		name   string
		banner string
		port   int
		want   model.Result
	}{
		{
			name:   "nginx text decoy",
			banner: "random text nginx/1.24.0",
			port:   80,
			want:   model.Result{Protocol: "unknown"},
		},
		{
			name:   "server header without status",
			banner: "Server: nginx/1.24.0",
			port:   80,
			want:   model.Result{Protocol: "unknown"},
		},
		{
			name:   "valid nginx",
			banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/plain",
			port:   80,
			want:   model.Result{Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
		},
		{
			name:   "nginx over lf",
			banner: "HTTP/1.1 200 OK\nServer: nginx/1.24.0\n",
			port:   18080,
			want:   model.Result{Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
		},
		{
			name:   "header case",
			banner: "http/1.1 200 ok\r\nSeRvEr: nginx/1.24.0\r\n",
			port:   8080,
			want:   model.Result{Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
		},
		{
			name:   "apache only in body",
			banner: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nApache/2.4.57",
			port:   80,
			want:   model.Result{Protocol: "HTTP", Confidence: 0.5},
		},
		{
			name:   "unknown product ignores body apache",
			banner: "HTTP/1.1 200 OK\r\nServer: custom-web/2.7\r\n\r\nApache/2.4.57",
			port:   443,
			want:   model.Result{Protocol: "HTTP", Confidence: 0.5},
		},
		{
			name:   "conflicting server headers",
			banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nServer: Apache/2.4.57\r\n",
			port:   80,
			want:   model.Result{Protocol: "HTTP", Confidence: 0.5},
		},
		{
			name:   "repeated identical server",
			banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nServer: nginx/1.24.0\r\n",
			port:   80,
			want:   model.Result{Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
		},
		{
			name:   "no server header",
			banner: "HTTP/1.0 204 No Content\r\n\r\n",
			port:   81,
			want:   model.Result{Protocol: "HTTP", Confidence: 0.5},
		},
		{
			name:   "invalid status code",
			banner: "HTTP/1.1 999 Weird\r\nServer: nginx/1.24.0\r\n",
			port:   80,
			want:   model.Result{Protocol: "unknown"},
		},
		{
			name:   "ssh prefix decoy",
			banner: "noise SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
			port:   22,
			want:   model.Result{Protocol: "unknown"},
		},
		{
			name:   "smtp is not ftp",
			banner: "220 smtp.example.test ESMTP ready",
			port:   25,
			want:   model.Result{Protocol: "unknown"},
		},
		{
			name:   "proftpd mentioned later",
			banner: "220 FTP server ready. Later mentions ProFTPD 1.3.7",
			port:   21,
			want:   model.Result{Protocol: "FTP", Confidence: 0.55},
		},
		{
			name:   "proftpd greeting",
			banner: "220 ProFTPD 1.3.7 Server (ProFTPD)",
			port:   2121,
			want:   model.Result{Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7", Confidence: 0.9},
		},
		{
			name:   "mysql sentence decoy",
			banner: "database error: MySQL 8.0.32",
			port:   3306,
			want:   model.Result{Protocol: "unknown"},
		},
		{
			name:   "mysql newline decoy",
			banner: "arbitrary banner\n8.0.32",
			port:   3306,
			want:   model.Result{Protocol: "unknown"},
		},
		{
			name:   "mysql explicit label",
			banner: "MySQL version 8.0.32",
			port:   13306,
			want:   model.Result{Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", Confidence: 0.85},
		},
		{
			name:   "redis sentence decoy",
			banner: "application failed: -ERR something failed",
			port:   6379,
			want:   model.Result{Protocol: "unknown"},
		},
		{
			name:   "redis error inside http body",
			banner: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n-ERR wrong number of arguments for 'get' command",
			port:   8080,
			want:   model.Result{Protocol: "HTTP", Confidence: 0.5},
		},
		{
			name:   "redis original error",
			banner: "-ERR wrong number of arguments for 'get' command",
			port:   6379,
			want:   model.Result{Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		},
		{
			name:   "redis wrongpass",
			banner: "-WRONGPASS invalid username-password pair",
			port:   6380,
			want:   model.Result{Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		},
		{
			name:   "tls too short",
			banner: string([]byte{0x16, 0x03, 0x01, 0x00, 0xa5}),
			port:   443,
			want:   model.Result{Protocol: "unknown"},
		},
		{
			name:   "tls bad handshake type",
			banner: string([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x63, 0x00, 0x00, 0x00}),
			port:   443,
			want:   model.Result{Protocol: "unknown"},
		},
		{
			name:   "empty banner",
			banner: "",
			port:   9,
			want:   model.Result{Protocol: "unknown"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Identify("203.0.113.10", tc.port, tc.banner)
			tc.want.IP = "203.0.113.10"
			tc.want.Port = tc.port
			assertResult(t, got, tc.want)
		})
	}
}

func TestMixedUnknownBatch(t *testing.T) {
	engine := loadTestEngine(t)
	got := engine.IdentifyBatch([]model.Input{
		{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{IP: "9.9.9.1", Port: 80, Banner: "random text nginx/1.24.0"},
		{IP: "9.9.9.2", Port: 1, Banner: ""},
		{IP: "1.2.3.5", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"},
		{IP: "9.9.9.3", Port: 3306, Banner: "database error: MySQL 8.0.32"},
	})
	if len(got) != 5 {
		t.Fatalf("len %d", len(got))
	}
	assertResult(t, got[0], model.Result{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95})
	assertResult(t, got[1], model.Result{IP: "9.9.9.1", Port: 80, Protocol: "unknown"})
	assertResult(t, got[2], model.Result{IP: "9.9.9.2", Port: 1, Protocol: "unknown"})
	assertResult(t, got[3], model.Result{IP: "1.2.3.5", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9})
	assertResult(t, got[4], model.Result{IP: "9.9.9.3", Port: 3306, Protocol: "unknown"})
}

func TestInvalidSourceRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	body := `[{"name":"bad","priority":1,"pattern":"a","protocol":"HTTP","confidence":0.2,"source":"body"}]`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid source to fail")
	}
}

func TestCustomRuleFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	body := `[{
		"name":"widget",
		"priority":90,
		"source":"http_server",
		"pattern":"^Widget/(?P<version>\\d+)$",
		"protocol":"HTTP",
		"product":"Widget",
		"version_group":"version",
		"confidence":0.42
	}]`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := engine.Identify("198.51.100.8", 9, "HTTP/1.1 200 OK\r\nServer: Widget/4\r\n")
	assertResult(t, got, model.Result{
		IP: "198.51.100.8", Port: 9, Protocol: "HTTP", Product: "Widget", Version: "4", Confidence: 0.42,
	})
	bare := engine.Identify("198.51.100.8", 9, "Server: Widget/4")
	assertResult(t, bare, model.Result{IP: "198.51.100.8", Port: 9, Protocol: "unknown"})
}
