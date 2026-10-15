package fingerprint

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ecakeman/temp/internal/model"
)

func TestSampleInput(t *testing.T) {
	engine := loadTestEngine(t)
	var inputs []model.Input
	readJSON(t, repoPath("testdata", "input.json"), &inputs)
	if len(inputs) != 20 {
		t.Fatalf("sample size = %d, want 20", len(inputs))
	}
	want := []model.Result{
		{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
		{IP: "1.2.3.5", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
		{IP: "1.2.3.6", Port: 443, Protocol: "HTTP", Product: "Apache", Version: "2.4.57", Confidence: 0.9},
		{IP: "1.2.3.7", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", Confidence: 0.9},
		{IP: "1.2.3.8", Port: 6379, Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		{IP: "1.2.3.9", Port: 21, Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7", Confidence: 0.9},
		{IP: "1.2.3.10", Port: 8080, Protocol: "HTTP", Product: "Jetty", Version: "9.4.51", Confidence: 0.85},
		{IP: "1.2.3.11", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "9.3", OSHint: "Debian", Confidence: 0.95},
		{IP: "1.2.3.12", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.18.0", OSHint: "Ubuntu", Confidence: 0.9},
		{IP: "1.2.3.13", Port: 443, Protocol: "HTTP", Product: "Apache", Version: "2.4.41", OSHint: "Ubuntu", Confidence: 0.9},
		{IP: "1.2.3.14", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "5.7.42", Confidence: 0.9},
		{IP: "1.2.3.15", Port: 6379, Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		{IP: "1.2.3.16", Port: 21, Protocol: "FTP", Product: "vsFTPd", Version: "3.0.5", Confidence: 0.9},
		{IP: "1.2.3.17", Port: 8443, Protocol: "HTTP", Product: "nginx", Version: "1.25.3", Confidence: 0.9},
		{IP: "1.2.3.18", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "4.3", Confidence: 0.95},
		{IP: "1.2.3.19", Port: 9999, Protocol: "TLS", Confidence: 0.6},
		{IP: "1.2.3.20", Port: 8888, Protocol: "HTTP", Product: "Microsoft-IIS", Version: "10.0", Confidence: 0.9},
		{IP: "1.2.3.21", Port: 6379, Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		{IP: "1.2.3.22", Port: 21, Protocol: "FTP", Product: "Pure-FTPd", Confidence: 0.85},
		{IP: "1.2.3.23", Port: 12345, Protocol: "unknown"},
	}
	got := engine.IdentifyBatch(inputs)
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		assertResult(t, got[i], want[i])
	}
}

func TestEngineEdges(t *testing.T) {
	engine := loadTestEngine(t)
	mysql := string([]byte{'J', 0, 0, 0, '\n', '5', '.', '7', '.', '4', '2', 0})
	cases := []struct {
		name   string
		banner string
		port   int
		want   model.Result
	}{
		{
			name:   "http without server header",
			banner: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello",
			port:   8080,
			want:   model.Result{Protocol: "HTTP", Confidence: 0.5},
		},
		{
			name:   "lowercase nginx and crlf",
			banner: "http/1.1 404 not found\r\nserver: nginx/1.24.0\r\n",
			port:   8081,
			want:   model.Result{Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
		},
		{
			name:   "raw mysql nul",
			banner: mysql,
			port:   13306,
			want:   model.Result{Protocol: "MySQL", Product: "MySQL", Version: "5.7.42", Confidence: 0.9},
		},
		{
			name:   "mysql label",
			banner: "mysql version 8.0.32",
			port:   3306,
			want:   model.Result{Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", Confidence: 0.85},
		},
		{
			name:   "empty banner",
			banner: "",
			port:   1,
			want:   model.Result{Protocol: "unknown"},
		},
		{
			name:   "quit is not ftp",
			banner: "QUIT\r\n",
			port:   21,
			want:   model.Result{Protocol: "unknown"},
		},
		{
			name:   "generic ftp",
			banner: "220 FTP server ready",
			port:   2121,
			want:   model.Result{Protocol: "FTP", Confidence: 0.55},
		},
		{
			name:   "generic ssh",
			banner: "SSH-2.0-dropbear_2022.83",
			port:   2222,
			want:   model.Result{Protocol: "SSH", Confidence: 0.55},
		},
		{
			name:   "tls bytes",
			banner: string([]byte{0x16, 0x03, 0x03, 0x00, 0x05}),
			port:   443,
			want:   model.Result{Protocol: "TLS", Confidence: 0.6},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Identify("10.0.0.1", tc.port, tc.banner)
			tc.want.IP = "10.0.0.1"
			tc.want.Port = tc.port
			assertResult(t, got, tc.want)
		})
	}
}

func TestUnknownDoesNotStopBatch(t *testing.T) {
	engine := loadTestEngine(t)
	got := engine.IdentifyBatch([]model.Input{
		{IP: "1.1.1.1", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{IP: "1.1.1.2", Port: 9, Banner: "hello"},
		{IP: "1.1.1.3", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
	})
	if got[0].Product != "OpenSSH" || got[1].Protocol != "unknown" || got[2].Product != "nginx" {
		t.Fatalf("%+v", got)
	}
	if got[1].Confidence != 0 || got[1].Version != "" || got[1].OSHint != "" || got[1].Product != "" {
		t.Fatalf("unknown fields: %+v", got[1])
	}
}

func TestLoadRejectsBrokenRules(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"regex":      `[{"name":"bad","priority":1,"pattern":"(","protocol":"HTTP","confidence":0.5}]`,
		"confidence": `[{"name":"bad","priority":1,"pattern":"a","protocol":"HTTP","confidence":1.5}]`,
		"group":      `[{"name":"bad","priority":1,"pattern":"a","protocol":"HTTP","version_group":"missing","confidence":0.5}]`,
		"json":       `{"name":"bad"}`,
		"duplicate":  `[{"name":"a","priority":1,"pattern":"a","protocol":"HTTP","confidence":0.2},{"name":"a","priority":1,"pattern":"b","protocol":"HTTP","confidence":0.2}]`,
		"trailing":   `[{"name":"a","priority":1,"pattern":"a","protocol":"HTTP","confidence":0.2}]{}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func assertResult(t *testing.T, got, want model.Result) {
	t.Helper()
	if got.IP != want.IP || got.Port != want.Port || got.Protocol != want.Protocol || got.Product != want.Product || got.Version != want.Version || got.OSHint != want.OSHint || math.Abs(got.Confidence-want.Confidence) > 1e-9 {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if got.Confidence < 0 || got.Confidence > 1 {
		t.Fatalf("confidence out of range: %v", got.Confidence)
	}
}

func loadTestEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := Load(repoPath("rules", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func readJSON(t *testing.T, path string, dest any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, dest); err != nil {
		t.Fatal(err)
	}
}

func repoPath(parts ...string) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(append([]string{root}, parts...)...)
}
