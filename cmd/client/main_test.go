package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ecakeman/temp/internal/api"
	"github.com/ecakeman/temp/internal/fingerprint"
)

func TestClientReadsFile(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	engine, err := fingerprint.Load(filepath.Join(root, "rules", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.New(engine, api.MaxBodyBytes))
	defer srv.Close()

	var stdout bytes.Buffer
	if err := run(filepath.Join(root, "testdata", "input.json"), srv.URL, 5*time.Second, &stdout); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 20 {
		t.Fatalf("len %d", len(got))
	}
	if got[0]["product"] != "OpenSSH" || got[0]["version"] != "8.9p1" || got[0]["os_hint"] != "Ubuntu" {
		t.Fatalf("%v", got[0])
	}
	if got[6]["product"] != "Jetty" || got[6]["version"] != "9.4.51" {
		t.Fatalf("%v", got[6])
	}
	if got[19]["protocol"] != "unknown" {
		t.Fatalf("%v", got[19])
	}
	if _, ok := got[0]["confidence"].(float64); !ok {
		t.Fatalf("confidence type %T", got[0]["confidence"])
	}
	if _, ok := got[0]["port"].(float64); !ok {
		t.Fatalf("port type %T", got[0]["port"])
	}
}

func TestClientErrors(t *testing.T) {
	if err := run("", "http://127.0.0.1:9", time.Second, &bytes.Buffer{}); err == nil {
		t.Fatal("expected missing file error")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "in.json")
	if err := os.WriteFile(path, []byte(`[{"ip":"1.1.1.1","port":1,"banner":"x"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(path, "http://127.0.0.1:1", time.Second, &bytes.Buffer{}); err == nil {
		t.Fatal("expected connection error")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadRequest)
	}))
	defer srv.Close()
	if err := run(path, srv.URL, time.Second, &bytes.Buffer{}); err == nil {
		t.Fatal("expected status error")
	}
}
