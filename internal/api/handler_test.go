package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ecakeman/temp/internal/fingerprint"
	"github.com/ecakeman/temp/internal/model"
)

func TestHealth(t *testing.T) {
	resp := do(t, newHandler(t, 1<<20), http.MethodGet, "/health", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	var body map[string]string
	decode(t, resp.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("%v", body)
	}
}

func TestEmptyArray(t *testing.T) {
	resp := do(t, newHandler(t, 1<<20), http.MethodPost, "/fingerprint", []byte("[]"))
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d body %s", resp.Code, resp.Body.Bytes())
	}
	if strings.TrimSpace(resp.Body.String()) != "[]" {
		t.Fatalf("body %q", resp.Body.String())
	}
}

func TestFingerprintSamplePreservesOrder(t *testing.T) {
	h := newHandler(t, 1<<20)
	payload := readRepo(t, "testdata", "input.json")
	resp := do(t, h, http.MethodPost, "/fingerprint", payload)
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d %s", resp.Code, resp.Body.Bytes())
	}
	var got []model.Result
	decode(t, resp.Body.Bytes(), &got)
	var inputs []model.Input
	decode(t, payload, &inputs)
	engine, err := fingerprint.Load(repoFile(t, "rules", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := engine.IdentifyBatch(inputs)
	if len(got) != len(want) {
		t.Fatalf("len %d", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d got %+v want %+v", i, got[i], want[i])
		}
	}
	if got[0].IP != "1.2.3.4" || got[len(got)-1].Protocol != "unknown" {
		t.Fatalf("order %+v ... %+v", got[0], got[len(got)-1])
	}
}

func TestEmptyBannerIsUnknown(t *testing.T) {
	body := []byte(`[{"ip":"10.1.1.1","port":22,"banner":""}]`)
	resp := do(t, newHandler(t, 1<<20), http.MethodPost, "/fingerprint", body)
	if resp.Code != http.StatusOK {
		t.Fatal(resp.Body.String())
	}
	var got []model.Result
	decode(t, resp.Body.Bytes(), &got)
	if len(got) != 1 || got[0].Protocol != "unknown" || got[0].Confidence != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestRejectsBadRequests(t *testing.T) {
	h := newHandler(t, 64)
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		status int
	}{
		{name: "invalid json", method: http.MethodPost, path: "/fingerprint", body: "{", status: http.StatusBadRequest},
		{name: "trailing", method: http.MethodPost, path: "/fingerprint", body: `[{"ip":"1.1.1.1","port":1,"banner":""}]{"a":1}`, status: http.StatusBadRequest},
		{name: "missing ip", method: http.MethodPost, path: "/fingerprint", body: `[{"port":1,"banner":""}]`, status: http.StatusBadRequest},
		{name: "missing port", method: http.MethodPost, path: "/fingerprint", body: `[{"ip":"1.1.1.1","banner":""}]`, status: http.StatusBadRequest},
		{name: "missing banner", method: http.MethodPost, path: "/fingerprint", body: `[{"ip":"1.1.1.1","port":1}]`, status: http.StatusBadRequest},
		{name: "invalid port", method: http.MethodPost, path: "/fingerprint", body: `[{"ip":"1.1.1.1","port":0,"banner":""}]`, status: http.StatusBadRequest},
		{name: "port too high", method: http.MethodPost, path: "/fingerprint", body: `[{"ip":"1.1.1.1","port":70000,"banner":""}]`, status: http.StatusBadRequest},
		{name: "unknown field", method: http.MethodPost, path: "/fingerprint", body: `[{"ip":"1.1.1.1","port":1,"banner":"","extra":true}]`, status: http.StatusBadRequest},
		{name: "null", method: http.MethodPost, path: "/fingerprint", body: `null`, status: http.StatusBadRequest},
		{name: "object", method: http.MethodPost, path: "/fingerprint", body: `{}`, status: http.StatusBadRequest},
		{name: "too large", method: http.MethodPost, path: "/fingerprint", body: `[{"ip":"1.1.1.1","port":1,"banner":"` + strings.Repeat("A", 80) + `"}]`, status: http.StatusRequestEntityTooLarge},
		{name: "get fingerprint", method: http.MethodGet, path: "/fingerprint", status: http.StatusMethodNotAllowed},
		{name: "post health", method: http.MethodPost, path: "/health", body: `[]`, status: http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(t, h, tc.method, tc.path, []byte(tc.body))
			if resp.Code != tc.status {
				t.Fatalf("status %d body %s", resp.Code, resp.Body.Bytes())
			}
			var payload map[string]string
			decode(t, resp.Body.Bytes(), &payload)
			if payload["error"] == "" {
				t.Fatalf("missing error: %s", resp.Body.Bytes())
			}
		})
	}
}

func TestRealNULThroughJSON(t *testing.T) {
	body := []byte("{\"ip\":\"10.0.0.8\",\"port\":3306,\"banner\":\"J\\u0000\\u0000\\u0000\\n8.0.36\\u0000\"}")
	// The body above is a JSON object; the API requires an array.
	body = append([]byte{'['}, append(body, ']')...)
	resp := do(t, newHandler(t, 1<<20), http.MethodPost, "/fingerprint", body)
	if resp.Code != http.StatusOK {
		t.Fatal(resp.Body.String())
	}
	var got []model.Result
	decode(t, resp.Body.Bytes(), &got)
	if len(got) != 1 || got[0].Protocol != "MySQL" || got[0].Version != "8.0.36" {
		t.Fatalf("%+v", got)
	}
}

type stubEngine struct{}

func (stubEngine) IdentifyBatch(items []model.Input) []model.Result {
	out := make([]model.Result, len(items))
	for i, item := range items {
		out[i] = model.Unknown(item.IP, item.Port)
	}
	return out
}

func newHandler(t *testing.T, max int64) http.Handler {
	t.Helper()
	if max < 1<<20 {
		return New(stubEngine{}, max)
	}
	engine, err := fingerprint.Load(repoFile(t, "rules", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	return New(engine, max)
}

func do(t *testing.T, h http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, data []byte, dest any) {
	t.Helper()
	if err := json.Unmarshal(data, dest); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
}
