package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ecakeman/temp/internal/model"
)

// MaxBodyBytes rejects scan batches large enough to exhaust memory.
const MaxBodyBytes = 1 << 20

// Engine identifies a validated batch. The handler does not match banners itself.
type Engine interface {
	IdentifyBatch(items []model.Input) []model.Result
}

type rawInput struct {
	IP     *string `json:"ip"`
	Port   *int    `json:"port"`
	Banner *string `json:"banner"`
}

// New returns the HTTP handler for /health and /fingerprint.
func New(engine Engine, maxBody int64) http.Handler {
	if maxBody <= 0 {
		maxBody = MaxBodyBytes
	}
	mux := http.NewServeMux()
	h := &handler{engine: engine, maxBody: maxBody}
	mux.HandleFunc("/health", h.health)
	mux.HandleFunc("/fingerprint", h.fingerprint)
	return mux
}

type handler struct {
	engine  Engine
	maxBody int64
}

func (h *handler) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handler) fingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	items, err := decodeInputs(http.MaxBytesReader(w, r.Body, h.maxBody))
	if err != nil {
		status := http.StatusBadRequest
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || errors.Is(err, errTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeError(w, status, err.Error())
		return
	}
	results := h.engine.IdentifyBatch(items)
	if results == nil {
		results = []model.Result{}
	}
	writeJSON(w, http.StatusOK, results)
}

var errTooLarge = errors.New("request body too large")

func decodeInputs(body io.Reader) ([]model.Input, error) {
	dec := json.NewDecoder(body)
	var payload json.RawMessage
	if err := dec.Decode(&payload); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, err
		}
		return nil, errors.New("invalid json")
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, errors.New("expected a json array")
	}
	itemDec := json.NewDecoder(bytes.NewReader(trimmed))
	itemDec.DisallowUnknownFields()
	var raw []rawInput
	if err := itemDec.Decode(&raw); err != nil {
		return nil, errors.New("invalid json")
	}
	if raw == nil {
		return nil, errors.New("expected a json array")
	}
	items := make([]model.Input, len(raw))
	for i, item := range raw {
		if item.IP == nil || strings.TrimSpace(*item.IP) == "" {
			return nil, errors.New("missing ip")
		}
		if item.Port == nil {
			return nil, errors.New("missing port")
		}
		if *item.Port < 1 || *item.Port > 65535 {
			return nil, errors.New("invalid port")
		}
		if item.Banner == nil {
			return nil, errors.New("missing banner")
		}
		items[i] = model.Input{IP: *item.IP, Port: *item.Port, Banner: *item.Banner}
	}
	return items, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
