package main

import (
	"net/http/httptest"
	"testing"

	"github.com/ecakeman/temp/internal/api"
	"github.com/ecakeman/temp/internal/model"
)

type stub struct{}

func (stub) IdentifyBatch(items []model.Input) []model.Result {
	return make([]model.Result, len(items))
}

func TestRunHealth(t *testing.T) {
	srv := httptest.NewServer(api.New(stub{}, api.MaxBodyBytes))
	defer srv.Close()
	if code := runHealth([]string{"--url", srv.URL + "/health"}); code != 0 {
		t.Fatalf("code %d", code)
	}
	if code := runHealth([]string{"--url", srv.URL + "/missing"}); code == 0 {
		t.Fatal("expected non-zero")
	}
	if code := runHealth([]string{"--url", "http://127.0.0.1:1/health"}); code == 0 {
		t.Fatal("expected connection failure")
	}
}
