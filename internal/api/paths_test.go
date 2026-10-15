package api

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func repoFile(t *testing.T, parts ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(append([]string{root}, parts...)...)
}

func readRepo(t *testing.T, parts ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(repoFile(t, parts...))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
