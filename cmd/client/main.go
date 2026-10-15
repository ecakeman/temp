package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ecakeman/temp/internal/model"
)

const maxRequestBytes = 1 << 20

func main() {
	file := flag.String("file", "", "path to a JSON array of scan records")
	server := flag.String("server", "", "server base URL, or SERVER_URL when empty")
	timeout := flag.Duration("timeout", 15*time.Second, "HTTP client timeout")
	flag.Parse()
	if *server == "" {
		*server = os.Getenv("SERVER_URL")
	}
	if err := run(*file, *server, *timeout, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(file, server string, timeout time.Duration, stdout io.Writer) error {
	if file == "" {
		return fmt.Errorf("missing -file")
	}
	if server == "" {
		return fmt.Errorf("missing -server or SERVER_URL")
	}
	server = strings.TrimRight(server, "/")
	payload, err := readLimited(file, maxRequestBytes)
	if err != nil {
		return err
	}
	if !json.Valid(payload) {
		return fmt.Errorf("input is not valid json")
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodPost, server+"/fingerprint", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request server: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(body) > maxRequestBytes {
		return fmt.Errorf("response too large")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %s: %s", resp.Status, bytes.TrimSpace(body))
	}
	var decoded []model.Result
	if err := json.Unmarshal(body, &decoded); err != nil {
		return fmt.Errorf("response is not a result array: %w", err)
	}
	if decoded == nil {
		decoded = []model.Result{}
	}
	pretty, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		return fmt.Errorf("format response: %w", err)
	}
	if _, err := stdout.Write(append(pretty, '\n')); err != nil {
		return err
	}
	return nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("input exceeds %d bytes", limit)
	}
	return data, nil
}
