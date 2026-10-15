package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ecakeman/temp/internal/api"
	"github.com/ecakeman/temp/internal/fingerprint"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "health" {
		os.Exit(runHealth(os.Args[2:]))
	}
	if err := serve(); err != nil {
		log.Fatal(err)
	}
}

func serve() error {
	rulesPath := os.Getenv("RULES_PATH")
	if rulesPath == "" {
		rulesPath = "rules/rules.json"
	}
	engine, err := fingerprint.Load(rulesPath)
	if err != nil {
		return err
	}
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           api.New(engine, api.MaxBodyBytes),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Printf("stopped")
	return nil
}

func runHealth(args []string) int {
	url := os.Getenv("HEALTH_URL")
	if url == "" {
		url = "http://127.0.0.1:8080/health"
	}
	for i := 0; i < len(args); i++ {
		if args[i] == "--url" && i+1 < len(args) {
			url = args[i+1]
		}
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, resp.Status)
		return 1
	}
	return 0
}
