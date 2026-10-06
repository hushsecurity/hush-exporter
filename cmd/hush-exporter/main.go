// hush-exporter serves Hush Security findings as Prometheus metrics.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/hushsecurity/hush-exporter/internal/config"
	"github.com/hushsecurity/hush-exporter/internal/exporter"
	"github.com/hushsecurity/hush-exporter/internal/hush"
)

func main() {
	if err := run(); err != nil {
		slog.Error("exit", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = hush.BaseURL(cfg.Realm)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	poller, err := exporter.NewPoller(hush.NewClient(baseURL, cfg.KeyID, cfg.KeySecret), cfg.Sources)
	if err != nil {
		return err
	}

	collector, err := exporter.NewCollector(poller, cfg.File.TagLabels)
	if err != nil {
		return err
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)
	go poller.Run(ctx)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Addr: cfg.ListenAddress, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	stopped := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stopped <- server.Shutdown(shutdown)
	}()
	slog.Info("serving", "address", cfg.ListenAddress, "api", baseURL)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// Wait for open scrapes.
	return <-stopped
}
