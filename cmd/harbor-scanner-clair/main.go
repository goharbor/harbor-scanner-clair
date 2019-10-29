package main

import (
	"context"
	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"github.com/goharbor/harbor-scanner-clair/pkg/http/api"
	"github.com/goharbor/harbor-scanner-clair/pkg/http/api/v1"
	"github.com/goharbor/harbor-scanner-clair/pkg/metrics"
	"github.com/goharbor/harbor-scanner-clair/pkg/model"
	"github.com/goharbor/harbor-scanner-clair/pkg/persistence/redis"
	"github.com/goharbor/harbor-scanner-clair/pkg/registry"
	"github.com/goharbor/harbor-scanner-clair/pkg/scanner"
	"github.com/goharbor/harbor-scanner-clair/pkg/scanner/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/work"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

var (
	// Default wise GoReleaser sets three ldflags:
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(etc.GetLogLevel())
	log.SetReportCaller(false)
	log.SetFormatter(&log.JSONFormatter{})

	config, err := etc.GetConfig()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	store := redis.NewStore(config.Store)

	workPool := work.New(config.WorkPool)

	log.WithFields(log.Fields{
		"version":  version,
		"commit":   commit,
		"built_at": date,
	}).Info("Starting harbor-scanner-clair")

	registryClientFactory := registry.NewClientFactory(config.TLS)
	clairClient := clair.NewClient(config.TLS, config.Clair)
	s := clair.NewScanner(registryClientFactory, clairClient, model.NewTransformer())

	enqueuer := scanner.NewEnqueuer(workPool, s, store)

	apiHandler := v1.NewAPIHandler(enqueuer, store)

	apiServer := api.NewServer(config.API, apiHandler)
	metricsServer := metrics.NewServer(config.Metrics)

	shutdownComplete := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		captured := <-sigint
		log.WithField("signal", captured.String()).Debug("Trapped os signal")

		log.Trace("API server shutdown started")
		if err := apiServer.Shutdown(context.Background()); err != nil {
			log.WithError(err).Error("Error while shutting down API server")
		}
		log.Trace("API server shutdown completed")

		log.Trace("Metrics server shutdown started")
		if err := metricsServer.Shutdown(context.Background()); err != nil {
			log.WithError(err).Error("Error while shutting down metrics server")
		}
		log.Trace("Metrics server shutdown completed")

		log.Trace("Work pool shutdown started")
		workPool.Shutdown()
		log.Trace("Work pool shutdown completed")
		close(shutdownComplete)
	}()

	go func() {
		if err = apiServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Error: %v", err)
		}
		log.Trace("API server stopped listening for incoming connections")
	}()

	go func() {
		if err := metricsServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Error: %v", err)
		}
		log.Trace("Metrics server stopped listening for incoming connections")
	}()

	<-shutdownComplete
}
