package main

import (
	"context"
	"github.com/goharbor/harbor-scanner-clair/pkg/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"github.com/goharbor/harbor-scanner-clair/pkg/http/api"
	"github.com/goharbor/harbor-scanner-clair/pkg/http/api/v1"
	"github.com/goharbor/harbor-scanner-clair/pkg/persistence/redis"
	"github.com/goharbor/harbor-scanner-clair/pkg/registry"
	"github.com/goharbor/harbor-scanner-clair/pkg/scanner"
	"github.com/goharbor/harbor-scanner-clair/pkg/work"
	log "github.com/sirupsen/logrus"
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
	adapter := scanner.NewAdapter(registryClientFactory, clairClient, scanner.NewTransformer())

	enqueuer := scanner.NewEnqueuer(workPool, adapter, store)

	apiHandler := v1.NewAPIHandler(enqueuer, store)

	apiServer := api.NewServer(config.API, apiHandler)

	shutdownComplete := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		captured := <-sigint
		log.WithField("signal", captured.String()).Debug("Trapped os signal")

		apiServer.Shutdown(context.Background())

		log.Trace("Work pool shutdown started")
		workPool.Shutdown()
		log.Trace("Work pool shutdown completed")
		close(shutdownComplete)
	}()

	apiServer.ListenAndServe()

	<-shutdownComplete
}
