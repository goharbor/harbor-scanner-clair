package main

import (
	"context"
	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"github.com/goharbor/harbor-scanner-clair/pkg/http/api/v1"
	"github.com/goharbor/harbor-scanner-clair/pkg/model"
	"github.com/goharbor/harbor-scanner-clair/pkg/scanner/clair"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetReportCaller(false)
	log.SetFormatter(&log.JSONFormatter{})
}

func main() {
	cfg, err := etc.GetConfig()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Info("Starting harbor-scanner-clair")

	client := clair.NewClient(cfg.ClairURL)
	scanner, err := clair.NewScanner(client, model.NewTransformer())
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	apiHandler := v1.NewAPIHandler(scanner)

	server := http.Server{
		Handler:      apiHandler,
		Addr:         cfg.APIAddr,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	shutdownComplete := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, os.Kill)
		captured := <-sigint
		log.Debugf("Trapped os signal %v", captured)

		log.Debug("Graceful shutdown started")
		if err := server.Shutdown(context.Background()); err != nil {
			log.WithError(err).Error("Error while shutting down server")
		}
		log.Debug("Graceful shutdown completed")
		close(shutdownComplete)
	}()

	go func() {
		if err = server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Error: %v", err)
		}
		log.Debug("ListenAndServe returned")
	}()
	<-shutdownComplete
}
