package main

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"github.com/goharbor/harbor-scanner-clair/pkg/http/api/v1"
	"github.com/goharbor/harbor-scanner-clair/pkg/scanner/clair"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
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

	scanner, err := clair.NewScanner(cfg.ClairURL)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	apiHandler := v1.NewAPIHandler(scanner)

	err = http.ListenAndServe(cfg.APIAddr, apiHandler)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
}
