package main

import (
	"github.com/aquasecurity/harbor-scanner-clair/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/scanner/clair"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/store/memory"
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
	log.Infof("Starting harbor-scanner-clair with config %v", cfg)

	// TODO Replace with persistent storage. Redis or file system?
	dataStore := memory.NewDataStore()

	scanner, err := clair.NewScanner(cfg.ClairURL, dataStore)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	apiHandler := v1.NewAPIHandler(scanner)

	err = http.ListenAndServe(cfg.Addr, apiHandler)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
}
