package main

import (
	"github.com/aquasecurity/harbor-scanner-clair/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/scanner/clair"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func main() {
	cfg, err := etc.GetConfig()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Printf("Starting harbor-scanner-clair with config %v", cfg)

	scanner, err := clair.NewScanner(cfg.ClairURL)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	apiHandler := v1.NewAPIHandler(scanner)

	router := mux.NewRouter()
	v1Router := router.PathPrefix("/api/v1").Subrouter()

	v1Router.Methods(http.MethodGet).Path("").HandlerFunc(apiHandler.GetVersion)
	v1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(apiHandler.CreateScan)
	v1Router.Methods(http.MethodGet).Path("/scan/{detailsKey}").HandlerFunc(apiHandler.GetScanResult)

	err = http.ListenAndServe(cfg.Addr, router)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
}
