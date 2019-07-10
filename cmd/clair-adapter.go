package main

import (
	"github.com/aquasecurity/harbor-clair-adapter/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-clair-adapter/pkg/image/clair"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
)

type config struct {
	addr     string
	clairURL string
}

func main() {
	cfg := getConfig()
	log.Printf("Starting harbor-clair-adapter with config %v", cfg)

	scanner, err := clair.NewScanner(cfg.clairURL)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	apiHandler := v1.NewAPIHandler(scanner)

	router := mux.NewRouter()
	v1Router := router.PathPrefix("/api/v1").Subrouter()

	v1Router.Methods("POST").Path("/scan").HandlerFunc(apiHandler.CreateScan)
	v1Router.Methods("GET").Path("/scan/{detailsKey}").HandlerFunc(apiHandler.GetScanResult)

	err = http.ListenAndServe(cfg.addr, router)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
}

func getConfig() config {
	cfg := config{
		addr:     ":8080",
		clairURL: "http://harbor-harbor-clair:6060",
	}
	if addr, ok := os.LookupEnv("ADAPTER_ADDR"); ok {
		cfg.addr = addr
	}
	if clairURL, ok := os.LookupEnv("ADAPTER_CLAIR_URL"); ok {
		cfg.clairURL = clairURL
	}
	return cfg
}
