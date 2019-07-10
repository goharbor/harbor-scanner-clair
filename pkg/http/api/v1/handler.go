package v1

import (
	"encoding/json"
	"github.com/aquasecurity/harbor-clair-adapter/pkg/image"
	"github.com/aquasecurity/harbor-clair-adapter/pkg/model/harbor"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

type APIHandler struct {
	scanner image.Scanner
}

func NewAPIHandler(scanner image.Scanner) *APIHandler {
	return &APIHandler{
		scanner: scanner,
	}
}

func (h *APIHandler) CreateScan(res http.ResponseWriter, req *http.Request) {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}

	log.Printf("CreateScan request received\n\t%v", scanRequest)

	err = h.scanner.Scan(scanRequest)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}

	res.WriteHeader(http.StatusCreated)
}

func (h *APIHandler) GetScanResult(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	digest, _ := vars["digest"]
	log.Printf("GetScanResult request received (digest=%s)", digest)

	scanResult, err := h.scanner.GetResult(digest)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(res).Encode(scanResult)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}
}
