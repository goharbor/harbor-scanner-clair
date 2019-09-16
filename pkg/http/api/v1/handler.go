package v1

import (
	"encoding/json"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/goharbor/harbor-scanner-clair/pkg/scanner/clair"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
)

const (
	headerContentType = "Content-Type"

	mimeTypeMetadata                  = "application/vnd.scanner.adapter.metadata+json; version=1.0"
	mimeTypeScanRequest               = "application/vnd.scanner.adapter.scan.request+json; version=1.0"
	mimeTypeHarborVulnerabilityReport = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	mimeTypeClairReport               = "application/vnd.scanner.adapter.vuln.report.raw"

	pathAPIPrefix        = "/api/v1"
	pathMetadata         = "/metadata"
	pathScan             = "/scan"
	pathScanReport       = "/scan/{scanRequestID}/report"
	pathVarScanRequestID = "scanRequestID"
)

type requestHandler struct {
	scanner clair.Scanner
}

func NewAPIHandler(scanner clair.Scanner) http.Handler {
	handler := &requestHandler{
		scanner: scanner,
	}
	router := mux.NewRouter()
	v1Router := router.PathPrefix(pathAPIPrefix).Subrouter()

	v1Router.Methods(http.MethodGet).Path(pathMetadata).HandlerFunc(handler.GetMetadata)
	v1Router.Methods(http.MethodPost).Path(pathScan).HandlerFunc(handler.AcceptScanRequest)
	v1Router.Methods(http.MethodGet).Path(pathScanReport).HandlerFunc(handler.GetScanReport)
	return router
}

func (h *requestHandler) GetMetadata(res http.ResponseWriter, req *http.Request) {
	md := &harbor.ScannerMetadata{
		Name:    "Clair",
		Vendor:  "CoreOS",
		Version: "2.0.8",
		Capabilities: []*harbor.Capability{
			{
				ArtifactMIMETypes: []string{
					"application/vnd.oci.image.manifest.v1+json",
					"application/vnd.docker.distribution.manifest.v2+json",
				},
				ReportMIMETypes: []string{
					mimeTypeHarborVulnerabilityReport,
					mimeTypeClairReport,
				},
			},
		},
	}

	res.Header().Set(headerContentType, mimeTypeMetadata)
	err := json.NewEncoder(res).Encode(md)
	if err != nil {
		h.SendInternalServerError(res, err)
	}
}

func (h *requestHandler) AcceptScanRequest(res http.ResponseWriter, req *http.Request) {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		h.SendInternalServerError(res, err)
		return
	}

	log.Debugf("CreateScan request received: %v", scanRequest)

	err = h.scanner.Scan(scanRequest)
	if err != nil {
		h.SendInternalServerError(res, err)
		return
	}

	res.WriteHeader(http.StatusAccepted)
}

func (h *requestHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	scanRequestID, _ := vars[pathVarScanRequestID]
	log.Debugf("Handling get scan report request: %s", scanRequestID)

	scanResult, err := h.scanner.GetReport(scanRequestID)
	if err != nil {
		h.SendInternalServerError(res, err)
		return
	}

	res.Header().Set(headerContentType, "application/json")
	err = json.NewEncoder(res).Encode(scanResult)
	if err != nil {
		h.SendInternalServerError(res, err)
		return
	}
}

func (h *requestHandler) SendInternalServerError(res http.ResponseWriter, err error) {
	log.WithError(err).Error("Internal server error")
	http.Error(res, "Internal Server Error", http.StatusInternalServerError)
}
