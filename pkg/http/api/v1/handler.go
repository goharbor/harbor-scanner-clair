package v1

import (
	"encoding/json"
	"fmt"
	"github.com/goharbor/harbor-scanner-clair/pkg/http/api"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/goharbor/harbor-scanner-clair/pkg/scanner/clair"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
)

const (
	pathVarScanRequestID = "scan_request_id"
)

type requestHandler struct {
	scanner clair.Scanner
	api.BaseHandler
}

func NewAPIHandler(scanner clair.Scanner) http.Handler {
	handler := &requestHandler{
		scanner: scanner,
	}
	router := mux.NewRouter()
	router.Use(handler.logRequest)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()

	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(handler.GetMetadata)
	apiV1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(handler.AcceptScanRequest)
	apiV1Router.Methods(http.MethodGet).Path("/scan/{scan_request_id}/report").HandlerFunc(handler.GetScanReport)

	probeRouter := router.PathPrefix("/probe").Subrouter()
	probeRouter.Methods(http.MethodGet).Path("/healthy").HandlerFunc(handler.GetHealthy)
	probeRouter.Methods(http.MethodGet).Path("/ready").HandlerFunc(handler.GetReady)
	return router
}

func (h *requestHandler) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Tracef("%s - %s %s %s", r.RemoteAddr, r.Proto, r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}

func (h *requestHandler) AcceptScanRequest(res http.ResponseWriter, req *http.Request) {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		log.WithError(err).Error("Error while unmarshalling scan request")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  fmt.Sprintf("unmarshalling scan request: %s", err.Error()),
		})
		return
	}

	scanResponse, err := h.scanner.Scan(scanRequest)
	if err != nil {
		log.WithError(err).Error("Error while performing scan")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("performing scan: %s", err.Error()),
		})
		return
	}

	h.WriteJSON(res, scanResponse, api.MimeTypeScanResponse, http.StatusAccepted)
}

func (h *requestHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	scanRequestID, _ := vars[pathVarScanRequestID]
	log.Debugf("Handling get scan report request: %s", scanRequestID)

	scanReport, err := h.scanner.GetReport(scanRequestID)
	if err != nil {
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("getting scan report: %v", err),
		})
		return
	}
	h.WriteJSON(res, scanReport, api.MimeTypeScanReport, http.StatusOK)
}

func (h *requestHandler) GetMetadata(res http.ResponseWriter, req *http.Request) {
	metadata := &harbor.ScannerMetadata{
		Scanner: harbor.Scanner{
			Name:   "Clair",
			Vendor: "CoreOS",
			// TODO Get version from Clair API or env if the API does not provide it.
			Version: "2.0.8",
		},
		Capabilities: []harbor.Capability{
			{
				ConsumesMimeTypes: []string{
					api.MimeTypeOCIImageManifest.String(),
					api.MimeTypeDockerDistributionManifest.String(),
				},
				ProducesMimeTypes: []string{
					api.MimeTypeScanReport.String(),
				},
			},
		},
		Properties: map[string]string{
			"harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
		},
	}

	h.WriteJSON(res, metadata, api.MimeTypeMetadata, http.StatusOK)
}

func (h *requestHandler) GetHealthy(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *requestHandler) GetReady(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}
