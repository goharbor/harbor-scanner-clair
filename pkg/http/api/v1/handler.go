package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/goharbor/harbor-scanner-clair/pkg/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
	"github.com/goharbor/harbor-scanner-clair/pkg/http/api"
	"github.com/goharbor/harbor-scanner-clair/pkg/job"
	"github.com/goharbor/harbor-scanner-clair/pkg/persistence"
	"github.com/goharbor/harbor-scanner-clair/pkg/scanner"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	pathVarScanRequestID = "scan_request_id"
)

type requestHandler struct {
	clair    clair.Client
	enqueuer scanner.Enqueuer
	store    persistence.Store
	api.BaseHandler
}

func NewAPIHandler(clair clair.Client, enqueuer scanner.Enqueuer, store persistence.Store) http.Handler {
	handler := &requestHandler{
		clair:    clair,
		enqueuer: enqueuer,
		store:    store,
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

	router.Methods(http.MethodGet).Path("/metrics").Handler(promhttp.Handler())
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

	if validationError := h.validate(scanRequest); validationError != nil {
		log.Errorf("Error while validating scan request: %s", validationError.Message)
		h.WriteJSONError(res, *validationError)
		return
	}

	jobID, err := h.enqueuer.Enqueue(scanRequest)
	if err != nil {
		log.WithError(err).Error("Error while performing scan")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("performing scan: %s", err.Error()),
		})
		return
	}

	h.WriteJSON(res, harbor.ScanResponse{ID: jobID}, api.MimeTypeScanResponse, http.StatusAccepted)
}

func (h *requestHandler) validate(req harbor.ScanRequest) *harbor.Error {
	if req.Registry.URL == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing registry.url",
		}
	}

	_, err := url.ParseRequestURI(req.Registry.URL)
	if err != nil {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "invalid registry.url",
		}
	}

	if req.Artifact.Repository == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact.repository",
		}
	}

	if req.Artifact.Digest == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact.digest",
		}
	}

	return nil
}

func (h *requestHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	jobID, ok := vars[pathVarScanRequestID]
	if !ok {
		log.Error("Error while parsing `scan_request_id` path variable")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  "missing scan_request_id",
		})
		return
	}

	reqLog := log.WithField("scan_job_id", jobID)

	scanJob, err := h.store.Get(jobID)
	if err != nil {
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("getting scan job: %v", err),
		})
		return
	}

	if scanJob == nil {
		reqLog.Error("Cannot find scan job")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusNotFound,
			Message:  fmt.Sprintf("cannot find scan job: %v", jobID),
		})
		return
	}

	if scanJob.Status == job.Pending || scanJob.Status == job.Running {
		reqLog.WithField("scan_job_status", scanJob.Status.String()).Debug("Scan job has not finished yet")
		res.Header().Add("Location", req.URL.String())
		res.WriteHeader(http.StatusFound)
		return
	}

	if scanJob.Status == job.Failed {
		reqLog.WithField(log.ErrorKey, scanJob.Error).Error("Scan job failed")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  scanJob.Error,
		})
		return
	}

	if scanJob.Status != job.Finished {
		reqLog.WithField("scan_job_status", scanJob.Status).Error("Unexpected scan job status")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("unexpected status %v of scan job %v", scanJob.Status, scanJob.ID),
		})
		return
	}

	h.WriteJSON(res, scanJob.Report, api.MimeTypeScanReport, http.StatusOK)
}

func (h *requestHandler) GetMetadata(res http.ResponseWriter, req *http.Request) {
	properties := map[string]string{
		"harbor.scanner-adapter/scanner-type":                "os-package-vulnerability",
		"harbor.scanner-adapter/registry-authorization-type": "Bearer",
	}

	updatedAt, err := h.clair.GetVulnerabilityDatabaseUpdatedAt()
	if err != nil {
		log.Errorf("Failed to get vulnerability database updated time, %v", err)
	} else if updatedAt != nil {
		properties["harbor.scanner-adapter/vulnerability-database-updated-at"] = updatedAt.Format(time.RFC3339)
	}

	metadata := &harbor.ScannerMetadata{
		Scanner: etc.GetScannerMetadata(),
		Capabilities: []harbor.Capability{
			{
				ConsumesMimeTypes: []string{
					api.MimeTypeOCIImageManifest.String(),
					api.MimeTypeDockerDistributionManifest.String(),
					api.MimeTypeDockerDistributionManifestSchema1.String(),
					api.MimeTypeDockerDistributionManifestSchema1Signed.String(),
				},
				ProducesMimeTypes: []string{
					api.MimeTypeScanReport.String(),
				},
			},
		},
		Properties: properties,
	}

	h.WriteJSON(res, metadata, api.MimeTypeMetadata, http.StatusOK)
}

func (h *requestHandler) GetHealthy(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *requestHandler) GetReady(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}
