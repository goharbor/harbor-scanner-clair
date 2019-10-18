package v1

import (
	"errors"
	"fmt"
	"github.com/goharbor/harbor-scanner-clair/pkg/http/api"
	"github.com/goharbor/harbor-scanner-clair/pkg/mock"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequestHandler_GetHealthy(t *testing.T) {
	scanner := mock.NewScanner()

	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/probe/healthy", nil)
	require.NoError(t, err)

	NewAPIHandler(scanner).ServeHTTP(rr, r)

	rs := rr.Result()

	assert.Equal(t, http.StatusOK, rs.StatusCode)
	scanner.AssertExpectations(t)
}

func TestRequestHandler_GetReady(t *testing.T) {
	scanner := mock.NewScanner()

	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/probe/ready", nil)
	require.NoError(t, err)

	NewAPIHandler(scanner).ServeHTTP(rr, r)

	rs := rr.Result()

	assert.Equal(t, http.StatusOK, rs.StatusCode)
	scanner.AssertExpectations(t)
}

func TestRequestHandler_AcceptScanRequest(t *testing.T) {
	validScanRequest := harbor.ScanRequest{
		Registry: harbor.Registry{
			URL:           "https://core.harbor.domain",
			Authorization: "Basic dXNlcjpwYXNzd29yZAo=",
		},
		Artifact: harbor.Artifact{
			Repository: "library/mongo",
			Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
		},
	}
	validScanRequestJSON := `{
  "registry": {
    "url": "https://core.harbor.domain",
    "authorization": "Basic dXNlcjpwYXNzd29yZAo="
  },
  "artifact": {
    "repository": "library/mongo",
    "digest": "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"
  }
}`

	testCases := []struct {
		name                string
		scannerExpectation  *mock.Expectation
		requestBody         string
		expectedStatus      int
		expectedContentType string
		expectedResponse    string
	}{
		{
			name: "Should accept scan request",
			scannerExpectation: &mock.Expectation{
				Method:     "Scan",
				Args:       []interface{}{validScanRequest},
				ReturnArgs: []interface{}{harbor.ScanResponse{ID: "sr:123"}, nil},
			},
			requestBody:         validScanRequestJSON,
			expectedStatus:      http.StatusAccepted,
			expectedContentType: "application/vnd.scanner.adapter.scan.response+json; version=1.0",
			expectedResponse:    `{"id": "sr:123"}`,
		},
		{
			name:                "Should respond with error 400 when scan request cannot be parsed",
			requestBody:         "THIS AIN'T PARSE",
			expectedStatus:      http.StatusBadRequest,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("unmarshalling scan request: invalid character 'T' looking for beginning of value"),
		},
		{
			name:                "Should respond with error 422 when scan request's registry URL is blank",
			requestBody:         `{"registry":{}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("missing registry.url"),
		},
		{
			name:                "Should respond with error 422 when scan request's registry URL is invalid",
			requestBody:         `{"registry":{"url":"INVALID URL"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("invalid registry.url"),
		},
		{
			name:                "Should respond with error 422 when scan request's artifact repository is blank",
			requestBody:         `{"registry":{"url":"https://core.harbor.domain"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("missing artifact.repository"),
		},
		{
			name:                "Should respond with error 422 when scan request's artifact digest is blank",
			requestBody:         `{"registry":{"url":"https://core.harbor.domain"}, "artifact":{"repository":"library/mongo"}}`,
			expectedStatus:      http.StatusUnprocessableEntity,
			expectedContentType: api.MimeTypeError.String(),
			expectedResponse:    errorJSON("missing artifact.digest"),
		},
		{
			name: "Should respond with error 500 when scan fails",
			scannerExpectation: &mock.Expectation{
				Method:     "Scan",
				Args:       []interface{}{validScanRequest},
				ReturnArgs: []interface{}{harbor.ScanResponse{}, errors.New("clair is down")},
			},
			requestBody:         validScanRequestJSON,
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
			expectedResponse:    errorJSON("performing scan: clair is down"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanner := mock.NewScanner()

			mock.ApplyExpectations(t, scanner, tc.scannerExpectation)

			rr := httptest.NewRecorder()
			r, err := http.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(tc.requestBody))
			require.NoError(t, err)

			NewAPIHandler(scanner).ServeHTTP(rr, r)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Equal(t, tc.expectedContentType, rr.Header().Get("Content-Type"))

			assert.JSONEq(t, tc.expectedResponse, rr.Body.String())

			scanner.AssertExpectations(t)
		})
	}
}

func TestRequestHandler_GetScanReport(t *testing.T) {
	now := time.Now()

	testCases := []struct {
		name                string
		scannerExpectation  *mock.Expectation
		expectedStatus      int
		expectedContentType string
		expectedResponse    string
	}{
		{
			name: "Should respond with error 500 when getting scan report fails",
			scannerExpectation: &mock.Expectation{
				Method:     "GetReport",
				Args:       []interface{}{"sr:123"},
				ReturnArgs: []interface{}{harbor.ScanReport{}, errors.New("boom")},
			},
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: "application/vnd.scanner.adapter.error; version=1.0",
			expectedResponse: `{
  "error": {
    "message": "getting scan report: boom"
  }
}`,
		},
		{
			name: "Should respond with vulnerabilities report",
			scannerExpectation: &mock.Expectation{
				Method: "GetReport",
				Args:   []interface{}{"sr:123"},
				ReturnArgs: []interface{}{harbor.ScanReport{
					GeneratedAt: now,
					Artifact: harbor.Artifact{
						Repository: "library/mongo",
						Digest:     "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
					},
					Scanner: harbor.Scanner{
						Name:    "Clair",
						Vendor:  "CoreOS",
						Version: "2.x",
					},
					Severity: harbor.SevCritical,
					Vulnerabilities: []harbor.VulnerabilityItem{
						{
							ID:          "CVE-2019-1111",
							Pkg:         "openssl",
							Version:     "2.0-rc1",
							FixVersion:  "2.1",
							Severity:    harbor.SevCritical,
							Description: "You'd better upgrade your server",
							Links: []string{
								"http://cve.com?id=CVE-2019-1111",
							},
						},
					},
				}, nil},
			},
			expectedStatus:      http.StatusOK,
			expectedContentType: "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
			expectedResponse: fmt.Sprintf(`{
  "generated_at": "%s",
  "artifact": {
    "repository": "library/mongo",
    "digest": "sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b"
  },
  "scanner": {
    "name": "Clair",
    "vendor": "CoreOS",
    "version": "2.x"
  },
  "severity": "Critical",
  "vulnerabilities": [
    {
      "id": "CVE-2019-1111",
      "package": "openssl",
      "version": "2.0-rc1",
      "fix_version": "2.1",
      "severity": "Critical",
      "description": "You'd better upgrade your server",
      "links": [
        "http://cve.com?id=CVE-2019-1111"
      ]
    }
  ]
}`, now.Format(time.RFC3339Nano)),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanner := mock.NewScanner()

			mock.ApplyExpectations(t, scanner, tc.scannerExpectation)

			rr := httptest.NewRecorder()
			r, err := http.NewRequest(http.MethodGet, "/api/v1/scan/sr:123/report", nil)
			require.NoError(t, err)

			NewAPIHandler(scanner).ServeHTTP(rr, r)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Equal(t, tc.expectedContentType, rr.Header().Get("Content-Type"))
			if tc.expectedResponse != "" {
				assert.JSONEq(t, tc.expectedResponse, rr.Body.String())
			}

			scanner.AssertExpectations(t)
		})
	}
}

func TestRequestHandler_GetMetadata(t *testing.T) {
	scanner := mock.NewScanner()

	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/api/v1/metadata", nil)
	require.NoError(t, err)

	NewAPIHandler(scanner).ServeHTTP(rr, r)

	rs := rr.Result()

	assert.Equal(t, http.StatusOK, rs.StatusCode)
	assert.JSONEq(t, `{
  "scanner": {
    "name": "Clair",
    "vendor": "CoreOS",
    "version": "2.x"
  },
  "capabilities": [
    {
      "consumes_mime_types": [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json"
      ],
      "produces_mime_types": [
        "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
      ]
    }
  ],
  "properties": {
    "harbor.scanner-adapter/scanner-type": "os-package-vulnerability"
  }
}`, rr.Body.String())
	scanner.AssertExpectations(t)
}

func errorJSON(message string) string {
	return fmt.Sprintf(`{"error":{"message":"%s"}}`, message)
}
