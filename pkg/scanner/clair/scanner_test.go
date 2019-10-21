package clair

import (
	"errors"
	"github.com/goharbor/harbor-scanner-clair/pkg/mock"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestImageScanner_GetReport(t *testing.T) {
	layerEnvelope := clair.LayerEnvelope{
		Layer: &clair.Layer{
			Name: "test layer",
		},
	}
	scanReport := harbor.ScanReport{
		GeneratedAt: time.Now(),
		Artifact:    harbor.Artifact{},
		Scanner:     harbor.Scanner{},
		Severity:    harbor.SevCritical,
		Vulnerabilities: []harbor.VulnerabilityItem{
			{ID: "CVE-2019-2341"},
		},
	}

	testCases := []struct {
		name                   string
		clairClientExpectation *mock.Expectation
		transformerExpectation *mock.Expectation
		expectedReport         harbor.ScanReport
		expectedError          error
	}{
		{
			name: "Should return scan report",
			clairClientExpectation: &mock.Expectation{
				Method:     "GetLayer",
				Args:       []interface{}{"sr:123"},
				ReturnArgs: []interface{}{&layerEnvelope, nil},
			},
			transformerExpectation: &mock.Expectation{
				Method:     "Transform",
				Args:       []interface{}{harbor.Artifact{}, layerEnvelope},
				ReturnArgs: []interface{}{scanReport},
			},
			expectedReport: scanReport,
		},
		{
			name: "Should return error when getting Clair layer fails",
			clairClientExpectation: &mock.Expectation{
				Method:     "GetLayer",
				Args:       []interface{}{"sr:123"},
				ReturnArgs: []interface{}{(*clair.LayerEnvelope)(nil), errors.New("boom")},
			},
			expectedError: errors.New("getting layer sr:123: boom"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			registryClientFactory := mock.NewRegistryClientFactory()
			clairClient := mock.NewClairClient()
			transformer := mock.NewTransformer()

			scanner := NewScanner(registryClientFactory, clairClient, transformer)

			mock.ApplyExpectations(t, clairClient, tc.clairClientExpectation)
			mock.ApplyExpectations(t, transformer, tc.transformerExpectation)

			report, err := scanner.GetReport("sr:123")
			assert.Equal(t, tc.expectedError, err)
			assert.Equal(t, tc.expectedReport, report)

			registryClientFactory.AssertExpectations(t)
			clairClient.AssertExpectations(t)
			transformer.AssertExpectations(t)
		})
	}
}
