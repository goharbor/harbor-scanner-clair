package mock

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/model/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/stretchr/testify/mock"
)

type TransformerMock struct {
	mock.Mock
}

func NewTransformer() *TransformerMock {
	return &TransformerMock{}
}

func (m *TransformerMock) Transform(req harbor.ScanRequest, source clair.LayerEnvelope) harbor.VulnerabilityReport {
	args := m.Called(req, source)
	return args.Get(0).(harbor.VulnerabilityReport)
}
