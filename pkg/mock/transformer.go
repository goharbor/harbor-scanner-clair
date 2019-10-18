package mock

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/model/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/stretchr/testify/mock"
)

type Transformer struct {
	mock.Mock
}

func NewTransformer() *Transformer {
	return &Transformer{}
}

func (m *Transformer) Transform(req harbor.ScanRequest, source clair.LayerEnvelope) harbor.ScanReport {
	args := m.Called(req, source)
	return args.Get(0).(harbor.ScanReport)
}
