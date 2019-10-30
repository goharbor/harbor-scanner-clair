package mock

import (
	"github.com/docker/distribution"
	"github.com/goharbor/harbor-scanner-clair/pkg/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
	"github.com/stretchr/testify/mock"
)

type Transformer struct {
	mock.Mock
}

func NewTransformer() *Transformer {
	return &Transformer{}
}

func (m *Transformer) ToClairLayers(req harbor.ScanRequest, manifest distribution.Manifest) []clair.Layer {
	args := m.Called(req, manifest)
	return args.Get(0).([]clair.Layer)
}

func (m *Transformer) Transform(artifact harbor.Artifact, source clair.LayerEnvelope) harbor.ScanReport {
	args := m.Called(artifact, source)
	return args.Get(0).(harbor.ScanReport)
}
