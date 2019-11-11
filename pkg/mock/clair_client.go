package mock

import (
	"time"

	"github.com/goharbor/harbor-scanner-clair/pkg/clair"
	"github.com/stretchr/testify/mock"
)

type ClairClient struct {
	mock.Mock
}

func NewClairClient() *ClairClient {
	return &ClairClient{}
}

func (cc *ClairClient) ScanLayer(l clair.Layer) error {
	args := cc.Called(l)
	return args.Error(0)
}

func (cc *ClairClient) GetLayer(layerName string) (*clair.LayerEnvelope, error) {
	args := cc.Called(layerName)
	return args.Get(0).(*clair.LayerEnvelope), args.Error(1)
}

func (cc *ClairClient) GetVulnerabilityDatabaseUpdatedAt() (*time.Time, error) {
	args := cc.Called()
	return args.Get(0).(*time.Time), args.Error(1)
}
