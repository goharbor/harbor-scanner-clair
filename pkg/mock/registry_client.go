package mock

import (
	"github.com/docker/distribution"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/goharbor/harbor-scanner-clair/pkg/registry"
	"github.com/stretchr/testify/mock"
)

type RegistryClientFactory struct {
	mock.Mock
}

type RegistryClient struct {
	mock.Mock
}

func NewRegistryClientFactory() *RegistryClientFactory {
	return &RegistryClientFactory{}
}

func NewRegistryClient() *RegistryClient {
	return &RegistryClient{}
}

func (f *RegistryClientFactory) Get(req harbor.ScanRequest) (registry.Client, error) {
	args := f.Called(req)
	return args.Get(0).(registry.Client), args.Error(1)
}

func (c *RegistryClient) GetManifest() (distribution.Manifest, error) {
	args := c.Called()
	return args.Get(0).(distribution.Manifest), args.Error(1)
}
