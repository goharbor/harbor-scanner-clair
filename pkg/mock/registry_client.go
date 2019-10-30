package mock

import (
	"github.com/docker/distribution"
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
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

func (f *RegistryClientFactory) Get() registry.Client {
	args := f.Called()
	return args.Get(0).(registry.Client)
}

func (c *RegistryClient) GetManifest(req harbor.ScanRequest) (distribution.Manifest, error) {
	args := c.Called(req)
	return args.Get(0).(distribution.Manifest), args.Error(1)
}
