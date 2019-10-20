package mock

import (
	"github.com/docker/distribution"
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

func (f *RegistryClientFactory) Get(registryURL, authorization string) (registry.Client, error) {
	args := f.Called(registryURL, authorization)
	return args.Get(0).(registry.Client), args.Error(1)
}

func (c *RegistryClient) Manifest(repository, reference string) (distribution.Manifest, string, error) {
	args := c.Called(repository, reference)
	return args.Get(0).(distribution.Manifest), args.String(1), args.Error(2)
}
