package clair

import (
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/goharbor/harbor-scanner-clair/pkg/mock"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestImageScanner_Scan(t *testing.T) {
	// FIXME Fix this unit test
	t.Skip("Fix me")
	req := harbor.ScanRequest{
		Registry: harbor.Registry{
			URL:           "https://core.harbor.domain",
			Authorization: "Bearer <JWT TOKEN>",
		},
		Artifact: harbor.Artifact{
			Repository: "library/erlang",
			Digest:     "sha256:d66da0a3b3b856a737168f28549be04512d9c9af2ff5120686d75d3a55e4af57",
		},
	}

	registryClientFactory := mock.NewRegistryClientFactory()
	registryClient := mock.NewRegistryClient()
	clairClient := mock.NewClairClient()
	transformer := mock.NewTransformer()

	registryClientFactory.On("Get").Return(registryClient)
	registryClient.On("GetManifest", req).Return(schema2.DeserializedManifest{
		Manifest: schema2.Manifest{
			Versioned: manifest.Versioned{
				SchemaVersion: 2,
				MediaType:     schema2.MediaTypeManifest,
			},
			Config: distribution.Descriptor{
				MediaType: schema2.MediaTypeImageConfig,
				Digest:    "sha256:e82e9f112bf7d37e4dd037a2707030ba647af94329036f6da101d36c53c974cf",
			},
			Layers: []distribution.Descriptor{
				{
					MediaType: schema2.MediaTypeLayer,
					Digest:    "sha256:9a0b0ce99936ce4861d44ce1f193e881e5b40b5bf1847627061205b092fa7f1d",
				},
				{
					MediaType: schema2.MediaTypeLayer,
					Digest:    "sha256:db3b6004c61a0e86fbf910b9b4a6611ae79e238a336011a1b5f9b177d85cbf9d",
				},
			},
		},
	}, nil)
	clairClient.On("ScanLayer", clair.Layer{
		Name: "31d8546ce949163443fad8147ad5831fc5ecc6efc889a06d2a3b93af56dd4bcd",
		Path: "https://core.harbor.domain/v2/library/erlang/blobs/sha256:9a0b0ce99936ce4861d44ce1f193e881e5b40b5bf1847627061205b092fa7f1d",
		Headers: map[string]string{
			"Authorization": "Bearer <JWT TOKEN>",
			"Connection":    "close",
		},
		Format: "Docker",
	}).Return(nil)
	clairClient.On("ScanLayer", clair.Layer{
		Name:       "d10095311d9a7dde7d350fdab383ef1e525ec793c33ca941ac593675762bc5d8",
		ParentName: "31d8546ce949163443fad8147ad5831fc5ecc6efc889a06d2a3b93af56dd4bcd",
		Path:       "https://core.harbor.domain/v2/library/erlang/blobs/sha256:db3b6004c61a0e86fbf910b9b4a6611ae79e238a336011a1b5f9b177d85cbf9d",
		Headers: map[string]string{
			"Authorization": "Bearer <JWT TOKEN>",
			"Connection":    "close",
		},
		Format: "Docker",
	}).Return(nil)

	clairClient.On("GetLayer", "d10095311d9a7dde7d350fdab383ef1e525ec793c33ca941ac593675762bc5d8").
		Return(&clair.LayerEnvelope{
			Layer: &clair.Layer{},
		}, nil)
	transformer.On("Transform", harbor.Artifact{}, &clair.LayerEnvelope{Layer: &clair.Layer{}}).
		Return(harbor.ScanReport{}, nil)

	scanner := NewScanner(registryClientFactory, clairClient, transformer)

	resp, err := scanner.Scan(req)
	require.NoError(t, err)
	assert.Equal(t, harbor.ScanResponse{
		ID: "d10095311d9a7dde7d350fdab383ef1e525ec793c33ca941ac593675762bc5d8",
	}, resp)

	registryClientFactory.AssertExpectations(t)
	registryClient.AssertExpectations(t)
	clairClient.AssertExpectations(t)
	transformer.AssertExpectations(t)
}
