package clair

import (
	"crypto/sha256"
	"fmt"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/goharbor/harbor-scanner-clair/pkg/model"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/goharbor/harbor-scanner-clair/pkg/registry"
	log "github.com/sirupsen/logrus"
)

// Scanner defines methods for scanning container images.
type Scanner interface {
	Scan(req harbor.ScanRequest) (harbor.ScanResponse, error)
	GetReport(scanRequestID string) (harbor.ScanReport, error)
}

type imageScanner struct {
	registryClientFactory registry.ClientFactory
	clairClient           Client
	transformer           model.Transformer
}

func NewScanner(registryClientFactory registry.ClientFactory, clairClient Client, transformer model.Transformer) Scanner {
	return &imageScanner{
		registryClientFactory: registryClientFactory,
		clairClient:           clairClient,
		transformer:           transformer,
	}
}

func (s *imageScanner) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	layers, err := s.prepareLayers(req)
	if err != nil {
		return harbor.ScanResponse{}, fmt.Errorf("preparing layers: %v", err)
	}

	for _, l := range layers {
		layerLog := log.WithFields(log.Fields{
			"layer_name": l.Name,
			"layer_path": l.Path,
		})

		layerLog.Debug("Sending layer for scanning")
		if err := s.clairClient.ScanLayer(l); err != nil {
			layerLog.WithError(err).Error("Error while sending layer for scanning")
			return harbor.ScanResponse{}, err
		}
	}

	layerName := layers[len(layers)-1].Name

	return harbor.ScanResponse{ID: layerName}, nil
}

func (s *imageScanner) prepareLayers(req harbor.ScanRequest) ([]clair.Layer, error) {
	layers := make([]clair.Layer, 0)

	registryClient, err := s.registryClientFactory.Get(req.Registry.URL, req.Registry.Authorization)
	if err != nil {
		return nil, fmt.Errorf("constructing registry client: %v", err)
	}

	manifest, bearerToken, err := registryClient.Manifest(req.Artifact.Repository, req.Artifact.Digest)
	if err != nil {
		return nil, err
	}

	tokenHeader := map[string]string{
		"Connection":    "close",
		"Authorization": fmt.Sprintf("Bearer %s", bearerToken),
	}
	// form the chain by using the digests of all parent layers in the image, such that if another image is built on top of this image the layer name can be re-used.
	shaChain := ""
	for _, d := range manifest.References() {
		if d.MediaType == schema2.MediaTypeImageConfig {
			continue
		}
		shaChain += string(d.Digest) + "-"
		l := clair.Layer{
			Name:    fmt.Sprintf("%x", sha256.Sum256([]byte(shaChain))),
			Headers: tokenHeader,
			Format:  "Docker",
			Path:    s.buildBlobURL(req.Registry.URL, req.Artifact.Repository, string(d.Digest)),
		}
		if len(layers) > 0 {
			l.ParentName = layers[len(layers)-1].Name
		}
		layers = append(layers, l)
	}
	return layers, nil
}

func (s *imageScanner) buildBlobURL(endpoint, repository, digest string) string {
	return fmt.Sprintf("%s/v2/%s/blobs/%s", endpoint, repository, digest)
}

func (s *imageScanner) GetReport(layerName string) (harbor.ScanReport, error) {
	res, err := s.clairClient.GetLayer(layerName)
	if err != nil {
		return harbor.ScanReport{}, fmt.Errorf("getting layer %s: %v", layerName, err)
	}
	scanReport := s.transformer.Transform(harbor.Artifact{}, *res)
	return scanReport, nil
}
