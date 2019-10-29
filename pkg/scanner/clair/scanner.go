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

type Scanner interface {
	Scan(req harbor.ScanRequest) (harbor.ScanReport, error)
}

type scanner struct {
	registryClientFactory registry.ClientFactory
	clairClient           Client
	transformer           model.Transformer
}

func NewScanner(registryClientFactory registry.ClientFactory, clairClient Client, transformer model.Transformer) Scanner {
	return &scanner{
		registryClientFactory: registryClientFactory,
		clairClient:           clairClient,
		transformer:           transformer,
	}
}

func (s *scanner) Scan(req harbor.ScanRequest) (harbor.ScanReport, error) {
	layers, err := s.prepareLayers(req)
	if err != nil {
		return harbor.ScanReport{}, fmt.Errorf("preparing layers: %v", err)
	}

	for _, l := range layers {
		layerLog := log.WithFields(log.Fields{
			"layer_name": l.Name,
			"layer_path": l.Path,
		})

		layerLog.Debug("Sending layer for scanning")
		if err := s.clairClient.ScanLayer(l); err != nil {
			layerLog.WithError(err).Error("Error while sending layer for scanning")
			return harbor.ScanReport{}, err
		}
	}

	return s.getReport(req.Artifact, layers[len(layers)-1].Name)
}

func (s *scanner) prepareLayers(req harbor.ScanRequest) ([]clair.Layer, error) {
	manifest, err := s.registryClientFactory.Get().GetManifest(req)
	if err != nil {
		return nil, err
	}

	layers := make([]clair.Layer, 0)

	// Form the chain by using the digests of all parent layers in the image, such that if another image is built
	// on top of this image the layer name can be re-used.
	shaChain := ""
	for _, d := range manifest.References() {
		if d.MediaType == schema2.MediaTypeImageConfig {
			continue
		}
		shaChain += string(d.Digest) + "-"
		l := clair.Layer{
			Name: fmt.Sprintf("%x", sha256.Sum256([]byte(shaChain))),
			Headers: map[string]string{
				"Connection":    "close",
				"Authorization": req.Registry.Authorization,
			},
			Format: "Docker",
			Path:   s.buildBlobURL(req.Registry.URL, req.Artifact.Repository, string(d.Digest)),
		}
		if len(layers) > 0 {
			l.ParentName = layers[len(layers)-1].Name
		}
		layers = append(layers, l)
	}
	return layers, nil
}

func (s *scanner) buildBlobURL(endpoint, repository, digest string) string {
	return fmt.Sprintf("%s/v2/%s/blobs/%s", endpoint, repository, digest)
}

func (s *scanner) getReport(artifact harbor.Artifact, layerName string) (harbor.ScanReport, error) {
	res, err := s.clairClient.GetLayer(layerName)
	if err != nil {
		return harbor.ScanReport{}, fmt.Errorf("getting layer %s: %v", layerName, err)
	}
	scanReport := s.transformer.Transform(artifact, *res)
	return scanReport, nil
}
