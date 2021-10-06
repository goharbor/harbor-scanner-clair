package scanner

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/goharbor/harbor-scanner-clair/pkg/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
	"github.com/goharbor/harbor-scanner-clair/pkg/registry"
)

// Adapter wraps the Scan method.
type Adapter interface {
	// Scan adapts a Harbor ScanRequest to Clair API calls and then maps the response Clair layer to Harbor ScanReport.
	// Returns error in case of failures.
	Scan(req harbor.ScanRequest) (harbor.ScanReport, error)
}

type adapter struct {
	registryClientFactory registry.ClientFactory
	clairClient           clair.Client
	transformer           Transformer
}

func NewAdapter(registryClientFactory registry.ClientFactory, clairClient clair.Client, transformer Transformer) Adapter {
	return &adapter{
		registryClientFactory: registryClientFactory,
		clairClient:           clairClient,
		transformer:           transformer,
	}
}

func (s *adapter) Scan(req harbor.ScanRequest) (harbor.ScanReport, error) {
	layers, err := s.prepareLayers(req)
	if err != nil {
		return harbor.ScanReport{}, fmt.Errorf("preparing layers: %v", err)
	}

	if len(layers) == 0 {
		return harbor.ScanReport{
			GeneratedAt:     time.Now(),
			Scanner:         etc.GetScannerMetadata(),
			Artifact:        req.Artifact,
			Severity:        harbor.SevUnknown,
			Vulnerabilities: []harbor.VulnerabilityItem{},
		}, nil
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

func (s *adapter) prepareLayers(req harbor.ScanRequest) ([]clair.Layer, error) {
	manifest, err := s.registryClientFactory.Get().GetManifest(req)
	if err != nil {
		return nil, err
	}
	return s.transformer.ToClairLayers(req, manifest), nil
}

func (s *adapter) getReport(artifact harbor.Artifact, layerName string) (harbor.ScanReport, error) {
	envelope, err := s.clairClient.GetLayer(layerName)
	if err != nil {
		return harbor.ScanReport{}, fmt.Errorf("getting layer %s: %v", layerName, err)
	}
	scanReport := s.transformer.ToHarborScanReport(artifact, envelope.Layer)
	return scanReport, nil
}
