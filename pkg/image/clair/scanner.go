package clair

import (
	"crypto/sha256"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/image"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/model/clair"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/oci/auth"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/oci/registry"
	"github.com/docker/distribution/manifest/schema2"
	"log"
	"strings"
)

type imageScanner struct {
	client *Client
}

func NewScanner(clairURL string) (image.Scanner, error) {
	return &imageScanner{
		client: NewClient(clairURL),
	}, nil
}

func (s *imageScanner) Scan(req harbor.ScanRequest) (*harbor.ScanResponse, error) {
	layers, err := s.prepareLayers(req)
	if err != nil {
		return nil, err
	}

	for _, l := range layers {
		log.Printf("Scanning Layer: %s, path: %s", l.Name, l.Path)
		if err := s.client.ScanLayer(l); err != nil {
			log.Printf("Failed to scan layer: %s, error: %v", l.Name, err)
			return nil, err
		}
	}

	layerName := layers[len(layers)-1].Name

	return &harbor.ScanResponse{
		DetailsKey: layerName,
	}, nil
}

func (s *imageScanner) prepareLayers(req harbor.ScanRequest) ([]clair.ClairLayer, error) {
	layers := make([]clair.ClairLayer, 0)

	client, err := registry.NewClient(req.RegistryURL, auth.NewBearerTokenAuthorizer(req.RegistryToken))
	if err != nil {
		return nil, fmt.Errorf("constructing registry client: %v", err)
	}

	manifest, _, err := client.Manifest(req.Repository, req.Digest)
	if err != nil {
		return nil, err
	}

	tokenHeader := map[string]string{"Connection": "close", "Authorization": fmt.Sprintf("Bearer %s", req.RegistryToken)}
	// form the chain by using the digests of all parent layers in the image, such that if another image is built on top of this image the layer name can be re-used.
	shaChain := ""
	for _, d := range manifest.References() {
		if d.MediaType == schema2.MediaTypeImageConfig {
			continue
		}
		shaChain += string(d.Digest) + "-"
		l := clair.ClairLayer{
			Name:    fmt.Sprintf("%x", sha256.Sum256([]byte(shaChain))),
			Headers: tokenHeader,
			Format:  "Docker",
			Path:    s.buildBlobURL(req.RegistryURL, req.Repository, string(d.Digest)),
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

// ParseClairSev parse the severity of clair to Harbor's Severity type if the string is not recognized the value will be set to unknown.
func (s *imageScanner) parseClairSev(clairSev string) harbor.Severity {
	sev := strings.ToLower(clairSev)
	switch sev {
	case clair.SeverityNone:
		return harbor.SevNone
	case clair.SeverityLow:
		return harbor.SevLow
	case clair.SeverityMedium:
		return harbor.SevMedium
	case clair.SeverityHigh, clair.SeverityCritical:
		return harbor.SevHigh
	default:
		return harbor.SevUnknown
	}
}

func (s *imageScanner) GetResult(detailsKey string) (*harbor.ScanResult, error) {
	res, err := s.client.GetResult(detailsKey)
	if err != nil {
		log.Printf("Failed to get result from Clair, error: %v", err)
		return nil, err
	}

	overview, sev := s.toComponentsOverview(res)

	return &harbor.ScanResult{
		Severity:        sev,
		Overview:        overview,
		Vulnerabilities: s.toVulnerabilityItems(res),
	}, nil
}

// TransformVuln is for running scanning job in both job service V1 and V2.
func (s *imageScanner) toComponentsOverview(clairVuln *clair.ClairLayerEnvelope) (*harbor.ComponentsOverview, harbor.Severity) {
	vulnMap := make(map[harbor.Severity]int)
	features := clairVuln.Layer.Features
	totalComponents := len(features)
	var temp harbor.Severity
	for _, f := range features {
		sev := harbor.SevNone
		for _, v := range f.Vulnerabilities {
			temp = s.parseClairSev(v.Severity)
			if temp > sev {
				sev = temp
			}
		}
		vulnMap[sev]++
	}
	overallSev := harbor.SevNone
	compSummary := []*harbor.ComponentsOverviewEntry{}
	for k, v := range vulnMap {
		if k > overallSev {
			overallSev = k
		}
		entry := &harbor.ComponentsOverviewEntry{
			Sev:   int(k),
			Count: v,
		}
		compSummary = append(compSummary, entry)
	}
	return &harbor.ComponentsOverview{
		Total:   totalComponents,
		Summary: compSummary,
	}, overallSev
}

// transformVulnerabilities transforms the returned value of Clair API to a list of VulnerabilityItem
func (s *imageScanner) toVulnerabilityItems(layerWithVuln *clair.ClairLayerEnvelope) []*harbor.VulnerabilityItem {
	res := []*harbor.VulnerabilityItem{}
	l := layerWithVuln.Layer
	if l == nil {
		return res
	}
	features := l.Features
	if features == nil {
		return res
	}
	for _, f := range features {
		vulnerabilities := f.Vulnerabilities
		if vulnerabilities == nil {
			continue
		}
		for _, v := range vulnerabilities {
			vItem := &harbor.VulnerabilityItem{
				ID:          v.Name,
				Pkg:         f.Name,
				Version:     f.Version,
				Severity:    s.parseClairSev(v.Severity),
				Fixed:       v.FixedBy,
				Link:        v.Link,
				Description: v.Description,
			}
			res = append(res, vItem)
		}
	}
	return res
}
