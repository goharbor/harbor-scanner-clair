package clair

import (
	"crypto/sha256"
	"fmt"
	"github.com/aquasecurity/harbor-clair-adapter/pkg/image"
	"github.com/aquasecurity/harbor-clair-adapter/pkg/model/clair"
	"github.com/aquasecurity/harbor-clair-adapter/pkg/model/harbor"
	"github.com/danielpacak/docker-registry-client/pkg/auth"
	"github.com/danielpacak/docker-registry-client/pkg/registry"
	"github.com/docker/distribution/manifest/schema2"
	"log"
	"strings"
)

type clairScanner struct {
	detailKeys map[string]string
	client     *Client
}

func NewScanner(clairURL string) (image.Scanner, error) {
	return &clairScanner{
		detailKeys: make(map[string]string),
		client:     NewClient(clairURL),
	}, nil
}

// return detailKey
func (s *clairScanner) Scan(req harbor.ScanRequest) error {

	layers, err := s.prepareLayers(req)
	if err != nil {
		return err
	}

	for _, l := range layers {
		log.Printf("Scanning Layer: %s, path: %s", l.Name, l.Path)
		if err := s.client.ScanLayer(l); err != nil {
			log.Printf("Failed to scan layer: %s, error: %v", l.Name, err)
			return err
		}
	}

	layerName := layers[len(layers)-1].Name

	s.detailKeys[req.Digest] = layerName

	return nil
}

func (s *clairScanner) prepareLayers(req harbor.ScanRequest) ([]clair.ClairLayer, error) {
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
			Path:    BuildBlobURL(req.RegistryURL, req.Repository, string(d.Digest)),
		}
		if len(layers) > 0 {
			l.ParentName = layers[len(layers)-1].Name
		}
		layers = append(layers, l)
	}
	return layers, nil
}

// BuildBlobURL ...
func BuildBlobURL(endpoint, repository, digest string) string {
	return fmt.Sprintf("%s/v2/%s/blobs/%s", endpoint, repository, digest)
}

// TransformVuln is for running scanning job in both job service V1 and V2.
func TransformVuln(clairVuln *clair.ClairLayerEnvelope) (*harbor.ComponentsOverview, harbor.Severity) {
	return transformVuln(clairVuln)
}

func transformVuln(clairVuln *clair.ClairLayerEnvelope) (*harbor.ComponentsOverview, harbor.Severity) {
	vulnMap := make(map[harbor.Severity]int)
	features := clairVuln.Layer.Features
	totalComponents := len(features)
	var temp harbor.Severity
	for _, f := range features {
		sev := harbor.SevNone
		for _, v := range f.Vulnerabilities {
			temp = ParseClairSev(v.Severity)
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

// ParseClairSev parse the severity of clair to Harbor's Severity type if the string is not recognized the value will be set to unknown.
func ParseClairSev(clairSev string) harbor.Severity {
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

func (s *clairScanner) GetResult(digest string) (*harbor.ScanResult, error) {
	layerName := s.detailKeys[digest]
	res, err := s.client.GetResult(layerName)
	if err != nil {
		log.Printf("Failed to get result from Clair, error: %v", err)
		return nil, err
	}

	overview, sev := TransformVuln(res)

	return &harbor.ScanResult{
		Digest:          digest,
		Severity:        sev,
		Overview:        overview,
		Vulnerabilities: transformVulnerabilities(res),
	}, nil
}

// transformVulnerabilities transforms the returned value of Clair API to a list of VulnerabilityItem
func transformVulnerabilities(layerWithVuln *clair.ClairLayerEnvelope) []*harbor.VulnerabilityItem {
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
				Severity:    ParseClairSev(v.Severity),
				Fixed:       v.FixedBy,
				Link:        v.Link,
				Description: v.Description,
			}
			res = append(res, vItem)
		}
	}
	return res
}
