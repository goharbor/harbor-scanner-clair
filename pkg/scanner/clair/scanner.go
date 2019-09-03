package clair

import (
	"crypto/sha256"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/model/clair"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/oci/auth"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/oci/registry"
	"github.com/aquasecurity/harbor-scanner-clair/pkg/store"
	"github.com/docker/distribution/manifest/schema2"
	log "github.com/sirupsen/logrus"
	"strings"
)

// Scanner defines methods for scanning container images.
type Scanner interface {
	Scan(req harbor.ScanRequest) error
	GetReport(scanRequestID string) (*harbor.VulnerabilityReport, error)
}

type imageScanner struct {
	client    *Client
	dataStore store.DataStore
}

func NewScanner(clairURL string, dataStore store.DataStore) (Scanner, error) {
	return &imageScanner{
		client:    NewClient(clairURL),
		dataStore: dataStore,
	}, nil
}

func (s *imageScanner) Scan(req harbor.ScanRequest) error {
	layers, err := s.prepareLayers(req)
	if err != nil {
		return fmt.Errorf("preparing layers: %v", err)
	}

	for _, l := range layers {
		log.Debugf("Scanning Layer: %s, path: %s", l.Name, l.Path)
		if err := s.client.ScanLayer(l); err != nil {
			log.Debugf("Failed to scan layer: %s, error: %v", l.Name, err)
			return err
		}
	}

	layerName := layers[len(layers)-1].Name

	return s.dataStore.Set(req.ID, layerName)
}

func (s *imageScanner) prepareLayers(req harbor.ScanRequest) ([]clair.ClairLayer, error) {
	layers := make([]clair.ClairLayer, 0)

	client, err := registry.NewClient(req.RegistryURL, auth.NewBearerTokenAuthorizer(req.RegistryAuthorization))
	if err != nil {
		return nil, fmt.Errorf("constructing registry client: %v", err)
	}

	manifest, _, err := client.Manifest(req.ArtifactRepository, req.ArtifactDigest)
	if err != nil {
		return nil, err
	}

	tokenHeader := map[string]string{"Connection": "close", "Authorization": fmt.Sprintf("Bearer %s", req.RegistryAuthorization)}
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
			Path:    s.buildBlobURL(req.RegistryURL, req.ArtifactRepository, string(d.Digest)),
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

func (s *imageScanner) GetReport(scanRequestID string) (*harbor.VulnerabilityReport, error) {
	layerName, err := s.dataStore.Get(scanRequestID)
	if err != nil {
		return nil, err
	}

	res, err := s.client.GetResult(layerName)
	if err != nil {
		log.Printf("Failed to get result from Clair, error: %v", err)
		return nil, err
	}

	sev := s.toComponentsOverview(res)

	return &harbor.VulnerabilityReport{
		Severity:        sev,
		Vulnerabilities: s.toVulnerabilityItems(res),
	}, nil
}

// TransformVuln is for running scanning job in both job service V1 and V2.
func (s *imageScanner) toComponentsOverview(clairVuln *clair.ClairLayerEnvelope) harbor.Severity {
	vulnMap := make(map[harbor.Severity]int)
	features := clairVuln.Layer.Features
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
	for k, _ := range vulnMap {
		if k > overallSev {
			overallSev = k
		}

	}
	return overallSev
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
