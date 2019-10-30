package scanner

import (
	"crypto/sha256"
	"fmt"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/goharbor/harbor-scanner-clair/pkg/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
	log "github.com/sirupsen/logrus"
	"strings"
	"time"
)

type systemClock struct {
}

func (c *systemClock) Now() time.Time {
	return time.Now()
}

type Transformer interface {
	ToClairLayers(req harbor.ScanRequest, manifest distribution.Manifest) []clair.Layer
	Transform(artifact harbor.Artifact, source clair.LayerEnvelope) harbor.ScanReport
}

type transformer struct {
	clock interface {
		Now() time.Time
	}
}

func NewTransformer() *transformer {
	return &transformer{
		clock: &systemClock{},
	}
}

func (t *transformer) ToClairLayers(req harbor.ScanRequest, manifest distribution.Manifest) []clair.Layer {
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
			Path:   t.buildBlobURL(req.Registry.URL, req.Artifact.Repository, string(d.Digest)),
		}
		if len(layers) > 0 {
			l.ParentName = layers[len(layers)-1].Name
		}
		layers = append(layers, l)
	}
	return layers
}

func (t *transformer) buildBlobURL(endpoint, repository, digest string) string {
	return fmt.Sprintf("%s/v2/%s/blobs/%s", endpoint, repository, digest)
}

func (t *transformer) Transform(artifact harbor.Artifact, source clair.LayerEnvelope) harbor.ScanReport {
	return harbor.ScanReport{
		GeneratedAt:     t.clock.Now(),
		Scanner:         etc.GetScannerMetadata(),
		Artifact:        artifact,
		Severity:        t.toComponentsOverview(source),
		Vulnerabilities: t.toVulnerabilityItems(source),
	}
}

// TransformVuln is for running scanning job in both job service V1 and V2.
func (t *transformer) toComponentsOverview(envelope clair.LayerEnvelope) harbor.Severity {
	vulnMap := make(map[harbor.Severity]int)
	features := envelope.Layer.Features
	var temp harbor.Severity
	for _, f := range features {
		sev := harbor.SevNone
		for _, v := range f.Vulnerabilities {
			temp = t.toHarborSeverity(v.Severity)
			if temp > sev {
				sev = temp
			}
		}
		vulnMap[sev]++
	}
	overallSev := harbor.SevNone
	for k := range vulnMap {
		if k > overallSev {
			overallSev = k
		}

	}
	return overallSev
}

// transformVulnerabilities transforms the returned value of Clair API to a list of VulnerabilityItem
func (t *transformer) toVulnerabilityItems(envelope clair.LayerEnvelope) []harbor.VulnerabilityItem {
	var res []harbor.VulnerabilityItem
	l := envelope.Layer
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
			vItem := harbor.VulnerabilityItem{
				ID:          v.Name,
				Pkg:         f.Name,
				Version:     f.Version,
				Severity:    t.toHarborSeverity(v.Severity),
				FixVersion:  v.FixedBy,
				Links:       t.toLinks(v.Link),
				Description: v.Description,
			}
			res = append(res, vItem)
		}
	}
	return res
}

func (t *transformer) toLinks(link string) []string {
	if link == "" {
		return []string{}
	}
	return []string{link}
}

// toHarborSeverity parses the severity of clair to Harbor's Severity type.
// If the string is not recognized the value will be set to unknown.
func (t *transformer) toHarborSeverity(clairSev string) harbor.Severity {
	switch sev := strings.ToLower(clairSev); sev {
	case clair.SeverityNegligible:
		return harbor.SevNegligible
	case clair.SeverityLow:
		return harbor.SevLow
	case clair.SeverityMedium:
		return harbor.SevMedium
	case clair.SeverityHigh:
		return harbor.SevHigh
	case clair.SeverityCritical:
		return harbor.SevCritical
	case clair.SeverityUnknown:
		return harbor.SevUnknown
	default:
		log.WithField("severity", sev).Warn("Unknown Clair severity")
		return harbor.SevUnknown
	}
}
