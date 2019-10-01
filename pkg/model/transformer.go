package model

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/model/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"strings"
	"time"
)

type systemClock struct {
}

func (c *systemClock) Now() time.Time {
	return time.Now()
}

type Transformer interface {
	Transform(req harbor.ScanRequest, source clair.LayerEnvelope) harbor.VulnerabilityReport
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

func (t *transformer) Transform(req harbor.ScanRequest, source clair.LayerEnvelope) harbor.VulnerabilityReport {
	return harbor.VulnerabilityReport{
		GeneratedAt: t.clock.Now(),
		Scanner: harbor.Scanner{
			Name:   "Clair",
			Vendor: "CoreOS",
			// TODO Get version from Clair API or env if the API does not provide it.
			Version: "2.0.8",
		},
		Artifact:        req.Artifact,
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
	for k, _ := range vulnMap {
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
				Links:       []string{v.Link},
				Description: v.Description,
			}
			res = append(res, vItem)
		}
	}
	return res
}

// toHarborSeverity parses the severity of clair to Harbor's Severity type.
// If the string is not recognized the value will be set to unknown.
func (t *transformer) toHarborSeverity(clairSev string) harbor.Severity {
	switch sev := strings.ToLower(clairSev); sev {
	case clair.SeverityNone:
		return harbor.SevNone
	case clair.SeverityLow:
		return harbor.SevLow
	case clair.SeverityMedium:
		return harbor.SevMedium
	case clair.SeverityHigh:
		return harbor.SevHigh
	case clair.SeverityCritical:
		return harbor.SevCritical
	default:
		return harbor.SevUnknown
	}
}
