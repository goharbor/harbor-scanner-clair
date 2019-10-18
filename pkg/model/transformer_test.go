package model

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/model/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

type fixedClock struct {
	fixedTime time.Time
}

func (c *fixedClock) Now() time.Time {
	return c.fixedTime
}

func TestTransformer_Transform(t *testing.T) {
	transformer := NewTransformer()
	fixedTime := time.Now()
	transformer.clock = &fixedClock{fixedTime: fixedTime}

	scanRequest := harbor.ScanRequest{
		Artifact: harbor.Artifact{
			Repository: "library/cassandra",
			Digest:     "sha256:70acd789bbbe58a2bbad70880e0ee1dc131846bd2f6c5f5ba459bad8a5b94815",
			MimeType:   "application/vnd.docker.distribution.manifest.v2+json",
		},
	}
	source := clair.LayerEnvelope{
		Layer: &clair.Layer{
			Features: []clair.Feature{
				{
					Name:    "e2fsprogs",
					Version: "1.43.4-2",
					Vulnerabilities: []clair.Vulnerability{
						{
							Name:        "CVE-2019-5094",
							Description: "CVE-2019-5094 desc",
							Link:        "https://security-tracker.debian.org/tracker/CVE-2019-5094",
							Severity:    "Medium",
							FixedBy:     "1.43.4-2+deb9u1",
						}},
				},
				{
					Name:    "glibc",
					Version: "2.24-11+deb9u4",
					Vulnerabilities: []clair.Vulnerability{
						{
							Name:        "CVE-2019-1010023",
							Description: "CVE-2019-1010023 desc",
							Link:        "https://security-tracker.debian.org/tracker/CVE-2019-1010023",
							Severity:    "Negligible",
						},
						{
							Name:        "CVE-2018-6485",
							Description: "CVE-2018-6485 desc",
							Link:        "https://security-tracker.debian.org/tracker/CVE-2018-6485",
							Severity:    "High",
						},
					},
				},
			},
		},
	}
	scanReport := transformer.Transform(scanRequest, source)
	assert.Equal(t, harbor.ScanReport{
		GeneratedAt: fixedTime,
		Artifact: harbor.Artifact{
			Repository: "library/cassandra",
			Digest:     "sha256:70acd789bbbe58a2bbad70880e0ee1dc131846bd2f6c5f5ba459bad8a5b94815",
			MimeType:   "application/vnd.docker.distribution.manifest.v2+json",
		},
		Scanner: harbor.Scanner{
			Name:    "Clair",
			Vendor:  "CoreOS",
			Version: "2.x",
		},
		Severity: harbor.SevHigh,
		Vulnerabilities: []harbor.VulnerabilityItem{
			{
				ID:          "CVE-2019-5094",
				Pkg:         "e2fsprogs",
				Version:     "1.43.4-2",
				FixVersion:  "1.43.4-2+deb9u1",
				Severity:    harbor.SevMedium,
				Description: "CVE-2019-5094 desc",
				Links:       []string{"https://security-tracker.debian.org/tracker/CVE-2019-5094"},
			},
			{
				ID:          "CVE-2019-1010023",
				Pkg:         "glibc",
				Version:     "2.24-11+deb9u4",
				Severity:    harbor.SevNone,
				Description: "CVE-2019-1010023 desc",
				Links:       []string{"https://security-tracker.debian.org/tracker/CVE-2019-1010023"},
			},
			{
				ID:          "CVE-2018-6485",
				Pkg:         "glibc",
				Version:     "2.24-11+deb9u4",
				Severity:    harbor.SevHigh,
				Description: "CVE-2018-6485 desc",
				Links:       []string{"https://security-tracker.debian.org/tracker/CVE-2018-6485"},
			},
		},
	}, scanReport)
}
