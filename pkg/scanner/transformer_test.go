package scanner

import (
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/goharbor/harbor-scanner-clair/pkg/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
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

func TestTransformer_ToClairLayers(t *testing.T) {
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
	mf := schema2.DeserializedManifest{
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
	}

	layers := NewTransformer().ToClairLayers(req, mf)
	assert.Equal(t, []clair.Layer{
		{
			Name: "31d8546ce949163443fad8147ad5831fc5ecc6efc889a06d2a3b93af56dd4bcd",
			Path: "https://core.harbor.domain/v2/library/erlang/blobs/sha256:9a0b0ce99936ce4861d44ce1f193e881e5b40b5bf1847627061205b092fa7f1d",
			Headers: map[string]string{
				"Authorization": "Bearer <JWT TOKEN>",
				"Connection":    "close",
			},
			Format: "Docker",
		},
		{
			Name:       "d10095311d9a7dde7d350fdab383ef1e525ec793c33ca941ac593675762bc5d8",
			ParentName: "31d8546ce949163443fad8147ad5831fc5ecc6efc889a06d2a3b93af56dd4bcd",
			Path:       "https://core.harbor.domain/v2/library/erlang/blobs/sha256:db3b6004c61a0e86fbf910b9b4a6611ae79e238a336011a1b5f9b177d85cbf9d",
			Headers: map[string]string{
				"Authorization": "Bearer <JWT TOKEN>",
				"Connection":    "close",
			},
			Format: "Docker",
		},
	}, layers)
}

func TestTransformer_ToHarborScanReport(t *testing.T) {
	transformer := NewTransformer()
	fixedTime := time.Now()
	transformer.clock = &fixedClock{fixedTime: fixedTime}

	artifact := harbor.Artifact{
		Repository: "library/cassandra",
		Digest:     "sha256:70acd789bbbe58a2bbad70880e0ee1dc131846bd2f6c5f5ba459bad8a5b94815",
		MimeType:   "application/vnd.docker.distribution.manifest.v2+json",
	}
	source := &clair.Layer{
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
			{
				Name:            "package1",
				Version:         "package1.version",
				Vulnerabilities: nil,
			},
			{
				Name:    "package2",
				Version: "package2.version",
				Vulnerabilities: []clair.Vulnerability{
					{
						Name:        "CVE-2019-0005",
						Description: "CVE-2019-0005.desc",
						Severity:    "Low",
					},
					{
						Name:        "CVE-2019-0030",
						Description: "CVE-2019-0030.desc",
						Severity:    "Unknown",
					},
					{
						Name:        "CVE-2019-8877",
						Description: "CVE-2019-8877.desc",
						Severity:    "Critical",
					},
					{
						Name:        "CVE-2019-6666",
						Description: "CVE-2019-6666.desc",
						Severity:    "~~UNRECOGNIZED~~",
					},
				},
			},
		},
	}
	scanReport := transformer.ToHarborScanReport(artifact, source)
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
		Severity: harbor.SevCritical,
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
				Severity:    harbor.SevNegligible,
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
			{
				ID:          "CVE-2019-0005",
				Pkg:         "package2",
				Version:     "package2.version",
				Severity:    harbor.SevLow,
				Description: "CVE-2019-0005.desc",
				Links:       []string{},
			},
			{
				ID:          "CVE-2019-0030",
				Pkg:         "package2",
				Version:     "package2.version",
				Severity:    harbor.SevUnknown,
				Description: "CVE-2019-0030.desc",
				Links:       []string{},
			},
			{
				ID:          "CVE-2019-8877",
				Pkg:         "package2",
				Version:     "package2.version",
				Severity:    harbor.SevCritical,
				Description: "CVE-2019-8877.desc",
				Links:       []string{},
			},
			{
				ID:          "CVE-2019-6666",
				Pkg:         "package2",
				Version:     "package2.version",
				Severity:    harbor.SevUnknown,
				Description: "CVE-2019-6666.desc",
				Links:       []string{},
			},
		},
	}, scanReport)
}
