package component

import (
	"fmt"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestComponent(t *testing.T) {
	if testing.Short() {
		t.Skip("A component test")
	}

	config, err := GetConfig()
	require.NoError(t, err)

	imageRef := fmt.Sprintf("%s:%s", config.ArtifactRepository, config.ArtifactTag)

	// 1. Download a test image from DockerHub, retag it and push to the test registry.
	artifactDigest, err := tagAndPush(config.Registry, imageRef)
	require.NoError(t, err)

	req := harbor.ScanRequest{
		Registry: harbor.Registry{
			URL:           config.Registry.URL,
			Authorization: config.Registry.GetBasicAuthorization(),
		},
		Artifact: harbor.Artifact{
			Repository: config.ArtifactRepository,
			Digest:     artifactDigest.String(),
		},
	}

	c := NewClient(config.ScannerURL)
	// 2. Send ScanRequest to Scanner Adapter.
	resp, err := c.RequestScan(req)
	require.NoError(t, err)

	// 3. Poll Scanner Adapter for ScanReport.
	report, err := c.GetScanReport(resp.ID)
	require.NoError(t, err)

	assert.Equal(t, req.Artifact, report.Artifact)
	// TODO Adding asserts on CVEs is tricky as we do not have any control over upstream vulnerabilities database used by Trivy.
	for _, v := range report.Vulnerabilities {
		t.Logf("ID %s, Package: %s, Version: %s, Severity: %s", v.ID, v.Pkg, v.Version, v.Severity)
	}
}

// tagAndPush tags the given imageRef and pushes it to the given test registry.
func tagAndPush(config RegistryConfig, imageRef string) (d digest.Digest, err error) {
	// TODO Implement me
	return digest.FromString("sha256:ABC"), nil
}
