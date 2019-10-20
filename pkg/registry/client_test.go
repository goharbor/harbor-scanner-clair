package registry

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func TestClient_parseAuthenticateHeader(t *testing.T) {
	testCases := []struct {
		name                 string
		authenticateHeader   string
		expectedError        error
		expectedTokenRequest tokenRequest
	}{
		{
			name:               "Should parse WWW-Authenticate header",
			authenticateHeader: "Bearer realm=\"https://core.harbor.domain/service/token\",service=\"harbor-registry\",scope=\"repository:scanners/nginx:pull\"",
			expectedTokenRequest: tokenRequest{
				Realm:   parseURL(t, "https://core.harbor.domain/service/token"),
				Service: "harbor-registry",
				Scope:   "repository:scanners/nginx:pull",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := client{}
			tokenRequest, err := c.parseAuthenticateHeader(tc.authenticateHeader)
			assert.Equal(t, tc.expectedError, err)
			assert.Equal(t, tc.expectedTokenRequest, tokenRequest)
		})
	}
}

func parseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsedURL, err := url.Parse(rawURL)
	require.NoError(t, err)
	return parsedURL
}
