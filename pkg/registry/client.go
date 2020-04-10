package registry

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/docker/distribution"
	// docker schema1 manifest
	_ "github.com/docker/distribution/manifest/schema1"
	// docker schema2 manifest
	_ "github.com/docker/distribution/manifest/schema2"
	// oci schema
	_ "github.com/docker/distribution/manifest/ocischema"
	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
)

var (
	once      sync.Once
	singleton *client
)

type ClientFactory interface {
	Get() Client
}

type Client interface {
	GetManifest(req harbor.ScanRequest) (distribution.Manifest, error)
}

type client struct {
	client *http.Client
}

type clientFactory struct {
	tlsConfig etc.TLSConfig
}

func NewClientFactory(TLSConfig etc.TLSConfig) ClientFactory {
	return &clientFactory{
		tlsConfig: TLSConfig,
	}
}

func (cf *clientFactory) Get() Client {
	once.Do(func() {
		singleton = &client{
			client: &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:            cf.tlsConfig.RootCAs,
					InsecureSkipVerify: cf.tlsConfig.InsecureSkipVerify,
				},
			}},
		}
	})

	return singleton
}

func (c *client) GetManifest(sr harbor.ScanRequest) (distribution.Manifest, error) {
	req, err := http.NewRequest(http.MethodGet, c.manifestURL(sr), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", sr.Artifact.MimeType)
	req.Header.Add("Authorization", sr.Registry.Authorization)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching manifest with status %q: %s", resp.Status, string(b))
	}

	manifest, _, err := distribution.UnmarshalManifest(sr.Artifact.MimeType, b)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling manifest: %v", err)
	}
	return manifest, nil
}

func (c *client) manifestURL(sr harbor.ScanRequest) string {
	return fmt.Sprintf("%s/v2/%s/manifests/%s", sr.Registry.URL,
		sr.Artifact.Repository,
		sr.Artifact.Digest)
}
