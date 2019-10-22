package registry

import (
	"crypto/tls"
	"fmt"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"io/ioutil"
	"net/http"
)

type ClientFactory interface {
	Get(req harbor.ScanRequest) (Client, error)
}

type Client interface {
	GetManifest() (distribution.Manifest, error)
}

type client struct {
	scanRequest harbor.ScanRequest
	client      *http.Client
}

type clientFactory struct {
	tlsConfig etc.TLSConfig
}

func NewClientFactory(TLSConfig etc.TLSConfig) ClientFactory {
	return &clientFactory{
		tlsConfig: TLSConfig,
	}
}

func (cf *clientFactory) Get(scanRequest harbor.ScanRequest) (Client, error) {
	return &client{
		scanRequest: scanRequest,
		client: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            cf.tlsConfig.RootCAs,
				InsecureSkipVerify: cf.tlsConfig.InsecureSkipVerify,
			},
		}},
	}, nil
}

func (c *client) GetManifest() (distribution.Manifest, error) {
	req, err := http.NewRequest(http.MethodGet, c.manifestURL(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", schema2.MediaTypeManifest)
	req.Header.Add("Authorization", c.scanRequest.Registry.Authorization)

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

	manifest, _, err := distribution.UnmarshalManifest(schema2.MediaTypeManifest, b)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling manifest: %v", err)
	}
	return manifest, nil
}

func (c *client) manifestURL() string {
	return fmt.Sprintf("%s/v2/%s/manifests/%s", c.scanRequest.Registry.URL,
		c.scanRequest.Artifact.Repository,
		c.scanRequest.Artifact.Digest)
}
