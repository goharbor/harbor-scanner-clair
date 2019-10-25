package registry

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema2"
	log "github.com/sirupsen/logrus"
)

type ClientFactory interface {
	Get(registryURL, authorization string) (Client, error)
}

type Client interface {
	Manifest(repository, reference string) (distribution.Manifest, string, error)
}

type client struct {
	registryURL   string
	client        *http.Client
	authorization string
}

type clientFactory struct {
}

func (cf *clientFactory) Get(registryURL, authorization string) (Client, error) {
	return &client{
		registryURL: registryURL,
		client: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// FIXME Allow configuring custom or self-signed certs rather than skipping verification.
				InsecureSkipVerify: true,
			},
		}},
		authorization: authorization,
	}, nil
}

func NewClientFactory() ClientFactory {
	return &clientFactory{}
}

func (c *client) Manifest(repository, reference string) (distribution.Manifest, string, error) {
	requestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", c.registryURL, repository, reference)
	log.Debugf("Fetch manifest URL: %s", requestURL)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Add("Accept", schema2.MediaTypeManifest)
	req.Header.Add("Authorization", c.authorization)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	log.Debugf("Response status: %s", resp.Status)
	log.Debugf("Response headers: %v", resp.Header)

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP not ok: %v", resp.Status)
	}

	manifest, _, err := distribution.UnmarshalManifest(schema2.MediaTypeManifest, b)
	if err != nil {
		return nil, "", fmt.Errorf("unmarshaling manifest: %v", err)
	}

	return manifest, strings.TrimPrefix(c.authorization, "Bearer "), nil
}
