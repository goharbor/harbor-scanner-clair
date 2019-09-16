package registry

import (
	"crypto/tls"
	"fmt"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/goharbor/harbor-scanner-clair/pkg/docker/auth"
	"github.com/opencontainers/go-digest"
	"io"
	"io/ioutil"
	"net/http"
)

type Client struct {
	registryURL string
	client      *http.Client
	authorizer  auth.Authorizer
}

func NewClient(registryURL string, authorizer auth.Authorizer) (*Client, error) {
	return &Client{
		registryURL: registryURL,
		client: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// FIXME Allow configuring custom or self-signed certs rather that skipping verification.
				InsecureSkipVerify: true,
			},
		}},
		authorizer: authorizer,
	}, nil
}

func (c *Client) Manifest(repository, reference string) (distribution.Manifest, digest.Digest, error) {
	requestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", c.registryURL, repository, reference)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Add(http.CanonicalHeaderKey("Accept"), schema2.MediaTypeManifest)

	err = c.authorize(req)

	if err != nil {
		return nil, "", err
	}

	resp, err := c.client.Do(req)
	if err != nil {

		return nil, "", err
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP not ok: %v", resp.Status)
	}

	digestHeader := resp.Header.Get(http.CanonicalHeaderKey("Docker-Content-Digest"))

	manifest, _, err := distribution.UnmarshalManifest(schema2.MediaTypeManifest, b)
	if err != nil {
		return nil, "", fmt.Errorf("unmarshaling manifest: %v", err)
	}
	return manifest, digest.FromString(digestHeader), nil
}

func (c *Client) ReadBlob(repository string, d digest.Digest) (io.Reader, error) {
	requestURL := fmt.Sprintf("%s/v2/%s/blobs/%s", c.registryURL, repository, d)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add(http.CanonicalHeaderKey("Accept"), schema2.MediaTypeManifest)
	err = c.authorize(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP not ok: %v", resp.Status)
	}

	return resp.Body, err
}

func (c *Client) authorize(req *http.Request) error {
	if c.authorizer != nil {
		err := c.authorizer.Authorize(req)
		if err != nil {
			return err
		}
	}
	return nil
}
