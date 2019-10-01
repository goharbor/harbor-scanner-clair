package registry

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/schema2"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type tokenRequest struct {
	Realm   *url.URL
	Service string
	Scope   string
}

type tokenResponse struct {
	Token     string    `json:"token"`
	ExpiresIn int       `json:"expires_in"`
	IssuedAt  time.Time `json:"issued_at"`
}

type Client struct {
	registryURL   string
	client        *http.Client
	authorization string
}

func NewClient(registryURL string, authorization string) (*Client, error) {
	return &Client{
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

func (c *Client) Manifest(repository, reference string) (distribution.Manifest, string, error) {
	tokenRequest, err := c.getTokenRequest(repository, reference)
	if err != nil {
		return nil, "", err
	}
	log.Debugf("Token request: %v", tokenRequest)
	tokenResponse, err := c.getAccessToken(tokenRequest)

	requestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", c.registryURL, repository, reference)
	log.Debugf("Fetch manifest URL: %s", requestURL)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Add(http.CanonicalHeaderKey("Accept"), schema2.MediaTypeManifest)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokenResponse.Token))

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
	return manifest, tokenResponse.Token, nil
}

func (c *Client) getTokenRequest(repository, reference string) (tokenRequest, error) {
	requestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", c.registryURL, repository, reference)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return tokenRequest{}, err
	}

	req.Header.Add(http.CanonicalHeaderKey("Accept"), schema2.MediaTypeManifest)

	resp, err := c.client.Do(req)
	if err != nil {
		return tokenRequest{}, err
	}
	log.Debugf("Response status: %s", resp.Status)
	log.Debugf("Response headers: %v", resp.Header)

	if resp.StatusCode != http.StatusUnauthorized {
		return tokenRequest{}, fmt.Errorf("expected status %d got %d", http.StatusUnauthorized, resp.StatusCode)
	}
	if resp.Header.Get("Www-Authenticate") == "" {
		return tokenRequest{}, fmt.Errorf("expected Www-Authenticate header")
	}

	return c.parseAuthenticateHeader(resp.Header.Get("Www-Authenticate"))
}

func (c *Client) parseAuthenticateHeader(value string) (tokenRequest, error) {
	log.Debugf("Parsing authenticate header %s", value)
	realmString := strings.TrimSpace(strings.TrimPrefix(value, "Bearer"))

	m := make(map[string]string)
	pairs := strings.Split(realmString, ",")
	for _, pair := range pairs {
		split := strings.Split(strings.TrimSpace(pair), "=")
		m[strings.ToLower(split[0])] = strings.Trim(split[1], "\"")
	}

	realm, err := url.Parse(m["realm"])
	if err != nil {
		return tokenRequest{}, err
	}

	service, ok := m["service"]
	if !ok {
		return tokenRequest{}, fmt.Errorf("expected service not set in %s", value)
	}

	scope, ok := m["scope"]
	if !ok {
		return tokenRequest{}, fmt.Errorf("expected scope not set in %s", value)
	}

	return tokenRequest{
		Realm:   realm,
		Service: service,
		Scope:   scope,
	}, nil
}

func (c *Client) getAccessToken(tokenRequest tokenRequest) (tokenResponse, error) {
	var tokenResponse tokenResponse
	requestURL := tokenRequest.Realm

	params := url.Values{}
	params.Add("service", tokenRequest.Service)
	params.Add("scope", tokenRequest.Scope)
	requestURL.RawQuery = params.Encode()

	req, err := http.NewRequest(http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return tokenResponse, err
	}

	req.Header.Add("Authorization", c.authorization)

	resp, err := c.client.Do(req)
	if err != nil {
		return tokenResponse, err
	}
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	defer resp.Body.Close()
	if err != nil {
		return tokenResponse, err
	}
	return tokenResponse, nil
}
